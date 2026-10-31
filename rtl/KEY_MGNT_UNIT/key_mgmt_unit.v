`timescale 1ns/1ps
// ---------------------------------------------------------------------------
// Key store: 8 x 256-bit slots.
//   attr[0] = lock   (slot cannot be rewritten until reset)
//   attr[1] = secret (slot cannot be read back over the secure bus; only the
//                     direct key port to the accelerators can use it)
// NOTE: behavioral flops. Real silicon would use NVM/OTP + tamper protection.
// ---------------------------------------------------------------------------
module key_store (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         we,
    input  wire [2:0]   wslot,
    input  wire [255:0] wdata,
    input  wire [1:0]   wattr,
    input  wire [2:0]   rslot,
    output wire [255:0] rdata,
    output wire         rsecret,
    output wire         rvalid,
    output wire         rlocked,
    // direct port to accelerators (slot and its pair slot^1)
    input  wire [2:0]   sel,
    output wire [255:0] d0,
    output wire [255:0] d1,
    output wire         v0,
    output wire         v1
);
  reg [255:0] slot   [0:7];
  reg [7:0]   valid, secret, lock;
  integer i;

  always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      valid <= 8'd0; secret <= 8'd0; lock <= 8'd0;
      for (i = 0; i < 8; i = i + 1) slot[i] <= 256'd0;
    end else if (we && !lock[wslot]) begin
      slot[wslot]   <= wdata;
      valid[wslot]  <= 1'b1;
      lock[wslot]   <= wattr[0];
      secret[wslot] <= wattr[1];
    end
  end

  assign rdata   = slot[rslot];
  assign rsecret = secret[rslot];
  assign rvalid  = valid[rslot];
  assign rlocked = lock[rslot];
  assign d0 = slot[sel];
  assign d1 = slot[sel ^ 3'd1];
  assign v0 = valid[sel];
  assign v1 = valid[sel ^ 3'd1];
endmodule

// ---------------------------------------------------------------------------
// Certification management: 4 certificate-hash entries with valid bits.
// ---------------------------------------------------------------------------
module cert_mgmt (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         we,
    input  wire [1:0]   widx,
    input  wire [255:0] wdata,
    input  wire [1:0]   ridx,
    output wire [255:0] rdata,
    output wire         rvalid
);
  reg [255:0] cert [0:3];
  reg [3:0]   valid;
  integer i;
  always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      valid <= 4'd0;
      for (i = 0; i < 4; i = i + 1) cert[i] <= 256'd0;
    end else if (we) begin
      cert[widx] <= wdata; valid[widx] <= 1'b1;
    end
  end
  assign rdata  = cert[ridx];
  assign rvalid = valid[ridx];
endmodule

// ---------------------------------------------------------------------------
// Key management unit with secure-bus target.
// Address map (sb_addr):  0x00-0x07 key slots,  0x10-0x13 certificate entries,
//                         0x20-0x27 per-slot anti-replay version counters (used by SECURE_LOAD only:
//                         a write succeeds only if the new value is strictly greater than the stored one)
// Handshake: hold sb_valid until sb_ready; sb_err qualifies the response.
// ---------------------------------------------------------------------------
module key_mgmt_unit (
    input  wire         clk,
    input  wire         rst_n,
    // secure bus
    input  wire         sb_valid,
    input  wire         sb_we,
    input  wire [7:0]   sb_addr,
    input  wire [255:0] sb_wdata,
    input  wire [1:0]   sb_attr,
    output reg          sb_ready,
    output reg          sb_err,
    output reg  [255:0] sb_rdata,
    // direct key port to crypto accelerators
    input  wire [2:0]   key_sel,
    output wire [255:0] key_d0,
    output wire [255:0] key_d1,
    output wire         key_v0,
    output wire         key_v1
);
  wire is_key  = (sb_addr[7:3] == 5'b00000);
  wire is_cert = (sb_addr[7:2] == 6'b000100);
  wire is_ver  = (sb_addr[7:3] == 5'b00100);

  // anti-replay counters (volatile here; they must live in NVM in silicon)
  reg [31:0] ver [0:7];
  integer vi;
  wire        ver_ok = (sb_wdata[255:32] == 224'd0) && (sb_wdata[31:0] > ver[sb_addr[2:0]]);

  wire [255:0] ks_rdata, cm_rdata;
  wire         ks_secret, ks_valid, ks_locked, cm_valid;

  wire do_op  = sb_valid && !sb_ready;
  wire ks_we  = do_op && sb_we && is_key;
  wire cm_we  = do_op && sb_we && is_cert;
  wire vr_we  = do_op && sb_we && is_ver && ver_ok;
  always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin for (vi = 0; vi < 8; vi = vi + 1) ver[vi] <= 32'd0; end
    else if (vr_we) ver[sb_addr[2:0]] <= sb_wdata[31:0];
  end

  key_store u_keys (
      .clk(clk), .rst_n(rst_n), .we(ks_we), .wslot(sb_addr[2:0]), .wdata(sb_wdata), .wattr(sb_attr),
      .rslot(sb_addr[2:0]), .rdata(ks_rdata), .rsecret(ks_secret), .rvalid(ks_valid), .rlocked(ks_locked),
      .sel(key_sel), .d0(key_d0), .d1(key_d1), .v0(key_v0), .v1(key_v1));

  cert_mgmt u_certs (
      .clk(clk), .rst_n(rst_n), .we(cm_we), .widx(sb_addr[1:0]), .wdata(sb_wdata),
      .ridx(sb_addr[1:0]), .rdata(cm_rdata), .rvalid(cm_valid));

  always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      sb_ready <= 1'b0; sb_err <= 1'b0; sb_rdata <= 256'd0;
    end else begin
      if (do_op) begin
        sb_ready <= 1'b1;
        sb_err   <= 1'b0;
        sb_rdata <= 256'd0;
        if (is_key) begin
          if (sb_we) sb_err <= ks_locked;
          else if (!ks_valid || ks_secret) sb_err <= 1'b1;
          else sb_rdata <= ks_rdata;
        end else if (is_cert) begin
          if (!sb_we) begin
            if (!cm_valid) sb_err <= 1'b1; else sb_rdata <= cm_rdata;
          end
        end else if (is_ver) begin
          if (!sb_we) sb_rdata <= {224'd0, ver[sb_addr[2:0]]};
          else if (!ver_ok) sb_err <= 1'b1;
        end else sb_err <= 1'b1;
      end else begin
        sb_ready <= 1'b0;
      end
    end
  end
endmodule
