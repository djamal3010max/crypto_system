`timescale 1ns/1ps
// ---------------------------------------------------------------------------
// ECDH (key agreement): shared = x( d * Peer )
// The peer public key is validated by ecc_engine (ONCURVE: x,y < p, not infinity, y^2 = x^3-3x+b)
// before the private scalar is used; P-256 has cofactor 1, so no subgroup check is needed.
// ---------------------------------------------------------------------------
module ecdh_unit (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,
    input  wire [255:0] d,
    input  wire [511:0] peer,
    input  wire         full,        // 1: return the whole point {x,y} (public-key generation), 0: x only
    output reg          sm_start,
    output reg  [255:0] sm_k,
    output reg  [511:0] sm_pt,
    input  wire         sm_done,
    input  wire [511:0] sm_res,
    output reg          done,
    output reg  [511:0] result,
    output reg          ok
);
  localparam [1:0] S_IDLE = 2'd0, S_REQ = 2'd1, S_WAIT = 2'd2;
  reg [1:0] st;
  always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      st <= S_IDLE; sm_start <= 1'b0; sm_k <= 256'd0; sm_pt <= 512'd0;
      done <= 1'b0; result <= 512'd0; ok <= 1'b0;
    end else begin
      sm_start <= 1'b0; done <= 1'b0;
      case (st)
        S_IDLE: if (start) begin sm_k <= d; sm_pt <= peer; st <= S_REQ; end
        S_REQ:  begin sm_start <= 1'b1; st <= S_WAIT; end
        S_WAIT: if (sm_done) begin
          result <= full ? sm_res : {256'd0, sm_res[511:256]};
          ok     <= (sm_res != 512'd0) && (peer != 512'd0) && (d != 256'd0);
          done   <= 1'b1; st <= S_IDLE;
        end
        default: st <= S_IDLE;
      endcase
    end
  end
endmodule

// ---------------------------------------------------------------------------
// ECDSA sign / verify sequencer (P-256). Micro-sequenced over the scalar
// multiplier (sm_*) and the arithmetic datapath (ar_*).
// ---------------------------------------------------------------------------
module ecdsa_unit (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,
    input  wire         verify,
    input  wire [255:0] hash,
    input  wire [511:0] rs,          // {r, s} (verify only)
    input  wire [255:0] k,           // per-signature random (sign only)
    input  wire [255:0] d,           // private key (sign)
    input  wire [255:0] qx,          // public key (verify)
    input  wire [255:0] qy,
    // scalar multiplier port
    output reg          sm_start,
    output reg  [255:0] sm_k,
    output reg  [511:0] sm_pt,
    input  wire         sm_done,
    input  wire [511:0] sm_res,
    // arithmetic datapath port
    output reg          ar_start,
    output reg  [2:0]   ar_op,
    output reg  [511:0] ar_a,
    output reg  [511:0] ar_b,
    input  wire         ar_done,
    input  wire [511:0] ar_out,
    output reg          done,
    output reg  [511:0] result,      // sign: {r, s}
    output reg          ok
);
  localparam OP_PADD = 3'd1, OP_MODN = 3'd2, OP_MULN = 3'd3, OP_INVN = 3'd4, OP_ADDN = 3'd5;
  localparam [255:0] N  = 256'hFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;
  localparam [511:0] G  = {256'h6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
                           256'h4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5};

  localparam [1:0] S_IDLE = 2'd0, S_ISSUE = 2'd1, S_WAIT = 2'd2;
  // steps
  localparam [3:0] SG_KG = 4'd0, SG_R = 4'd1, SG_KINV = 4'd2, SG_RD = 4'd3, SG_EDR = 4'd4, SG_S = 4'd5,
                   VF_W = 4'd8, VF_U1 = 4'd9, VF_U2 = 4'd10, VF_P1 = 4'd11, VF_P2 = 4'd12,
                   VF_ADD = 4'd13, VF_V = 4'd14;

  reg [1:0]   st;
  reg [3:0]   step;
  reg         use_sm, is_verify;
  reg [255:0] e, r, s, kk, dd, kinv, t, w, u1, u2, v;
  reg [511:0] q, p1, xr;

  always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      st <= S_IDLE; step <= 4'd0; use_sm <= 1'b0; is_verify <= 1'b0;
      sm_start <= 1'b0; sm_k <= 256'd0; sm_pt <= 512'd0;
      ar_start <= 1'b0; ar_op <= 3'd0; ar_a <= 512'd0; ar_b <= 512'd0;
      done <= 1'b0; result <= 512'd0; ok <= 1'b0;
      e <= 0; r <= 0; s <= 0; kk <= 0; dd <= 0; kinv <= 0; t <= 0; w <= 0; u1 <= 0; u2 <= 0; v <= 0;
      q <= 0; p1 <= 0; xr <= 0;
    end else begin
      sm_start <= 1'b0; ar_start <= 1'b0; done <= 1'b0;
      case (st)
        S_IDLE: if (start) begin
          e <= hash; kk <= k; dd <= d; q <= {qx, qy};
          r <= rs[511:256]; s <= rs[255:0];
          is_verify <= verify;
          step <= verify ? VF_W : SG_KG;
          st <= S_ISSUE;
        end

        S_ISSUE: begin
          st <= S_WAIT;
          case (step)
            SG_KG:  begin use_sm <= 1; sm_start <= 1; sm_k <= kk; sm_pt <= G; end
            SG_R:   begin use_sm <= 0; ar_start <= 1; ar_op <= OP_MODN; ar_a <= {256'd0, p1[511:256]}; ar_b <= 0; end
            SG_KINV:begin use_sm <= 0; ar_start <= 1; ar_op <= OP_INVN; ar_a <= {256'd0, kk}; ar_b <= 0; end
            SG_RD:  begin use_sm <= 0; ar_start <= 1; ar_op <= OP_MULN; ar_a <= {256'd0, r}; ar_b <= {256'd0, dd}; end
            SG_EDR: begin use_sm <= 0; ar_start <= 1; ar_op <= OP_ADDN; ar_a <= {256'd0, e}; ar_b <= {256'd0, t}; end
            SG_S:   begin use_sm <= 0; ar_start <= 1; ar_op <= OP_MULN; ar_a <= {256'd0, kinv}; ar_b <= {256'd0, t}; end
            VF_W:   begin use_sm <= 0; ar_start <= 1; ar_op <= OP_INVN; ar_a <= {256'd0, s}; ar_b <= 0; end
            VF_U1:  begin use_sm <= 0; ar_start <= 1; ar_op <= OP_MULN; ar_a <= {256'd0, e}; ar_b <= {256'd0, w}; end
            VF_U2:  begin use_sm <= 0; ar_start <= 1; ar_op <= OP_MULN; ar_a <= {256'd0, r}; ar_b <= {256'd0, w}; end
            VF_P1:  begin use_sm <= 1; sm_start <= 1; sm_k <= u1; sm_pt <= G; end
            VF_P2:  begin use_sm <= 1; sm_start <= 1; sm_k <= u2; sm_pt <= q; end
            VF_ADD: begin use_sm <= 0; ar_start <= 1; ar_op <= OP_PADD; ar_a <= p1; ar_b <= xr; end
            VF_V:   begin use_sm <= 0; ar_start <= 1; ar_op <= OP_MODN; ar_a <= {256'd0, xr[511:256]}; ar_b <= 0; end
            default: st <= S_IDLE;
          endcase
        end

        S_WAIT: if ((use_sm && sm_done) || (!use_sm && ar_done)) begin
          st <= S_ISSUE;
          case (step)
            SG_KG:   begin p1 <= sm_res;            step <= SG_R;    end
            SG_R:    begin r  <= ar_out[255:0];     step <= SG_KINV; end
            SG_KINV: begin kinv <= ar_out[255:0];   step <= SG_RD;   end
            SG_RD:   begin t  <= ar_out[255:0];     step <= SG_EDR;  end
            SG_EDR:  begin t  <= ar_out[255:0];     step <= SG_S;    end
            SG_S: begin
              s <= ar_out[255:0];
              result <= {r, ar_out[255:0]};
              ok <= (r != 0) && (ar_out[255:0] != 0) && (p1 != 0);
              done <= 1'b1; st <= S_IDLE;
            end
            VF_W:  begin w  <= ar_out[255:0]; step <= VF_U1; end
            VF_U1: begin u1 <= ar_out[255:0]; step <= VF_U2; end
            VF_U2: begin u2 <= ar_out[255:0]; step <= VF_P1; end
            VF_P1: begin p1 <= sm_res;        step <= VF_P2; end
            VF_P2: begin xr <= sm_res;        step <= VF_ADD; end
            VF_ADD:begin xr <= ar_out;        step <= VF_V;  end
            VF_V: begin
              v <= ar_out[255:0];
              ok <= (r != 0) && (r < N) && (s != 0) && (s < N) && (xr != 0) && (ar_out[255:0] == r);
              result <= 512'd0;
              done <= 1'b1; st <= S_IDLE;
            end
            default: st <= S_IDLE;
          endcase
        end
        default: st <= S_IDLE;
      endcase
    end
  end
endmodule

// ---------------------------------------------------------------------------
// ECC engine: ECDSA + ECDH sharing one ECC datapath (ecc_core)
// op: 0 = ECDSA sign, 1 = ECDSA verify, 2 = ECDH
// ---------------------------------------------------------------------------
// Scalar-multiplication method selection:
//   * ECDSA verify uses only public scalars -> always BA-Radix-2^w (fast, not constant time).
//   * ECDSA sign / ECDH use secret scalars -> constant-time Montgomery ladder, unless
//     BA_SECRET = 1 (only do that if you have completed a side-channel analysis of BA).
// op: 0 sign, 1 verify, 2 ECDH (x only), 3 public key k*P (full point), 4 validate the point in `operand` only
module ecc_engine #(parameter BA_W = 4, parameter BA_SECRET = 0) (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,
    input  wire [2:0]   op,
    input  wire [255:0] hash,
    input  wire [511:0] operand,     // verify: {r,s}; ECDH: peer {x,y}
    input  wire [255:0] k_rand,
    input  wire [255:0] d,
    input  wire [255:0] qx,
    input  wire [255:0] qy,
    output wire         done,
    output wire [511:0] result,
    output wire         ok
);
  reg active_ecdh;
  always @(posedge clk) begin
    if (!rst_n) active_ecdh <= 1'b0;
    else if (start) active_ecdh <= op[1];                    // op 2 = ECDH, op 3 = public key (k*G, full point)
  end

  reg full_q;
  always @(posedge clk) begin
    if (!rst_n) full_q <= 1'b0;
    else if (start) full_q <= (op == 3'd3);
  end

  reg verify_q;
  always @(posedge clk) begin
    if (!rst_n) verify_q <= 1'b0;
    else if (start) verify_q <= (op == 3'd1);
  end

  wire         core_done, core_busy;
  wire [511:0] core_out;

  // ---- public-key validation before ECDH / ECDSA verify ----
  // ECDH: the peer point; verify: the signer's public key {qx, qy}. Must be a valid curve point.
  localparam [1:0] C_IDLE = 2'd0, C_REQ = 2'd1, C_WAIT = 2'd2;
  reg [1:0]   cst;
  reg         chk_start, chk_fail, chk_done, go_ecdh, go_ecdsa, chk_active, chk_only_q, chk_pass;
  reg [511:0] chk_pt;
  always @(posedge clk) begin
    if (!rst_n) begin
      cst <= C_IDLE; chk_start <= 1'b0; chk_fail <= 1'b0; chk_done <= 1'b0;
      go_ecdh <= 1'b0; go_ecdsa <= 1'b0; chk_active <= 1'b0; chk_pt <= 512'd0; chk_only_q <= 1'b0; chk_pass <= 1'b0;
    end else begin
      chk_start <= 1'b0; chk_done <= 1'b0; go_ecdh <= 1'b0; go_ecdsa <= 1'b0;
      case (cst)
        C_IDLE: if (start) begin
          chk_fail <= 1'b0; chk_pass <= 1'b0; chk_only_q <= (op == 3'd4);
          if (op == 3'd0) go_ecdsa <= 1'b1;                    // sign: no public input to validate
          else begin
            chk_pt <= (op[1] || op[2]) ? operand : {qx, qy};
            chk_active <= 1'b1; cst <= C_REQ;
          end
        end
        C_REQ:  begin chk_start <= 1'b1; cst <= C_WAIT; end
        C_WAIT: if (core_done && chk_active) begin
          chk_active <= 1'b0; cst <= C_IDLE;
          if (core_out[0]) begin
            if (chk_only_q) begin chk_pass <= 1'b1; chk_done <= 1'b1; end   // validation-only request
            else if (active_ecdh) go_ecdh <= 1'b1; else go_ecdsa <= 1'b1;
          end else begin chk_fail <= 1'b1; chk_done <= 1'b1; end
        end
        default: cst <= C_IDLE;
      endcase
    end
  end

  wire start_ecdh  = go_ecdh;
  wire start_ecdsa = go_ecdsa;

  // scalar-multiplication requests from ECDSA / ECDH units
  wire         sm_start_a, sm_start_h, sm_start;
  wire [255:0] sm_k_a, sm_k_h, sm_k;
  wire [511:0] sm_pt_a, sm_pt_h, sm_pt;
  assign sm_start = active_ecdh ? sm_start_h : sm_start_a;
  assign sm_k     = active_ecdh ? sm_k_h     : sm_k_a;
  assign sm_pt    = active_ecdh ? sm_pt_h    : sm_pt_a;

  // scalar-arithmetic requests from the ECDSA unit
  wire         ar_start_a;
  wire [2:0]   ar_op_a;
  wire [511:0] ar_a_a, ar_b_a;

  // single shared datapath: scalar mult takes op 0, everything else as requested
  wire         core_start = chk_start | sm_start | ar_start_a;
  wire [2:0]   core_op    = chk_start ? 3'd7 : (sm_start ? ((verify_q || BA_SECRET != 0) ? 3'd6 : 3'd0) : ar_op_a);
  wire [511:0] core_a     = chk_start ? chk_pt : (sm_start ? {256'd0, sm_k} : ar_a_a);
  wire [511:0] core_b     = sm_start ? sm_pt : ar_b_a;

  reg sm_active;
  always @(posedge clk) begin
    if (!rst_n)          sm_active <= 1'b0;
    else if (sm_start)   sm_active <= 1'b1;
    else if (ar_start_a) sm_active <= 1'b0;
  end
  wire sm_done = core_done &&  sm_active;
  wire ar_done = core_done && !sm_active;

  ecc_core #(.BA_W(BA_W)) u_core (.clk(clk), .rst_n(rst_n), .start(core_start), .op(core_op),
                   .in_a(core_a), .in_b(core_b), .done(core_done), .out(core_out), .busy(core_busy));

  wire         dsa_done, dh_done, dsa_ok, dh_ok;
  wire [511:0] dsa_res, dh_res;

  ecdsa_unit u_ecdsa (
      .clk(clk), .rst_n(rst_n), .start(start_ecdsa), .verify(op == 3'd1),
      .hash(hash), .rs(operand), .k(k_rand), .d(d), .qx(qx), .qy(qy),
      .sm_start(sm_start_a), .sm_k(sm_k_a), .sm_pt(sm_pt_a), .sm_done(sm_done), .sm_res(core_out),
      .ar_start(ar_start_a), .ar_op(ar_op_a), .ar_a(ar_a_a), .ar_b(ar_b_a),
      .ar_done(ar_done), .ar_out(core_out),
      .done(dsa_done), .result(dsa_res), .ok(dsa_ok));

  ecdh_unit u_ecdh (
      .clk(clk), .rst_n(rst_n), .start(start_ecdh), .d(d), .peer(operand), .full(full_q),
      .sm_start(sm_start_h), .sm_k(sm_k_h), .sm_pt(sm_pt_h), .sm_done(sm_done), .sm_res(core_out),
      .done(dh_done), .result(dh_res), .ok(dh_ok));

  assign done   = dsa_done | dh_done | chk_done;
  assign result = chk_fail ? 512'd0 : (active_ecdh ? dh_res : dsa_res);
  assign ok     = chk_fail ? 1'b0   : chk_only_q ? chk_pass : (active_ecdh ? dh_ok  : dsa_ok);
endmodule
