`timescale 1ns/1ps
// Controller (FSM): decodes commands from the smart-card CPU and orchestrates
// the accelerators, key management unit (secure bus) and the TRNG.
//
// Commands (cpu_cmd):
//   01 GET_RANDOM   result[255:0] = 256 random bits
//   02 HASH         a = message (256b)                      -> SHA-256 digest
//   03 AES_ENC      slot = key slot (low 128b), a[127:0]=pt  -> ct in result[127:0]   (ECB)
//   04 AES_DEC      slot = key slot, a[127:0]=ct             -> pt in result[127:0]   (ECB)
//   05 AES_CBC_ENC  slot, a[127:0]=pt,  b[127:0]=IV/previous ct -> ct in result[127:0]
//   06 AES_CBC_DEC  slot, a[127:0]=ct,  b[127:0]=IV/previous ct -> pt in result[127:0]
//   07 HASH_INIT    slot[3:0] = algorithm: 0 SHA-1 (legacy), 1 SHA-224, 2 SHA-256, 3 SHA-384, 4 SHA-512,
//                   5 SHA3-224, 6 SHA3-256, 7 SHA3-384, 8 SHA3-512
//   08 HASH_UPDATE  a[6:0] = byte count (0..64), b = data, byte 0 at b[511:504]
//   09 HASH_FINAL   same as UPDATE for the last chunk; result = digest, left-aligned (byte 0 at bit 511)
//   13 SIGN_LAST    slot = private key; signs the digest latched by the last HASH_FINAL (hash-then-sign);
//                   e = leftmost 256 bits of the digest (digest as integer if shorter than 256 bits)
//   14 VERIFY_LAST  slot = even slot of the public key pair, b = {r,s}; verifies against the latched digest
//   15 ECDH_KDF     slot = private key, b = peer {x,y}, a[4:0] = FixedInfo length (0..28), a[255:32] = FixedInfo;
//                   result[255:0] = SHA-256(00000001 || Z || FixedInfo)  (SP 800-56C one-step KDF); Z is never exposed
//   16 SECURE_LOAD  key injection/rotation in ONE command (authenticate, unwrap, write - in that order):
//                   a[255:128] = AES-wrapped 128-bit key, a[7:4] = KEK slot, a[3:0] = issuer public-key slot (even),
//                   slot = destination slot, attr = destination attributes, b = {r,s}.
//                   a[39:8] = package version (anti-replay: must be greater than the version last installed in `slot`).
//                   Signed message = wrapped(16B) || dest(1B) || attr(1B) || kek(1B) || issuer(1B) || version(4B BE), hashed with SHA-256.
//                   The key is written only if the signature verifies; the plaintext key is never visible to the CPU.
//   17 CERT_VERIFY  hash-then-verify for certificates: slot = issuer public-key slot (even), a[1:0] = certificate entry,
//                   b = {r,s}; verifies the digest latched by HASH_FINAL and, only on success, stores it in the entry.
//                   attr[0] = 1 additionally PARSES the certificate body (SCC-1 format, see README: version byte 0x01 followed by
//                   the subject public key x||y, 65 bytes in total), checks the subject key is on the curve and installs it as a
//                   public-key pair in slots a[5:2], a[5:2]+1 (a[5:2] even, a[7:6] = 0).
//   18 KEYGEN       ephemeral/static key-pair generation: slot = destination slot, attr = attributes
//                   (the secret attribute is forced on); the TRNG supplies d with 1 <= d < n (rejection sampling),
//                   d is written to the key store, and result = public key {x,y} = d*G. d never leaves the chip.
//   10 ECDSA_SIGN   slot = private key slot, a = hash        -> result = {r,s}
//   11 ECDSA_VERIFY slot = even slot holding Qx (Qy in slot^1), a = hash, b = {r,s}
//                                                            -> cpu_ok
//   12 ECDH         slot = private key slot, b = peer {x,y}  -> result[255:0] = shared x
//   20 KEY_WRITE    slot, a = key, attr = {secret, lock}
//   21 KEY_READ     slot  (fails for secret slots)
//   30 CERT_WRITE   slot[1:0], a = certificate hash
//   31 CERT_READ    slot[1:0]
//   32 CERT_CHECK   slot[1:0], a = hash to compare           -> cpu_ok
module controller_fsm (
    input  wire         clk,
    input  wire         rst_n,
    // smart-card CPU interface
    input  wire         cpu_valid,
    output wire         cpu_ready,
    input  wire [7:0]   cpu_cmd,
    input  wire [3:0]   cpu_slot,
    input  wire [255:0] cpu_a,
    input  wire [511:0] cpu_b,
    input  wire [1:0]   cpu_attr,
    output reg          cpu_done,
    output reg          cpu_err,
    output reg          cpu_ok,
    output reg  [511:0] cpu_result,
    // TRNG
    output reg          rng_ack,
    input  wire         rng_valid,
    input  wire [255:0] rng_data,
    input  wire         rng_alarm,
    // crypto accelerators
    output reg          acc_start,
    output reg  [3:0]   acc_op,
    output reg  [255:0] acc_a,
    output reg  [511:0] acc_b,
    output reg  [255:0] acc_k,
    input  wire         acc_done,
    input  wire         acc_err,
    input  wire         acc_ok,
    input  wire [511:0] acc_result,
    // key management: direct key port control + secure bus master
    output wire [2:0]   key_sel,
    input  wire         key_v0,
    input  wire         key_v1,
    output reg          sb_valid,
    output reg          sb_we,
    output reg  [7:0]   sb_addr,
    output reg  [255:0] sb_wdata,
    output reg  [1:0]   sb_attr,
    input  wire         sb_ready,
    input  wire         sb_err,
    input  wire [255:0] sb_rdata
);
  localparam [7:0] CMD_RANDOM = 8'h01, CMD_HASH = 8'h02, CMD_AES = 8'h03,
                   CMD_AESD = 8'h04, CMD_CBCE = 8'h05, CMD_CBCD = 8'h06,
                   CMD_HINIT = 8'h07, CMD_HUPD = 8'h08, CMD_HFIN = 8'h09,
                   CMD_SLAST = 8'h13, CMD_VLAST = 8'h14, CMD_KDF = 8'h15, CMD_SLOAD = 8'h16, CMD_CVER = 8'h17, CMD_KGEN = 8'h18,
                   CMD_SIGN = 8'h10, CMD_VERIFY = 8'h11, CMD_ECDH = 8'h12,
                   CMD_KWR = 8'h20, CMD_KRD = 8'h21,
                   CMD_CWR = 8'h30, CMD_CRD = 8'h31, CMD_CCHK = 8'h32;

  localparam [3:0] S_IDLE = 4'd0, S_DECODE = 4'd1, S_RNG = 4'd2, S_ACC_GO = 4'd3, S_ACC_WAIT = 4'd4,
                   S_SB_REQ = 4'd5, S_SB_WAIT = 4'd6, S_DONE = 4'd7, S_ERR = 4'd8, S_SL = 4'd9;

  reg [3:0]   st;
  reg [7:0]   cmd_q;
  reg [3:0]   slot_q;
  reg [255:0] a_q;
  reg [511:0] b_q;
  reg [1:0]   attr_q;

  // ---- digest latched by HASH_FINAL, consumed by SIGN_LAST / VERIFY_LAST ----
  reg [3:0]   hash_alg_q;
  reg [511:0] last_digest;
  reg [6:0]   last_dlen;
  reg         ld_valid;
  reg [1:0]   kdf_ph;
  reg [255:0] z_q;

  function [6:0] dlen_of(input [3:0] a);
    case (a)
      4'd0: dlen_of = 7'd20;  4'd1: dlen_of = 7'd28;  4'd2: dlen_of = 7'd32;
      4'd3: dlen_of = 7'd48;  4'd4: dlen_of = 7'd64;  4'd5: dlen_of = 7'd28;
      4'd6: dlen_of = 7'd32;  4'd7: dlen_of = 7'd48;  default: dlen_of = 7'd64;
    endcase
  endfunction
  wire [511:0] ld_shift = last_digest >> (10'd512 - {last_dlen, 3'b000});
  wire [255:0] e_last   = (last_dlen >= 7'd32) ? last_digest[511:256] : ld_shift[255:0];

  assign cpu_ready = (st == S_IDLE);
  reg [2:0] ksel_r;
  assign key_sel   = ksel_r;
  reg [3:0] sl_ph;                       // secure-load sequencer phase
  reg [2:0] cv_ph;                       // certificate-verify sequencer phase
  // first 72 bytes of the last hashed message (certificate body capture) and its length
  reg [575:0] cap;
  reg [7:0]   msg_len;                   // bytes hashed so far in the open/last session (saturates at 255)
  wire [511:0] cap_chunk = b_q & ~({512{1'b1}} >> {a_q[6:0], 3'b000});
  wire [8:0]   msg_len_sum = {1'b0, msg_len} + {2'b00, a_q[6:0]};   // 9 bits so the carry is visible
  wire [255:0] cap_x = cap[567:312];
  wire [255:0] cap_y = cap[311:56];
  reg [1:0] kg_ph;                       // key-generation sequencer phase
  localparam [255:0] P256_N  = 256'hFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;
  localparam [511:0] P256_G  = {256'h6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
                                256'h4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5};
  // signed secure-load message: wrapped key || dest || attr || kek || issuer (20 bytes, left-aligned)
  wire [511:0] sl_msg = {a_q[255:128], {4'd0, slot_q}, {6'd0, attr_q}, {4'd0, a_q[7:4]}, {4'd0, a_q[3:0]}, a_q[39:8], 320'd0};

  always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      st <= S_IDLE; cmd_q <= 8'd0; slot_q <= 4'd0; a_q <= 256'd0; b_q <= 512'd0; attr_q <= 2'd0;
      cpu_done <= 1'b0; cpu_err <= 1'b0; cpu_ok <= 1'b0; cpu_result <= 512'd0;
      rng_ack <= 1'b0; acc_start <= 1'b0; acc_op <= 4'd0; acc_a <= 256'd0; acc_b <= 512'd0; acc_k <= 256'd0;
      sb_valid <= 1'b0; sb_we <= 1'b0; sb_addr <= 8'd0; sb_wdata <= 256'd0; sb_attr <= 2'd0;
      ksel_r <= 3'd0; sl_ph <= 4'd0; cv_ph <= 3'd0; kg_ph <= 2'd0; cap <= 576'd0; msg_len <= 8'd0;
      hash_alg_q <= 4'd0; last_digest <= 512'd0; last_dlen <= 7'd0; ld_valid <= 1'b0; kdf_ph <= 2'd0; z_q <= 256'd0;
    end else begin
      cpu_done <= 1'b0; rng_ack <= 1'b0; acc_start <= 1'b0;

      case (st)
        S_IDLE: if (cpu_valid) begin
          cmd_q <= cpu_cmd; slot_q <= cpu_slot; a_q <= cpu_a; b_q <= cpu_b; attr_q <= cpu_attr;
          ksel_r <= cpu_slot[2:0]; sl_ph <= 4'd0; cv_ph <= 3'd0; kg_ph <= 2'd0;
          cpu_err <= 1'b0; cpu_ok <= 1'b0; cpu_result <= 512'd0;
          st <= S_DECODE;
        end

        S_DECODE: begin
          acc_a <= a_q; acc_b <= b_q;
          case (cmd_q)
            CMD_RANDOM: st <= S_RNG;
            CMD_HASH:   begin acc_op <= 4'd0; st <= S_ACC_GO; end
            CMD_HINIT:  begin acc_op <= 4'd8;  acc_a <= {252'd0, slot_q}; hash_alg_q <= slot_q; ld_valid <= 1'b0; cap <= 576'd0; msg_len <= 8'd0; st <= S_ACC_GO; end
            CMD_HUPD:   begin acc_op <= 4'd9;  st <= S_ACC_GO; end
            CMD_HFIN:   begin acc_op <= 4'd10; st <= S_ACC_GO; end
            CMD_AES,
            CMD_AESD,
            CMD_CBCE,
            CMD_CBCD:   begin
                          acc_op <= (cmd_q == CMD_AES) ? 4'd1 : (cmd_q == CMD_AESD) ? 4'd5 :
                                    (cmd_q == CMD_CBCE) ? 4'd6 : 4'd7;
                          st <= (slot_q < 8 && key_v0) ? S_ACC_GO : S_ERR;
                        end
            CMD_SLAST:  begin acc_op <= 4'd2; acc_a <= e_last;
                              st <= (slot_q < 8 && key_v0 && ld_valid) ? S_RNG : S_ERR; end
            CMD_VLAST:  begin acc_op <= 4'd3; acc_a <= e_last;
                              st <= (slot_q < 8 && key_v0 && key_v1 && ld_valid) ? S_ACC_GO : S_ERR; end
            CMD_KDF:    begin acc_op <= 4'd4; kdf_ph <= 2'd1;
                              st <= (slot_q < 8 && key_v0 && a_q[4:0] <= 5'd28) ? S_ACC_GO : S_ERR; end
            CMD_KGEN:   begin kg_ph <= 2'd1; st <= (slot_q < 8) ? S_RNG : S_ERR; end
            CMD_SLOAD:  begin
                          // issuer pair (even slot) selected first; its validity is checked in S_SL
                          // first: read the slot's version counter (cheap replay rejection before any crypto)
                          sb_we <= 1'b0; sb_addr <= {5'b00100, slot_q[2:0]}; sb_attr <= 2'd0; sl_ph <= 4'd8;
                          st <= (slot_q < 8 && a_q[7:4] < 8 && a_q[3:0] < 8 && !a_q[0]) ? S_SB_REQ : S_ERR;
                        end
            CMD_CVER:   begin acc_op <= 4'd3; acc_a <= e_last; cv_ph <= 3'd1;
                          // base checks; with attr[0] (install) the body must also be a well-formed SCC-1 certificate
                          st <= (slot_q < 8 && !slot_q[0] && key_v0 && key_v1 && ld_valid &&
                                 (attr_q[0] ? (a_q[7:5] == 3'd0 && !a_q[2] && msg_len == 8'd65 && cap[575:568] == 8'h01)
                                            : (a_q[7:0] < 8'd4)))
                                ? S_ACC_GO : S_ERR; end
            CMD_SIGN:   begin acc_op <= 4'd2; st <= (slot_q < 8 && key_v0) ? S_RNG : S_ERR; end
            CMD_VERIFY: begin acc_op <= 4'd3; st <= (slot_q < 8 && key_v0 && key_v1) ? S_ACC_GO : S_ERR; end
            CMD_ECDH:   begin acc_op <= 4'd4; st <= (slot_q < 8 && key_v0) ? S_ACC_GO : S_ERR; end
            CMD_KWR:    begin sb_we <= 1; sb_addr <= {4'h0, slot_q}; sb_wdata <= a_q; sb_attr <= attr_q; st <= S_SB_REQ; end
            CMD_KRD:    begin sb_we <= 0; sb_addr <= {4'h0, slot_q}; sb_attr <= 2'd0; st <= S_SB_REQ; end
            CMD_CWR:    begin sb_we <= 1; sb_addr <= {4'h1, 2'b00, slot_q[1:0]}; sb_wdata <= a_q; sb_attr <= 2'd0;
                              st <= (slot_q < 4) ? S_SB_REQ : S_ERR; end          // only 4 certificate entries
            CMD_CRD,
            CMD_CCHK:   begin sb_we <= 0; sb_addr <= {4'h1, 2'b00, slot_q[1:0]}; sb_attr <= 2'd0;
                              st <= (slot_q < 4) ? S_SB_REQ : S_ERR; end
            default:    st <= S_ERR;
          endcase
        end

        S_RNG: begin
          if (rng_alarm) st <= S_ERR;
          else if (rng_valid) begin
            rng_ack <= 1'b1;
            if (cmd_q == CMD_RANDOM) begin
              cpu_result <= {256'd0, rng_data}; cpu_ok <= 1'b1; st <= S_DONE;
            end else if (cmd_q == CMD_KGEN) begin
              if (rng_data != 256'd0 && rng_data < P256_N) begin       // valid scalar: store it as a secret key
                sb_we <= 1'b1; sb_addr <= {4'h0, slot_q}; sb_wdata <= rng_data; sb_attr <= attr_q | 2'b10;
                st <= S_SB_REQ;
              end                                                       // else: rejected, draw another word
            end else begin
              acc_k <= rng_data; st <= S_ACC_GO;
            end
          end
        end

        S_ACC_GO: begin acc_start <= 1'b1; st <= S_ACC_WAIT; end

        S_ACC_WAIT: if (acc_done) begin
          if (kdf_ph == 2'd1) begin                                   // ECDH finished
            if (acc_err) begin kdf_ph <= 2'd0; st <= S_ERR; end
            else if (!acc_ok) begin cpu_result <= 512'd0; cpu_ok <= 1'b0; kdf_ph <= 2'd0; st <= S_DONE; end
            else begin z_q <= acc_result[255:0]; acc_op <= 4'd8; acc_a <= 256'd2; kdf_ph <= 2'd2; st <= S_ACC_GO; end
          end else if (kdf_ph == 2'd2) begin                          // SHA-256 session opened
            acc_op <= 4'd10; acc_a <= {249'd0, (7'd36 + {2'd0, a_q[4:0]})};
            acc_b <= {32'h00000001, z_q, a_q[255:32]};
            kdf_ph <= 2'd3; st <= S_ACC_GO;
          end else if (kdf_ph == 2'd3) begin                          // KDF output
            cpu_result <= {256'd0, acc_result[511:256]}; cpu_ok <= !acc_err;
            kdf_ph <= 2'd0; z_q <= 256'd0; st <= acc_err ? S_ERR : S_DONE;
          end else if (kg_ph == 2'd2) begin                           // ---- KEYGEN: public key computed ----
            kg_ph <= 2'd0; cpu_result <= acc_result; cpu_ok <= acc_ok && !acc_err;
            st <= acc_err ? S_ERR : S_DONE;
          end else if (sl_ph != 4'd0) begin                           // ---- SECURE_LOAD sequencer ----
            if (acc_err) begin sl_ph <= 4'd0; st <= S_ERR; end
            else case (sl_ph)
              4'd2: begin                                              // SHA-256 session open: hash the package
                acc_op <= 4'd10; acc_a <= 256'd24; acc_b <= sl_msg; sl_ph <= 4'd3; st <= S_ACC_GO;
              end
              4'd3: begin                                              // digest ready: verify the signature
                acc_op <= 4'd3; acc_a <= acc_result[511:256]; acc_b <= b_q; sl_ph <= 4'd4; st <= S_ACC_GO;
              end
              4'd4: begin
                if (!acc_ok) begin cpu_result <= 512'd0; cpu_ok <= 1'b0; sl_ph <= 4'd0; st <= S_DONE; end   // not authentic: nothing written
                else begin ksel_r <= a_q[6:4]; sl_ph <= 4'd5; st <= S_SL; end                                 // select the KEK
              end
              4'd6: begin                                              // key unwrapped: write it to the key store
                sb_we <= 1'b1; sb_addr <= {4'h0, slot_q}; sb_wdata <= {128'd0, acc_result[127:0]}; sb_attr <= attr_q;
                sl_ph <= 4'd7; st <= S_SB_REQ;
              end
              default: begin sl_ph <= 4'd0; st <= S_ERR; end
            endcase
          end else if (cv_ph != 3'd0) begin                           // ---- CERT_VERIFY sequencer ----
            if (acc_err) begin cv_ph <= 3'd0; st <= S_ERR; end
            else if (!acc_ok) begin cpu_result <= 512'd0; cpu_ok <= 1'b0; cv_ph <= 3'd0; st <= S_DONE; end   // bad signature / bad subject key: nothing written
            else if (cv_ph == 3'd1 && attr_q[0]) begin                // signature valid: validate the subject key
              acc_op <= 4'd12; acc_b <= {cap_x, cap_y}; cv_ph <= 3'd3; st <= S_ACC_GO;
            end else if (cv_ph == 3'd3) begin                         // subject key is on the curve: install x
              sb_we <= 1'b1; sb_addr <= {5'b0, a_q[4:3], 1'b0}; sb_wdata <= cap_x; sb_attr <= 2'd0;
              cv_ph <= 3'd4; st <= S_SB_REQ;
            end else begin                                            // plain hash-then-verify: record the digest
              sb_we <= 1'b1; sb_addr <= {4'h1, 2'b00, a_q[1:0]}; sb_wdata <= e_last; sb_attr <= 2'd0;
              cv_ph <= 3'd2; st <= S_SB_REQ;
            end
          end else begin
            cpu_result <= acc_result; cpu_ok <= acc_ok;
            if ((cmd_q == CMD_HUPD || cmd_q == CMD_HFIN) && !acc_err) begin     // certificate-body capture
              if (msg_len < 8'd72) cap <= cap | ({cap_chunk, 64'd0} >> {msg_len, 3'b000});
              msg_len <= msg_len_sum[8] ? 8'd255 : msg_len_sum[7:0];                 // saturate, never wrap
            end
            if (cmd_q == CMD_HFIN && !acc_err) begin
              last_digest <= acc_result; last_dlen <= dlen_of(hash_alg_q); ld_valid <= 1'b1;
            end
            st <= acc_err ? S_ERR : S_DONE;
          end
        end

        S_SB_REQ: begin sb_valid <= 1'b1; st <= S_SB_WAIT; end

        // secure-load dispatcher: one settling cycle after ksel_r changes, then check the slot(s) are populated
        S_SL: begin
          if (sl_ph == 4'd1) begin
            if (!(key_v0 && key_v1)) begin sl_ph <= 4'd0; st <= S_ERR; end
            else begin acc_op <= 4'd8; acc_a <= 256'd2; sl_ph <= 4'd2; st <= S_ACC_GO; end    // open a SHA-256 session
          end else begin                                               // sl_ph == 5: KEK selected
            if (!key_v0) begin sl_ph <= 4'd0; st <= S_ERR; end
            else begin acc_op <= 4'd5; acc_a <= {128'd0, a_q[255:128]}; sl_ph <= 4'd6; st <= S_ACC_GO; end   // AES-ECB decrypt
          end
        end

        S_SB_WAIT: if (sb_ready) begin
          sb_valid <= 1'b0;
          if (kg_ph == 2'd1) begin                                     // generated private key stored
            kg_ph <= 2'd2; sb_wdata <= 256'd0;
            if (sb_err) begin kg_ph <= 2'd0; st <= S_ERR; end
            else begin acc_op <= 4'd11; acc_a <= 256'd0; acc_b <= P256_G; st <= S_ACC_GO; end
          end else if (sl_ph == 4'd8) begin                            // version counter read
            if (sb_err) begin sl_ph <= 4'd0; st <= S_ERR; end
            else if (a_q[39:8] > sb_rdata[31:0]) begin ksel_r <= a_q[2:0]; sl_ph <= 4'd1; st <= S_SL; end
            else begin cpu_result <= 512'd0; cpu_ok <= 1'b0; sl_ph <= 4'd0; st <= S_DONE; end   // replay / downgrade: rejected
          end else if (sl_ph == 4'd7) begin                            // secure-load key write finished
            sb_wdata <= 256'd0;                                        // drop the plaintext key from the bus register
            if (sb_err) begin sl_ph <= 4'd0; st <= S_ERR; end
            else begin                                                 // record the installed version
              sb_we <= 1'b1; sb_addr <= {5'b00100, slot_q[2:0]}; sb_wdata <= {224'd0, a_q[39:8]}; sb_attr <= 2'd0;
              sl_ph <= 4'd9; st <= S_SB_REQ;
            end
          end else if (sl_ph == 4'd9) begin                            // counter written
            sl_ph <= 4'd0; sb_wdata <= 256'd0;
            if (sb_err) st <= S_ERR; else begin cpu_result <= 512'd0; cpu_ok <= 1'b1; st <= S_DONE; end
          end else if (cv_ph == 3'd4) begin                            // subject key x installed -> install y
            if (sb_err) begin cv_ph <= 3'd0; st <= S_ERR; end
            else begin sb_we <= 1'b1; sb_addr <= {5'b0, a_q[4:3], 1'b1}; sb_wdata <= cap_y; sb_attr <= 2'd0; cv_ph <= 3'd5; st <= S_SB_REQ; end
          end else if (cv_ph == 3'd5) begin                            // subject key y installed -> record the digest
            if (sb_err) begin cv_ph <= 3'd0; st <= S_ERR; end
            else begin sb_we <= 1'b1; sb_addr <= {4'h1, 2'b00, a_q[1:0]}; sb_wdata <= e_last; sb_attr <= 2'd0; cv_ph <= 3'd2; st <= S_SB_REQ; end
          end else if (cv_ph == 3'd2) begin                            // certificate entry write finished
            cv_ph <= 3'd0;
            if (sb_err) st <= S_ERR; else begin cpu_result <= 512'd0; cpu_ok <= 1'b1; st <= S_DONE; end
          end else if (sb_err) st <= S_ERR;
          else begin
            cpu_result <= {256'd0, sb_rdata};
            cpu_ok <= (cmd_q == CMD_CCHK) ? (sb_rdata == a_q) : 1'b1;
            st <= S_DONE;
          end
        end

        S_DONE: begin cpu_done <= 1'b1; st <= S_IDLE; end
        S_ERR:  begin kg_ph <= 2'd0; sl_ph <= 4'd0; cv_ph <= 3'd0; sb_wdata <= 256'd0; kdf_ph <= 2'd0; z_q <= 256'd0; cpu_err <= 1'b1; cpu_ok <= 1'b0; cpu_done <= 1'b1; st <= S_IDLE; end
        default: st <= S_IDLE;
      endcase
    end
  end
endmodule
