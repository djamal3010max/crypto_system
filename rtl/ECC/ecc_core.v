`timescale 1ns/1ps
// Synthesizable ECC datapath + sequencer for NIST P-256 (secp256r1).
//
//  * 16 x 256-bit register file, one bit-serial modular multiplier, 1-cycle
//    modular add/sub, microcoded complete point add/double (ecc_ucode).
//  * Scalar multiplication = Montgomery ladder: exactly one point add and one
//    point double per key bit, conditional swaps instead of branches, same
//    cycle count for every scalar.
//  * Projective -> affine conversion by Fermat inversion (p-2) on the same
//    multiplier. (The exponent is a public constant, so its bit pattern is not
//    a secret-dependent branch.)
//
// Operations (op):
//   0 SCALAR  in_a[255:0] = k,  in_b = {x,y} affine  -> out = {x,y}, 0 = infinity
//   1 PADD    in_a = {x,y}, in_b = {x,y} (all-zero = infinity) -> out = {x,y}
//   2 MODN    out[255:0] = in_a[255:0] mod n    (in_a < 2n)
//   3 MULN    out[255:0] = in_a * in_b mod n
//   4 INVN    out[255:0] = in_a^-1 mod n
//   5 ADDN    out[255:0] = in_a + in_b mod n
//   7 ONCURVE out[0] = 1 iff in_a = {x,y} is a valid affine point: x,y < p, not (0,0), y^2 = x^3 - 3x + b
//   6 SCALAR_BA  same interface as SCALAR but using BA-Radix-2^w (window BA_W):
//             boundary-aligned recoding + odd-multiple table {P,3P,..,(2^(BA_W-1)-1)P}.
//             FASTER but NOT constant time: the number and spacing of point additions
//             depend on the scalar. Use it only for public scalars (e.g. ECDSA verify).
// Input points are NOT validated to lie on the curve.
module ecc_core #(parameter BA_W = 4) (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,
    input  wire [2:0]   op,
    input  wire [511:0] in_a,
    input  wire [511:0] in_b,
    output reg          done,
    output reg  [511:0] out,
    output wire         busy
);
  localparam [255:0] P  = 256'hFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF;
  localparam [255:0] N  = 256'hFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;
  localparam [255:0] CB = 256'h5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B;

  localparam [2:0] OP_SCALAR = 3'd0, OP_PADD = 3'd1, OP_MODN = 3'd2,
                   OP_MULN = 3'd3, OP_INVN = 3'd4, OP_ADDN = 3'd5, OP_SCALAR_BA = 3'd6, OP_ONCURVE = 3'd7;

  localparam NENT = 1 << (BA_W - 2);          // table entries: P, 3P, ..., (2^(w-1)-1)P

  // microcode program boundaries (must match ecc_ucode.v)
  localparam [6:0] P_ADD_S = 7'd0,  P_ADD_E = 7'd42,
                   P_DBL_S = 7'd43, P_DBL_E = 7'd76,
                   P_MOVB_S = 7'd77, P_MOVB_E = 7'd79,
                   P_MOVA_S = 7'd80, P_MOVA_E = 7'd82,
                   P_AFF_S = 7'd83, P_AFF_E = 7'd84,
                   P_MULN_S = 7'd85, P_MULN_E = 7'd85,
                   P_ADDN_S = 7'd86, P_ADDN_E = 7'd86,
                   P_ONC_S = 7'd87, P_ONC_E = 7'd93;

  localparam [4:0] S_IDLE = 5'd0, S_LOAD = 5'd1, S_PROG = 5'd2, S_MULW = 5'd3, S_NEXT = 5'd4,
                   S_SW1 = 5'd5, S_SW2 = 5'd6, S_NORM = 5'd7,
                   S_INVI = 5'd8, S_INVA = 5'd9, S_INVAW = 5'd10, S_INVB = 5'd11, S_INVBW = 5'd12,
                   S_BA_REC = 5'd13, S_PRE_LD = 5'd14, S_EV_INIT = 5'd15, S_EV_FETCH = 5'd16,
                   S_EV_DBL = 5'd17, S_EV_STEP = 5'd18;

  localparam [4:0] M_SC_ADD = 5'd0, M_SC_MOVB = 5'd1, M_SC_DBL = 5'd2, M_SC_MOVA = 5'd3,
                   M_PA_ADD = 5'd4, M_PA_MOVA = 5'd5, M_N_INV = 5'd6, M_N_AFF = 5'd7,
                   M_MULN = 5'd8, M_ADDN = 5'd9, M_INVN = 5'd10,
                   M_BA_D2 = 5'd11, M_BA_PADD = 5'd12, M_BA_EADD = 5'd13, M_BA_EMOVA = 5'd14,
                   M_BA_EDBL = 5'd15, M_BA_EDMOV = 5'd16, M_ONC = 5'd17;

  reg [4095:0] RF;                       // 16 x 256-bit register file
  reg [4:0]    st, mst;
  reg [2:0]    op_q;
  reg [511:0]  a_q, b_q;
  reg          use_n;
  reg [6:0]    pc, pc_end;
  reg [3:0]    dst_q, inv_src;
  reg [7:0]    ibit;
  reg [8:0]    iv;
  reg          mm_start;
  reg [255:0]  mm_a, mm_b;
  wire         mm_done;
  wire [255:0] mm_res;

  // ---- BA-Radix-2^w state ----
  reg  [(NENT+1)*768-1:0] TBL;           // NENT odd multiples (projective) + 2P in slot NENT

  // Explicit mux/demux helpers instead of variable part-selects on the 4096/3840-bit vectors:
  // yosys otherwise builds huge barrel shifters and runs out of memory.
  function [255:0] rdf(input [3:0] i, input [4095:0] v);
    integer j;
    begin
      rdf = 256'd0;
      for (j = 0; j < 16; j = j + 1) if (i == j) rdf = v[j*256 +: 256];
    end
  endfunction
  function [767:0] rdt(input [7:0] i, input [(NENT+1)*768-1:0] v);
    integer j;
    begin
      rdt = 768'd0;
      for (j = 0; j <= NENT; j = j + 1) if (i == j) rdt = v[j*768 +: 768];
    end
  endfunction
  integer jj;
  reg  [7:0]   ii;                       // precompute index
  reg  [8:0]   ei;                       // evaluation: current slice index (counts down)
  reg  [8:0]   dcnt;                     // doublings still to do after the current addition
  reg          rc_start;
  wire         rc_busy, rc_done;
  wire [8:0]   rc_count, rc_pos_a, rc_pos_b;
  wire         rc_neg_a;
  wire [BA_W-3:0] rc_idx_a;

  ba_recoder #(.W(BA_W)) u_rec (
      .clk(clk), .rst_n(rst_n), .start(rc_start), .k(a_q[255:0]),
      .busy(rc_busy), .done(rc_done), .count(rc_count),
      .ra(ei), .pos_a(rc_pos_a), .neg_a(rc_neg_a), .idx_a(rc_idx_a),
      .rb(ei - 9'd1), .pos_b(rc_pos_b));

  wire [767:0] tbl_sel   = rdt({{(8-(BA_W-2)){1'b0}}, rc_idx_a}, TBL);
  wire [255:0] tbl_sel_y = tbl_sel[511:256];
  wire [255:0] tbl_y_neg = (tbl_sel_y == 256'd0) ? 256'd0 : (P - tbl_sel_y);
  wire [767:0] tbl_prev  = rdt(ii - 8'd1, TBL);
  wire [767:0] tbl_2p    = TBL[NENT*768 +: 768];

  wire [255:0] M = use_n ? N : P;
  wire [255:0] E = M - 256'd2;           // inversion exponent
  assign busy = (st != S_IDLE);

  modmul_serial u_mm (.clk(clk), .rst_n(rst_n), .start(mm_start), .a(mm_a), .b(mm_b), .m(M),
                      .done(mm_done), .res(mm_res));

  wire [14:0] ins;
  ecc_ucode u_rom (.addr(pc), .instr(ins));
  wire [2:0]   i_op = ins[14:12];
  wire [3:0]   i_d  = ins[11:8];
  wire [3:0]   i_s1 = ins[7:4];
  wire [3:0]   i_s2 = ins[3:0];
  wire [255:0] ra = rdf(i_s1, RF);
  wire [255:0] rb = rdf(i_s2, RF);

  // modular add / subtract (operands < m)
  wire [256:0] sum  = {1'b0, ra} + {1'b0, rb};
  wire [256:0] sumr = (sum >= {1'b0, M}) ? (sum - {1'b0, M}) : sum;
  wire [256:0] dif  = {1'b0, ra} - {1'b0, rb};
  wire [256:0] difr = (ra < rb) ? (dif + {1'b0, M}) : dif;

  reg [255:0] alu_res;
  always @* begin
    case (i_op)
      3'd1:    alu_res = sumr[255:0];
      3'd2:    alu_res = difr[255:0];
      default: alu_res = ra;             // MOV
    endcase
  end

  wire prog_last = (pc == pc_end);

  // one conditional subtraction reduces any value < 2n
  wire [255:0] a_red = (a_q[255:0] >= N) ? (a_q[255:0] - N) : a_q[255:0];
  wire [255:0] b_red = (b_q[255:0] >= N) ? (b_q[255:0] - N) : b_q[255:0];

  wire k_bit = a_q[ibit];                // scalar bit currently processed
  wire a_inf = (a_q == 512'd0);
  wire b_inf = (b_q == 512'd0);

  always @(posedge clk) begin
    if (!rst_n) begin
      st <= S_IDLE; mst <= 4'd0; op_q <= 3'd0; a_q <= 512'd0; b_q <= 512'd0; use_n <= 1'b0;
      pc <= 7'd0; pc_end <= 7'd0; dst_q <= 4'd0; inv_src <= 4'd0; ibit <= 8'd0; iv <= 9'd0;
      mm_start <= 1'b0; mm_a <= 256'd0; mm_b <= 256'd0; done <= 1'b0; out <= 512'd0;
      RF <= 4096'd0; TBL <= {((NENT+1)*768){1'b0}}; ii <= 8'd0; ei <= 9'd0; dcnt <= 9'd0; rc_start <= 1'b0;
    end else begin
      done <= 1'b0;
      mm_start <= 1'b0;
      rc_start <= 1'b0;

      case (st)
        S_IDLE: if (start) begin
          op_q <= op; a_q <= in_a; b_q <= in_b; st <= S_LOAD;
        end

        S_LOAD: begin
          RF[14*256 +: 256] <= CB;
          case (op_q)
            OP_SCALAR: begin
              use_n <= 1'b0;
              RF[0*256 +: 256] <= 256'd0; RF[1*256 +: 256] <= 256'd1; RF[2*256 +: 256] <= 256'd0;
              RF[3*256 +: 256] <= b_inf ? 256'd0 : b_q[511:256];
              RF[4*256 +: 256] <= b_inf ? 256'd1 : b_q[255:0];
              RF[5*256 +: 256] <= b_inf ? 256'd0 : 256'd1;
              ibit <= 8'd255; st <= S_SW1;
            end
            OP_SCALAR_BA: begin
              use_n <= 1'b0;
              RF[0*256 +: 256] <= b_inf ? 256'd0 : b_q[511:256];      // R0..R2 = P (projective)
              RF[1*256 +: 256] <= b_inf ? 256'd1 : b_q[255:0];
              RF[2*256 +: 256] <= b_inf ? 256'd0 : 256'd1;
              RF[15*256 +: 256] <= 256'd0;
              rc_start <= 1'b1; st <= S_BA_REC;
            end
            OP_ONCURVE: begin
              use_n <= 1'b0;
              if (a_inf || a_q[511:256] >= P || a_q[255:0] >= P) begin
                out <= 512'd0; done <= 1'b1; st <= S_IDLE;                 // out of range / infinity
              end else begin
                RF[0*256 +: 256] <= a_q[511:256]; RF[1*256 +: 256] <= a_q[255:0];
                mst <= M_ONC; pc <= P_ONC_S; pc_end <= P_ONC_E; st <= S_PROG;
              end
            end
            OP_PADD: begin
              use_n <= 1'b0;
              RF[0*256 +: 256] <= a_inf ? 256'd0 : a_q[511:256];
              RF[1*256 +: 256] <= a_inf ? 256'd1 : a_q[255:0];
              RF[2*256 +: 256] <= a_inf ? 256'd0 : 256'd1;
              RF[3*256 +: 256] <= b_inf ? 256'd0 : b_q[511:256];
              RF[4*256 +: 256] <= b_inf ? 256'd1 : b_q[255:0];
              RF[5*256 +: 256] <= b_inf ? 256'd0 : 256'd1;
              mst <= M_PA_ADD; pc <= P_ADD_S; pc_end <= P_ADD_E; st <= S_PROG;
            end
            OP_MODN: begin
              use_n <= 1'b1; out <= {256'd0, a_red}; done <= 1'b1; st <= S_IDLE;
            end
            OP_MULN: begin
              use_n <= 1'b1;
              RF[0*256 +: 256] <= a_red; RF[1*256 +: 256] <= b_red;
              mst <= M_MULN; pc <= P_MULN_S; pc_end <= P_MULN_E; st <= S_PROG;
            end
            OP_ADDN: begin
              use_n <= 1'b1;
              RF[0*256 +: 256] <= a_red; RF[1*256 +: 256] <= b_red;
              mst <= M_ADDN; pc <= P_ADDN_S; pc_end <= P_ADDN_E; st <= S_PROG;
            end
            OP_INVN: begin
              use_n <= 1'b1;
              RF[0*256 +: 256] <= a_red;
              inv_src <= 4'd0; mst <= M_INVN; st <= S_INVI;
            end
            default: begin out <= 512'd0; done <= 1'b1; st <= S_IDLE; end
          endcase
        end

        // ---------------- microcode runner ----------------
        S_PROG: begin
          if (i_op == 3'd0) begin
            mm_a <= ra; mm_b <= rb; mm_start <= 1'b1; dst_q <= i_d; st <= S_MULW;
          end else begin
            for (jj = 0; jj < 16; jj = jj + 1) if (i_d == jj) RF[jj*256 +: 256] <= alu_res;
            if (prog_last) st <= S_NEXT; else pc <= pc + 7'd1;
          end
        end
        S_MULW: if (mm_done) begin
          for (jj = 0; jj < 16; jj = jj + 1) if (dst_q == jj) RF[jj*256 +: 256] <= mm_res;
          if (prog_last) st <= S_NEXT; else begin pc <= pc + 7'd1; st <= S_PROG; end
        end

        // ---------------- macro sequencing ----------------
        S_NEXT: begin
          case (mst)
            M_SC_ADD:  begin mst <= M_SC_MOVB; pc <= P_MOVB_S; pc_end <= P_MOVB_E; st <= S_PROG; end
            M_SC_MOVB: begin mst <= M_SC_DBL;  pc <= P_DBL_S;  pc_end <= P_DBL_E;  st <= S_PROG; end
            M_SC_DBL:  begin mst <= M_SC_MOVA; pc <= P_MOVA_S; pc_end <= P_MOVA_E; st <= S_PROG; end
            M_SC_MOVA: st <= S_SW2;
            M_PA_ADD:  begin mst <= M_PA_MOVA; pc <= P_MOVA_S; pc_end <= P_MOVA_E; st <= S_PROG; end
            M_PA_MOVA: st <= S_NORM;
            M_N_INV:   begin mst <= M_N_AFF;   pc <= P_AFF_S;  pc_end <= P_AFF_E;  st <= S_PROG; end
            M_N_AFF:   begin out <= {RF[12*256 +: 256], RF[13*256 +: 256]}; done <= 1'b1; st <= S_IDLE; end
            M_MULN,
            M_ADDN:    begin out <= {256'd0, RF[2*256 +: 256]};  done <= 1'b1; st <= S_IDLE; end
            M_INVN:    begin out <= {256'd0, RF[11*256 +: 256]}; done <= 1'b1; st <= S_IDLE; end
            M_ONC:     begin out <= {511'd0, (RF[9*256 +: 256] == RF[11*256 +: 256])}; done <= 1'b1; st <= S_IDLE; end
            // ---- BA-Radix-2^w ----
            M_BA_D2: begin                                    // R6..R8 = 2P
              TBL[NENT*768 +: 768] <= {RF[6*256 +: 256], RF[7*256 +: 256], RF[8*256 +: 256]};
              ii <= 8'd1; st <= S_PRE_LD;
            end
            M_BA_PADD: begin                                  // T[ii] = T[ii-1] + 2P
              for (jj = 0; jj <= NENT; jj = jj + 1) if (ii == jj)
                TBL[jj*768 +: 768] <= {RF[6*256 +: 256], RF[7*256 +: 256], RF[8*256 +: 256]};
              if (ii == NENT-1) st <= S_EV_INIT;
              else begin ii <= ii + 8'd1; st <= S_PRE_LD; end
            end
            M_BA_EADD:  begin mst <= M_BA_EMOVA; pc <= P_MOVA_S; pc_end <= P_MOVA_E; st <= S_PROG; end
            M_BA_EMOVA: st <= S_EV_DBL;
            M_BA_EDBL:  begin mst <= M_BA_EDMOV; pc <= P_MOVA_S; pc_end <= P_MOVA_E; st <= S_PROG; end
            M_BA_EDMOV: begin dcnt <= dcnt - 9'd1; st <= S_EV_DBL; end
            default:   st <= S_IDLE;
          endcase
        end

        // ---------------- Montgomery ladder ----------------
        // swap(R0R1R2 <-> R3R4R5) if key bit = 1, add, double, swap back
        S_SW1: begin
          if (k_bit) begin
            RF[0*256 +: 256] <= RF[3*256 +: 256]; RF[3*256 +: 256] <= RF[0*256 +: 256];
            RF[1*256 +: 256] <= RF[4*256 +: 256]; RF[4*256 +: 256] <= RF[1*256 +: 256];
            RF[2*256 +: 256] <= RF[5*256 +: 256]; RF[5*256 +: 256] <= RF[2*256 +: 256];
          end
          mst <= M_SC_ADD; pc <= P_ADD_S; pc_end <= P_ADD_E; st <= S_PROG;
        end
        S_SW2: begin
          if (k_bit) begin
            RF[0*256 +: 256] <= RF[3*256 +: 256]; RF[3*256 +: 256] <= RF[0*256 +: 256];
            RF[1*256 +: 256] <= RF[4*256 +: 256]; RF[4*256 +: 256] <= RF[1*256 +: 256];
            RF[2*256 +: 256] <= RF[5*256 +: 256]; RF[5*256 +: 256] <= RF[2*256 +: 256];
          end
          if (ibit == 8'd0) st <= S_NORM;
          else begin ibit <= ibit - 8'd1; st <= S_SW1; end
        end

        // ---------------- BA-Radix-2^w evaluation (Algorithm 2) ----------------
        S_BA_REC: if (rc_done) begin
          if (rc_count == 9'd0) begin                        // k = 0
            out <= 512'd0; done <= 1'b1; st <= S_IDLE;
          end else begin
            TBL[0 +: 768] <= {RF[0*256 +: 256], RF[1*256 +: 256], RF[2*256 +: 256]};  // T[0] = P
            mst <= M_BA_D2; pc <= P_DBL_S; pc_end <= P_DBL_E; st <= S_PROG;            // R6..8 = 2P
          end
        end
        S_PRE_LD: begin
          RF[0*256 +: 256] <= tbl_prev[767:512]; RF[1*256 +: 256] <= tbl_prev[511:256]; RF[2*256 +: 256] <= tbl_prev[255:0];  // R0..R2 = T[ii-1]
          RF[3*256 +: 256] <= tbl_2p[767:512];   RF[4*256 +: 256] <= tbl_2p[511:256];   RF[5*256 +: 256] <= tbl_2p[255:0];    // R3..R5 = 2P
          mst <= M_BA_PADD; pc <= P_ADD_S; pc_end <= P_ADD_E; st <= S_PROG;
        end
        S_EV_INIT: begin
          RF[0*256 +: 256] <= 256'd0; RF[1*256 +: 256] <= 256'd1; RF[2*256 +: 256] <= 256'd0;  // R = O
          ei <= rc_count - 9'd1; st <= S_EV_FETCH;
        end
        S_EV_FETCH: begin
          // B = +/- T[idx];   doublings after this slice = pos_i - pos_(i-1)  (pos_0 for the last)
          RF[3*256 +: 256] <= tbl_sel[767:512];
          RF[4*256 +: 256] <= rc_neg_a ? tbl_y_neg : tbl_sel_y;
          RF[5*256 +: 256] <= tbl_sel[255:0];
          dcnt <= (ei == 9'd0) ? rc_pos_a : (rc_pos_a - rc_pos_b);
          mst <= M_BA_EADD; pc <= P_ADD_S; pc_end <= P_ADD_E; st <= S_PROG;
        end
        S_EV_DBL: begin
          if (dcnt != 9'd0) begin
            mst <= M_BA_EDBL; pc <= P_DBL_S; pc_end <= P_DBL_E; st <= S_PROG;
          end else st <= S_EV_STEP;
        end
        S_EV_STEP: begin
          if (ei == 9'd0) st <= S_NORM;
          else begin ei <= ei - 9'd1; st <= S_EV_FETCH; end
        end

        // ---------------- projective -> affine ----------------
        S_NORM: begin
          if (RF[2*256 +: 256] == 256'd0) begin
            out <= 512'd0; done <= 1'b1; st <= S_IDLE;     // point at infinity
          end else begin
            inv_src <= 4'd2; mst <= M_N_INV; st <= S_INVI;
          end
        end

        // ---------------- Fermat inversion: R11 = R[inv_src]^(M-2) ----------------
        S_INVI: begin
          RF[11*256 +: 256] <= 256'd1;
          RF[10*256 +: 256] <= rdf(inv_src, RF);
          iv <= 9'd0; st <= S_INVA;
        end
        S_INVA: begin
          if (E[iv[7:0]]) begin
            mm_a <= RF[11*256 +: 256]; mm_b <= RF[10*256 +: 256]; mm_start <= 1'b1; st <= S_INVAW;
          end else st <= S_INVB;
        end
        S_INVAW: if (mm_done) begin RF[11*256 +: 256] <= mm_res; st <= S_INVB; end
        S_INVB: begin
          mm_a <= RF[10*256 +: 256]; mm_b <= RF[10*256 +: 256]; mm_start <= 1'b1; st <= S_INVBW;
        end
        S_INVBW: if (mm_done) begin
          RF[10*256 +: 256] <= mm_res;
          if (iv == 9'd255) st <= S_NEXT;
          else begin iv <= iv + 9'd1; st <= S_INVA; end
        end

        default: st <= S_IDLE;
      endcase
    end
  end
endmodule
