`timescale 1ns/1ps
// BEHAVIORAL reference model of the ECC arithmetic datapath (NIST P-256).
// It uses Verilog '*' and '%' so it is meant for simulation / golden-model use,
// NOT for synthesis. Replace it with your real GF(p) datapath (e.g. the
// BA-Radix-2^w hardware) but keep this interface.
//
// Points are packed {x[255:0], y[255:0]}; the point at infinity is all zeros.
// Scalars live in the low 256 bits of in_a / in_b / out.
module ecc_arith_ref #(parameter LAT = 2) (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,
    input  wire [2:0]   op,
    input  wire [511:0] in_a,
    input  wire [511:0] in_b,
    output reg          done,
    output reg  [511:0] out
);
  localparam OP_PDBL = 3'd0, OP_PADD = 3'd1, OP_MODN = 3'd2,
             OP_MULN = 3'd3, OP_INVN = 3'd4, OP_ADDN = 3'd5;

  localparam [255:0] P = 256'hFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF;
  localparam [255:0] N = 256'hFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;
  localparam [255:0] A = 256'hFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC; // p-3

  function [255:0] mmul(input [255:0] x, input [255:0] y, input [255:0] m);
    reg [511:0] t;
    begin t = x * y; mmul = t % m; end
  endfunction

  function [255:0] madd(input [255:0] x, input [255:0] y, input [255:0] m);
    reg [256:0] t;
    begin
      t = {1'b0, x} + {1'b0, y};
      if (t >= {1'b0, m}) t = t - {1'b0, m};
      madd = t[255:0];
    end
  endfunction

  function [255:0] msub(input [255:0] x, input [255:0] y, input [255:0] m);
    reg [256:0] t;
    begin
      t = {1'b0, x} + {1'b0, m} - {1'b0, y};
      if (t >= {1'b0, m}) t = t - {1'b0, m};
      msub = t[255:0];
    end
  endfunction

  // modular inverse by Fermat (m prime): x^(m-2)
  function [255:0] minv(input [255:0] x, input [255:0] m);
    reg [255:0] e, base, res;
    integer i;
    begin
      e = m - 256'd2; base = x; res = 256'd1;
      for (i = 0; i < 256; i = i + 1) begin
        if (e[i]) res = mmul(res, base, m);
        base = mmul(base, base, m);
      end
      minv = res;
    end
  endfunction

  function [511:0] pdbl(input [511:0] p1);
    reg [255:0] x, y, x2, num, den, lam, x3, y3;
    begin
      x = p1[511:256]; y = p1[255:0];
      if (p1 == 512'd0 || y == 256'd0) pdbl = 512'd0;
      else begin
        x2  = mmul(x, x, P);
        num = madd(madd(x2, x2, P), x2, P);
        num = madd(num, A, P);
        den = madd(y, y, P);
        lam = mmul(num, minv(den, P), P);
        x3  = msub(msub(mmul(lam, lam, P), x, P), x, P);
        y3  = msub(mmul(lam, msub(x, x3, P), P), y, P);
        pdbl = {x3, y3};
      end
    end
  endfunction

  function [511:0] padd(input [511:0] p1, input [511:0] p2);
    reg [255:0] x1, y1, x2, y2, lam, x3, y3;
    begin
      x1 = p1[511:256]; y1 = p1[255:0]; x2 = p2[511:256]; y2 = p2[255:0];
      if (p1 == 512'd0) padd = p2;
      else if (p2 == 512'd0) padd = p1;
      else if (x1 == x2) begin
        if (y1 == y2) padd = pdbl(p1);
        else          padd = 512'd0;
      end else begin
        lam = mmul(msub(y2, y1, P), minv(msub(x2, x1, P), P), P);
        x3  = msub(msub(mmul(lam, lam, P), x1, P), x2, P);
        y3  = msub(mmul(lam, msub(x1, x3, P), P), y1, P);
        padd = {x3, y3};
      end
    end
  endfunction

  reg [2:0]   op_q;
  reg [511:0] a_q, b_q;
  reg [7:0]   cnt;
  reg         busy;
  reg [255:0] sa, sb;

  always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      done <= 1'b0; out <= 512'd0; busy <= 1'b0; cnt <= 8'd0;
      op_q <= 3'd0; a_q <= 512'd0; b_q <= 512'd0;
    end else begin
      done <= 1'b0;
      if (start && !busy) begin
        op_q <= op; a_q <= in_a; b_q <= in_b; cnt <= LAT[7:0]; busy <= 1'b1;
      end else if (busy) begin
        if (cnt > 8'd1) cnt <= cnt - 8'd1;
        else begin
          sa = a_q[255:0] % N;
          sb = b_q[255:0] % N;
          case (op_q)
            OP_PDBL: out <= pdbl(a_q);
            OP_PADD: out <= padd(a_q, b_q);
            OP_MODN: out <= {256'd0, a_q % {256'd0, N}};
            OP_MULN: out <= {256'd0, mmul(sa, sb, N)};
            OP_INVN: out <= {256'd0, minv(sa, N)};
            OP_ADDN: out <= {256'd0, madd(sa, sb, N)};
            default: out <= 512'd0;
          endcase
          busy <= 1'b0; done <= 1'b1;
        end
      end
    end
  end
endmodule
