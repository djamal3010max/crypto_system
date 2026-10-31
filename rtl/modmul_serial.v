`timescale 1ns/1ps
// Bit-serial interleaved modular multiplier: res = a * b mod m.
// 256 clock cycles per multiplication, one shift-add-reduce step per cycle.
// Requirements: b < m, m > 2^255 (true for the P-256 prime and group order).
// `a` may be any 256-bit value. Fully synthesizable, no '*' or '%'.
module modmul_serial (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,
    input  wire [255:0] a,
    input  wire [255:0] b,
    input  wire [255:0] m,
    output reg          done,
    output reg  [255:0] res
);
  reg [255:0] a_q, b_q, m_q, acc;
  reg [8:0]   cnt;
  reg         busy;

  wire [257:0] m_ext = {2'b00, m_q};
  wire [257:0] t  = {1'b0, acc, 1'b0} + (a_q[255] ? {2'b00, b_q} : 258'd0);   // < 3m
  wire [257:0] t1 = (t  >= m_ext) ? (t  - m_ext) : t;
  wire [257:0] t2 = (t1 >= m_ext) ? (t1 - m_ext) : t1;

  always @(posedge clk) begin
    if (!rst_n) begin
      busy <= 1'b0; done <= 1'b0; cnt <= 9'd0; acc <= 256'd0; res <= 256'd0;
      a_q <= 256'd0; b_q <= 256'd0; m_q <= 256'd0;
    end else begin
      done <= 1'b0;
      if (start && !busy) begin
        a_q <= a; b_q <= b; m_q <= m; acc <= 256'd0; cnt <= 9'd0; busy <= 1'b1;
      end else if (busy) begin
        acc <= t2[255:0];
        a_q <= {a_q[254:0], 1'b0};
        cnt <= cnt + 9'd1;
        if (cnt == 9'd255) begin
          busy <= 1'b0; done <= 1'b1; res <= t2[255:0];
        end
      end
    end
  end
endmodule
