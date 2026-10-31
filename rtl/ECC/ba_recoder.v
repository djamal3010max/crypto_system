`timescale 1ns/1ps
// BA-Radix-2^w recoder: hardware version of Algorithm 1 (Boundary-Aligned Radix-2^w).
//
//   n <- k; pos <- 0
//   while n > 0:
//     skip trailing zeros (pos advances, no slice)          -- Phase A
//     chunk <- n mod 2^w, re-centred into (-2^(w-1), 2^(w-1)]   -- Phase B
//     record (pos, sign, |chunk|);  n <- (n - chunk) >> w;  pos += w
//
// Serial implementation: one bit of zero-skipping or one whole slice per clock,
// so a 256-bit scalar needs at most ~256 + (#slices) cycles. The trailing-zero
// skip is done one bit per cycle instead of with a 256-bit barrel shifter to keep
// the area small (recoding time is negligible next to the point arithmetic).
//
// Slices are produced least-significant first and stored; the evaluator reads
// them back from the top. Every recorded magnitude is odd and in 1 .. 2^(w-1)-1,
// so it is stored as the table index (mag-1)/2 (w-2 bits).
// Requires W >= 3.
module ba_recoder #(parameter W = 4) (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,
    input  wire [255:0] k,
    output reg          busy,
    output reg          done,           // 1-cycle pulse, slices valid
    output reg  [8:0]   count,          // number of slices
    // two combinational read ports
    input  wire [8:0]   ra,
    output wire [8:0]   pos_a,
    output wire         neg_a,
    output wire [W-3:0] idx_a,
    input  wire [8:0]   rb,
    output wire [8:0]   pos_b
);
  localparam MAXS = 256 / W + 3;

  reg [MAXS*9-1:0]     posv;
  reg [MAXS-1:0]       negv;
  reg [MAXS*(W-2)-1:0] idxv;

  reg [257:0] n;
  reg [8:0]   pos, cnt;

  wire          neg = n[W-1];                                  // raw chunk > 2^(w-1)  (raw is odd)
  wire [W-1:0]  mag = neg ? (~n[W-1:0] + {{(W-1){1'b0}}, 1'b1}) : n[W-1:0];

  // explicit muxes (constant part-selects after unrolling) instead of variable part-selects
  function [8:0] rdpos(input [8:0] i, input [MAXS*9-1:0] v);
    integer j;
    begin rdpos = 9'd0; for (j = 0; j < MAXS; j = j + 1) if (i == j) rdpos = v[j*9 +: 9]; end
  endfunction
  function rdneg(input [8:0] i, input [MAXS-1:0] v);
    integer j;
    begin rdneg = 1'b0; for (j = 0; j < MAXS; j = j + 1) if (i == j) rdneg = v[j]; end
  endfunction
  function [W-3:0] rdidx(input [8:0] i, input [MAXS*(W-2)-1:0] v);
    integer j;
    begin rdidx = {(W-2){1'b0}}; for (j = 0; j < MAXS; j = j + 1) if (i == j) rdidx = v[j*(W-2) +: (W-2)]; end
  endfunction
  assign pos_a = rdpos(ra, posv);
  assign neg_a = rdneg(ra, negv);
  assign idx_a = rdidx(ra, idxv);
  assign pos_b = rdpos(rb, posv);
  integer wj;

  always @(posedge clk) begin
    if (!rst_n) begin
      busy <= 1'b0; done <= 1'b0; count <= 9'd0; n <= 258'd0; pos <= 9'd0; cnt <= 9'd0;
      posv <= {(MAXS*9){1'b0}}; negv <= {MAXS{1'b0}}; idxv <= {(MAXS*(W-2)){1'b0}};
    end else begin
      done <= 1'b0;
      if (start && !busy) begin
        n <= {2'b00, k}; pos <= 9'd0; cnt <= 9'd0; busy <= 1'b1;
      end else if (busy) begin
        if (n == 258'd0) begin
          busy <= 1'b0; done <= 1'b1; count <= cnt;
        end else if (!n[0]) begin                              // Phase A: skip a zero
          n <= n >> 1; pos <= pos + 9'd1;
        end else begin                                         // Phase B: record a slice
          for (wj = 0; wj < MAXS; wj = wj + 1) if (cnt == wj) begin
            posv[wj*9 +: 9]         <= pos;
            negv[wj]                <= neg;
            idxv[wj*(W-2) +: (W-2)] <= mag[W-2:1];
          end
          n   <= (n >> W) + {257'd0, neg};                     // (n - chunk) >> w
          pos <= pos + W;
          cnt <= cnt + 9'd1;
        end
      end
    end
  end
endmodule
