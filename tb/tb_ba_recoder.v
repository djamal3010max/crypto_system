`timescale 1ns/1ps
// Checks ba_recoder against the two worked examples in the BA-Radix-2^w paper (w = 4).
module tb_ba_recoder;
  reg clk = 0, rst_n = 0; always #5 clk = ~clk;
  reg start = 0; reg [255:0] k = 0;
  wire busy, done; wire [8:0] count;
  reg [8:0] ra = 0, rb = 0;
  wire [8:0] pos_a, pos_b; wire neg_a; wire [1:0] idx_a;
  ba_recoder #(.W(4)) dut (.clk(clk), .rst_n(rst_n), .start(start), .k(k), .busy(busy), .done(done),
      .count(count), .ra(ra), .pos_a(pos_a), .neg_a(neg_a), .idx_a(idx_a), .rb(rb), .pos_b(pos_b));
  integer errors = 0;

  task recode(input [255:0] kk);
    begin
      @(posedge clk); k <= kk; start <= 1; @(posedge clk); start <= 0;
      while (!done) @(posedge clk);
    end
  endtask
  // expected slice: position, sign, magnitude (table index = (mag-1)/2)
  task expect_slice(input [8:0] i, input [8:0] p, input s, input [3:0] m);
    begin
      ra = i; #1;
      if (pos_a !== p || neg_a !== s || idx_a !== (m - 1) / 2) begin
        $display("FAIL  slice %0d: got pos=%0d sign=%b mag=%0d, expected pos=%0d sign=%b mag=%0d",
                 i, pos_a, neg_a, idx_a * 2 + 1, p, s, m);
        errors = errors + 1;
      end else $display("PASS  slice %0d = (pos %0d, sign %b, mag %0d)", i, p, s, m);
    end
  endtask

  initial begin
    #47 rst_n = 1; repeat (3) @(posedge clk);
    $display("k = 4196366  (paper Fig. 2: 3 slices)");
    recode(256'd4196366);
    if (count !== 9'd3) begin $display("FAIL  count=%0d expected 3", count); errors = errors + 1; end
    expect_slice(0, 1, 0, 7); expect_slice(1, 11, 0, 1); expect_slice(2, 22, 0, 1);
    $display("k = 4196378  (paper Fig. 4: 4 slices, carry propagation)");
    recode(256'd4196378);
    if (count !== 9'd4) begin $display("FAIL  count=%0d expected 4", count); errors = errors + 1; end
    expect_slice(0, 1, 1, 3); expect_slice(1, 5, 0, 1); expect_slice(2, 11, 0, 1); expect_slice(3, 22, 0, 1);
    $display("k = 0");
    recode(256'd0);
    if (count !== 9'd0) begin $display("FAIL  k=0 count=%0d", count); errors = errors + 1; end
    $display("\n%0s (%0d error(s))", errors == 0 ? "BA RECODER TESTS PASSED" : "BA RECODER TESTS FAILED", errors);
    $finish;
  end
  initial begin #1_000_000; $display("TIMEOUT"); $finish; end
endmodule
