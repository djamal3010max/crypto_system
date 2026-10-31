`timescale 1ns/1ps
// Focused self-checking test of ecc_core against Python reference vectors.
`ifndef BAW
`define BAW 4
`endif
module tb_ecc_core;
  reg clk = 0, rst_n = 0;
  always #5 clk = ~clk;
  reg start = 0; reg [2:0] op = 0; reg [511:0] a = 0, b = 0;
  wire done; wire [511:0] out; wire busy;
  ecc_core #(.BA_W(`BAW)) dut (.clk(clk), .rst_n(rst_n), .start(start), .op(op), .in_a(a), .in_b(b),
                .done(done), .out(out), .busy(busy));

  localparam [255:0] GX = 256'h6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296;
  localparam [255:0] GY = 256'h4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5;
  localparam [255:0] K   = 256'hdeadbeefcafebabe0123456789abcdeffedcba9876543210a5a5a5a5c3c3c3c3;
  localparam [255:0] QX  = 256'h02fb75685e8d5da008253727f017701e340142bcb0697ec4e2eee8a9df78753a;
  localparam [255:0] QY  = 256'hf3fe8b23a1ccf12239944734df7e3efc39b4ca420d061095601a93330de9e146;
  localparam [255:0] G2X = 256'h7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978;
  localparam [255:0] G2Y = 256'h07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1;
  localparam [255:0] S3X = 256'h5ecbe4d1a6330a44c8f7ef951d4bf165e6c6b721efada985fb41661bc6e7fd6c;
  localparam [255:0] S3Y = 256'h8734640c4998ff7e374b06ce1a64a2ecd82ab036384fb83d9a79b127a27d5032;
  localparam [255:0] VA  = 256'h1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef;
  localparam [255:0] VB  = 256'hfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321;
  localparam [255:0] MULN = 256'h544b326fbeea4277596e4d77c0b32a161afcf4d420603366e90af5b3a4277657;
  localparam [255:0] INVN = 256'hddbe67fb14714ab5c0d909913a16bb6a2af63adfab8d3a5be98658011a910777;
  localparam [255:0] ADDN = 256'h11111083181111101111108218111111542a15d470f9728c1d5745bf1badebbf;
  localparam [255:0] MODN = 256'h000000000000000000000000000000004319055358e8617b0c46353d039cdaad;
  localparam [255:0] PRIME = 256'hFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF;
  localparam [255:0] PM1  = 256'hFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFE;

  integer errors = 0;
  reg [511:0] res;
  integer t0;

  task run(input [2:0] o, input [511:0] x, input [511:0] y);
    begin
      @(posedge clk); op <= o; a <= x; b <= y; start <= 1;
      @(posedge clk); start <= 0;
      while (!done) @(posedge clk);
      res = out;
    end
  endtask
  task check(input c, input [8*60-1:0] name);
    begin
      if (c) $display("PASS  %0s", name);
      else begin $display("FAIL  %0s", name); errors = errors + 1; end
      $fflush;
    end
  endtask

  initial begin
    #47 rst_n = 1;
    run(3'd2, {256'd0, PM1}, 0);                check(res[255:0] == MODN, "MODN (p-1) mod n");
    run(3'd5, {256'd0, VA}, {256'd0, VB});      check(res[255:0] == ADDN, "ADDN");
    run(3'd3, {256'd0, VA}, {256'd0, VB});      check(res[255:0] == MULN, "MULN");
    run(3'd4, {256'd0, VA}, 0);                 check(res[255:0] == INVN, "INVN (Fermat)");
    run(3'd1, {GX, GY}, {GX, GY});              check(res == {G2X, G2Y}, "PADD G+G (doubling case)");
    run(3'd1, {GX, GY}, {G2X, G2Y});            check(res == {S3X, S3Y}, "PADD G+2G");
    run(3'd1, {GX, GY}, 512'd0);                check(res == {GX, GY}, "PADD G+O");
    run(3'd0, {256'd0, 256'd0}, {GX, GY});      check(res == 512'd0, "SCALAR 0*G = O");
    run(3'd0, {256'd0, 256'd2}, {GX, GY});      check(res == {G2X, G2Y}, "SCALAR 2*G");
    $display("running full 256-bit scalar multiplication ...");
    t0 = $time;
    run(3'd0, {256'd0, K}, {GX, GY});
    check(res == {QX, QY}, "SCALAR k*G (256-bit k)");
    $display("scalar mult took %0d cycles", ($time - t0) / 10);
    // ---- ONCURVE (op 7) ----
    run(3'd7, {GX, GY}, 0);                     check(res == 512'd1, "ONCURVE accepts G");
    run(3'd7, {G2X, G2Y}, 0);                   check(res == 512'd1, "ONCURVE accepts 2G");
    run(3'd7, {QX, QY}, 0);                     check(res == 512'd1, "ONCURVE accepts k*G");
    run(3'd7, {GX, GY ^ 256'd1}, 0);            check(res == 512'd0, "ONCURVE rejects a point with a changed y");
    run(3'd7, {GX ^ 256'd1, GY}, 0);            check(res == 512'd0, "ONCURVE rejects a point with a changed x");
    run(3'd7, 512'd0, 0);                       check(res == 512'd0, "ONCURVE rejects (0,0) / infinity");
    run(3'd7, {PRIME, GY}, 0);                  check(res == 512'd0, "ONCURVE rejects x = p (non-canonical)");
    run(3'd7, {{256{1'b1}}, GY}, 0);              check(res == 512'd0, "ONCURVE rejects x = 2^256-1 (non-canonical)");
    // ---- BA-Radix-2^w (op 6), window BA_W = `BAW ----
    $display("BA-Radix-2^w tests, BA_W = %0d", `BAW);
    run(3'd6, {256'd0, 256'd0}, {GX, GY});      check(res == 512'd0, "BA 0*G = O");
    run(3'd6, {256'd0, 256'd1}, {GX, GY});      check(res == {GX, GY}, "BA 1*G");
    run(3'd6, {256'd0, 256'd2}, {GX, GY});      check(res == {G2X, G2Y}, "BA 2*G");
    run(3'd6, {256'd0, 256'd3}, {GX, GY});      check(res == {S3X, S3Y}, "BA 3*G");
    t0 = $time;
    run(3'd6, {256'd0, K}, {GX, GY});
    check(res == {QX, QY}, "BA k*G (256-bit k)");
    $display("BA scalar mult took %0d cycles (ladder: 1906190)", ($time - t0) / 10);
    run(3'd6, {256'd0, K}, {QX, QY});           // second run, different base point (k*Q)
    check(res != 512'd0 && res != {QX, QY}, "BA k*Q runs");
    $display("\n%0s (%0d error(s))", errors == 0 ? "ECC CORE TESTS PASSED" : "ECC CORE TESTS FAILED", errors);
    $finish;
  end
  initial begin #4_000_000_000; $display("TIMEOUT"); $finish; end
endmodule
