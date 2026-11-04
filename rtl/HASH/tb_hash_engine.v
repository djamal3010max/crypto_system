`timescale 1ns/1ps
// Testbench: hash "algeria" with SHA-256, SHA-512 and SHA3-256 (one per core: sha256_core,
// sha512_core, sha3_256_core) and compare the computed digest with the expected one.
// Write the message as a plain value; the engine does all the padding.
module tb_hash_engine;
  reg          clk, rst_n, init_cmd, go, is_final;
  reg  [1:0]   alg;
  reg  [511:0] msg;
  reg  [6:0]   clen;
  wire         done, err, busy;
  wire [511:0] digest;

  // ---- message: only the bytes of the word, no padding ----
  localparam [511:0] MSG  = 512'h616c6765726961;   // "algeria"
  localparam [6:0]   MLEN = 7'd7;                  // number of bytes

  // ---- expected digests (left-aligned in 512 bits) ----
  localparam [255:0] EXP_SHA256   = 256'hd854169a7fa8233ea9a1db6b5c249fa4919523e0adefb8cb72389d29db83b32a;
  localparam [511:0] EXP_SHA512   = 512'h0c8cf817353e62e4e1aacf2b2f07b66901f0e43af65827cce4ba00e4edb8aab22c635a87c55bebe79c77290f813b5bac31790888d862ba6dadc966117a047e6a;
  localparam [255:0] EXP_SHA3_256 = 256'hf801565a9bf95564f1faee3c67fe9af5496d48d70f65b524294c7fe4f9d42b0c;

  hash_engine dut (.clk(clk), .rst_n(rst_n), .init_cmd(init_cmd), .alg(alg), .go(go), .is_final(is_final),
                   .msg(msg), .clen(clen), .done(done), .err(err), .digest(digest), .busy(busy));

  initial clk = 1'b0;
  always #5 clk = ~clk;

  integer fails;
  reg     first_test = 1'b1;
  integer wd;

  task wait_done;
    begin
      wd = 0;
      @(posedge clk); #1;
      while (!done && wd < 2000) begin @(posedge clk); #1; wd = wd + 1; end
      if (!done) begin $display("FAIL: timeout waiting for done"); fails = fails + 1; end
    end
  endtask

  // Hash MSG with algorithm a; compare the top `bits` bits of the digest with exp.
  task test(input [1:0] a, input [8*8-1:0] name, input integer bits, input [511:0] exp);
    reg [511:0] got;
    begin
      if (!first_test) @(negedge clk);                    // first test starts immediately
      first_test = 1'b0;
      alg = a; init_cmd = 1'b1;                           // select algorithm
      wait_done;
      @(negedge clk); init_cmd = 1'b0;                    // send message, final block
      msg = MSG << ({3'b000, (7'd64 - MLEN)} * 8);        // left-align for the engine
      clen = MLEN; is_final = 1'b1; go = 1'b1;
      wait_done;
      @(negedge clk); go = 1'b0;

      got = digest;
      $display("---- %0s ----", name);
      $display("Message : algeria");
      if (bits == 256) begin
        $display("Computed: %064x", got[511:256]);
        $display("Expected: %064x", exp[511:256]);
      end else begin
        $display("Computed: %0128x", got);
        $display("Expected: %0128x", exp);
      end
      if (err === 1'b0 && (got >> (512 - bits)) === (exp >> (512 - bits)))
        $display("PASS");
      else begin
        $display("FAIL");
        fails = fails + 1;
      end
    end
  endtask

  initial begin
    $dumpfile("tb_hash_engine.vcd");
    $dumpvars(0, tb_hash_engine);
    fails = 0;
    rst_n = 1'b0; init_cmd = 1'b0; go = 1'b0; is_final = 1'b0; alg = 2'd0; msg = 512'd0; clen = 7'd0;
    #1 rst_n = 1'b1;                                      // short async reset, then start at ~1 ns

    test(2'd1, "SHA-256",   256, {EXP_SHA256,   256'd0});
    test(2'd2, "SHA-512",   512, EXP_SHA512);
    test(2'd3, "SHA3-256",  256, {EXP_SHA3_256, 256'd0});

    repeat (360) @(posedge clk);                           // hold the final values in the waveform
    $display("========================================");
    if (fails == 0) $display("ALL TESTS PASSED");
    else            $display("%0d TEST(S) FAILED", fails);
    $finish;
  end
endmodule
