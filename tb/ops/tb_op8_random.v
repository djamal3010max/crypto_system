`timescale 1ns/1ps
// Operation 8: Raw Random Bytes   -- command 01 (TRNG output buffer straight to the CPU)
//   TRNG chain: ring oscillators + thermal noise -> sampler -> health monitor (Repetition Count Test +
//   Adaptive Proportion Test) -> von Neumann corrector -> SHA-256 conditioner -> output buffer
module tb_op8_random;
  `include "tb_common.vh"
  localparam NWORDS = 24;
  integer i, j, dup, zero, ones;
  reg [255:0] w [0:NWORDS-1];

  // standalone von Neumann corrector, driven with a biased bit stream
  reg vn_valid_i = 0, vn_bit_i = 0; wire vn_valid_o, vn_bit_o; reg vn_flush = 0;
  von_neumann u_vn_tb (.clk(clk), .rst_n(rst_n), .flush(vn_flush), .in_valid(vn_valid_i), .in_bit(vn_bit_i),
                       .out_valid(vn_valid_o), .out_bit(vn_bit_o));
  integer vn_in, vn_out, vn_out_ones, vn_in_ones;
  reg [7:0] vn_seq [0:7]; integer vn_k;

  // slightly biased, never-stuck pattern for the Adaptive Proportion Test: nine ones then a zero
  reg [3:0] pc = 0;
  always @(posedge clk) if (dut.u_trng.raw_valid) pc <= (pc == 9) ? 4'd0 : pc + 4'd1;
  wire pbit = (pc != 9);

  function integer popcount(input [255:0] x);
    integer b;
    begin popcount = 0; for (b = 0; b < 256; b = b + 1) popcount = popcount + x[b]; end
  endfunction

  initial begin
    power_up;
    dup = 0; zero = 0; ones = 0;
    for (i = 0; i < NWORDS; i = i + 1) begin
      run_cmd(CMD_RANDOM, 0, 0, 0, 0);
      w[i] = r_result[255:0];
      if (r_err || !r_ok) zero = zero + 1;
      if (w[i] == 0)      zero = zero + 1;
      ones = ones + popcount(w[i]);
      for (j = 0; j < i; j = j + 1) if (w[i] == w[j]) dup = dup + 1;
    end
    check(zero == 0, "24 requests all succeeded and none returned zero");
    check(dup == 0, "all 24 words distinct");
    $display("      ones = %0d of %0d bits", ones, NWORDS * 256);
    check(ones > NWORDS*256*47/100 && ones < NWORDS*256*53/100, "monobit sanity: 47%..53% ones");
    check(r_result[511:256] == 256'd0, "upper result bits are zero for a 256-bit random word");
    check(!trng_alarm, "health monitor reports no failure on a healthy source");

    // ---- von Neumann corrector on its own: known pairs, then a 70%-ones stream ----
    vn_k = 0;
    @(posedge clk); vn_valid_i <= 1;
    // pairs 00 01 10 11 01  -> expected outputs 0, 1, 0
    begin : vn_known
      reg [9:0] stream; integer q;
      stream = 10'b00_01_10_11_01;
      for (q = 9; q >= 0; q = q - 1) begin vn_bit_i <= stream[q]; @(posedge clk); end
    end
    vn_valid_i <= 0; repeat (3) @(posedge clk);
    vn_in = 0; vn_out = 0; vn_out_ones = 0; vn_in_ones = 0;
    repeat (20000) begin
      @(posedge clk); vn_valid_i <= 1; vn_bit_i <= (({$random} % 10) < 7);
      vn_in = vn_in + 1; vn_in_ones = vn_in_ones + (vn_bit_i ? 1 : 0);
      if (vn_valid_o) begin vn_out = vn_out + 1; vn_out_ones = vn_out_ones + (vn_bit_o ? 1 : 0); end
    end
    @(posedge clk); vn_valid_i <= 0;
    $display("      von Neumann: in %0d (%0d%% ones), out %0d (%0d%% ones)", vn_in, vn_in_ones*100/vn_in, vn_out, vn_out_ones*100/vn_out);
    check(vn_in_ones*100/vn_in > 65 && vn_in_ones*100/vn_in < 75, "test stream is biased (about 70% ones)");
    check(vn_out_ones*100/vn_out > 46 && vn_out_ones*100/vn_out < 54, "von Neumann output is unbiased (46%..54% ones)");
    check(vn_out * 4 <= vn_in, "von Neumann output rate is at most one bit per four input bits");

    // ---- Adaptive Proportion Test: biased source that is never stuck ----
    force dut.u_trng.u_health.bit_in = pbit;
    repeat (60000) @(posedge clk);
    check(trng_alarm && dut.u_trng.u_health.apt_fail, "biased (90% ones) source raises the Adaptive Proportion Test alarm");
    check(!dut.u_trng.u_health.rct_fail, "the same source does not trip the Repetition Count Test");
    run_cmd(CMD_RANDOM, 0, 0, 0, 0);
    check(r_err && !r_ok && r_result == 512'd0, "no random data is released after an Adaptive Proportion Test failure");
    release dut.u_trng.u_health.bit_in;
    repeat (200) @(posedge clk);
    @(posedge clk); alarm_clear <= 1; @(posedge clk); alarm_clear <= 0;
    repeat (4) @(posedge clk);
    check(!trng_alarm, "alarm cleared after the Adaptive Proportion Test failure");
    run_cmd(CMD_RANDOM, 0, 0, 0, 0);
    check(!r_err && r_ok && r_result[255:0] != 0, "random output resumes after the APT alarm is cleared");

    // health monitor: a stuck source must block the output (Repetition Count Test)
    force dut.u_trng.u_samp.raw_bit = 1'b1;
    repeat (3000) @(posedge clk);
    check(trng_alarm, "stuck-at-1 source raises the health alarm");
    run_cmd(CMD_RANDOM, 0, 0, 0, 0);
    check(r_err && !r_ok && r_result == 512'd0, "no random data is released while the alarm is raised");
    release dut.u_trng.u_samp.raw_bit;
    repeat (200) @(posedge clk);
    check(trng_alarm, "alarm is sticky after the source recovers");
    run_cmd(CMD_RANDOM, 0, 0, 0, 0);
    check(r_err, "still blocked until the alarm is cleared");

    @(posedge clk); alarm_clear <= 1; @(posedge clk); alarm_clear <= 0;
    repeat (4) @(posedge clk);
    check(!trng_alarm, "alarm cleared by the clear input");
    run_cmd(CMD_RANDOM, 0, 0, 0, 0);
    check(!r_err && r_ok && r_result[255:0] != 0, "random output resumes after clear and restart-up test");

    gap("health-test cutoffs assume H = 0.5 bit/sample; the real entropy of the analog source has not been measured");
    finish("op8 Random");
  end
  initial begin #1_000_000_000; $display("TIMEOUT"); $finish; end
endmodule
