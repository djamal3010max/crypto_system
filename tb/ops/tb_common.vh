// Shared testbench scaffolding for the 8 operation testbenches.
// Included INSIDE each tb module:   `include "tb_common.vh"
// Provides: clock, reset, DUT, TRNG noise source, CPU command task, check/gap/finish tasks.
`include "vectors.vh"

  reg         clk = 0, rst_n = 0;
  always #5 clk = ~clk;

  reg         cpu_valid = 0;
  reg  [7:0]  cpu_cmd = 0;
  reg  [3:0]  cpu_slot = 0;
  reg  [255:0] cpu_a = 0;
  reg  [511:0] cpu_b = 0;
  reg  [1:0]  cpu_attr = 0;
  wire        cpu_ready, cpu_done, cpu_err, cpu_ok, trng_alarm;
  wire [511:0] cpu_result;
  reg         thermal = 0;
  reg         alarm_clear = 0;
  always @(posedge clk) thermal <= $random;

  sc_crypto_top dut (
      .clk(clk), .rst_n_async(rst_n),
      .cpu_valid(cpu_valid), .cpu_ready(cpu_ready), .cpu_cmd(cpu_cmd), .cpu_slot(cpu_slot),
      .cpu_a(cpu_a), .cpu_b(cpu_b), .cpu_attr(cpu_attr),
      .cpu_done(cpu_done), .cpu_err(cpu_err), .cpu_ok(cpu_ok), .cpu_result(cpu_result),
      .thermal_noise_in(thermal), .trng_alarm_clear(alarm_clear), .trng_alarm(trng_alarm));

  // command opcodes (see rtl/controller_fsm.v)
  localparam [7:0] CMD_RANDOM = 8'h01, CMD_HASH = 8'h02, CMD_AES = 8'h03,
                   CMD_AESD = 8'h04, CMD_CBCE = 8'h05, CMD_CBCD = 8'h06,
                   CMD_HINIT = 8'h07, CMD_HUPD = 8'h08, CMD_HFIN = 8'h09,
                   CMD_SLAST = 8'h13, CMD_VLAST = 8'h14, CMD_KDF = 8'h15, CMD_SLOAD = 8'h16, CMD_CVER = 8'h17, CMD_KGEN = 8'h18,
                   CMD_SIGN = 8'h10, CMD_VERIFY = 8'h11, CMD_ECDH = 8'h12,
                   CMD_KWR = 8'h20, CMD_KRD = 8'h21,
                   CMD_CWR = 8'h30, CMD_CRD = 8'h31, CMD_CCHK = 8'h32;
  localparam [1:0] ATTR_PLAIN = 2'b00, ATTR_LOCK = 2'b01, ATTR_SECRET = 2'b10, ATTR_SECRET_LOCK = 2'b11;

  reg [511:0] r_result;
  reg         r_err, r_ok;
  integer     n_pass = 0, n_fail = 0, n_gap = 0;

  task power_up;
    begin
      #47 rst_n = 1;
      repeat (6) @(posedge clk);          // let the reset synchronizer release
    end
  endtask

  task run_cmd(input [7:0] c, input [3:0] slot, input [255:0] a, input [511:0] b, input [1:0] attr);
    begin
      @(posedge clk); while (!cpu_ready) @(posedge clk);
      cpu_cmd <= c; cpu_slot <= slot; cpu_a <= a; cpu_b <= b; cpu_attr <= attr; cpu_valid <= 1;
      @(posedge clk); cpu_valid <= 0;
      while (!cpu_done) @(posedge clk);
      r_result = cpu_result; r_err = cpu_err; r_ok = cpu_ok;
    end
  endtask

  // stream a 100-byte message (64-byte update + 36-byte final) into a hash session of the given algorithm
  task send_msg100(input [3:0] alg, input [799:0] msg);
    begin
      run_cmd(CMD_HINIT, alg, 256'd0, 512'd0, 0);
      run_cmd(CMD_HUPD, 0, 256'd64, msg[799:288], 0);
      run_cmd(CMD_HFIN, 0, 256'd36, {msg[287:0], 224'd0}, 0);
    end
  endtask

  task check(input cond, input [8*80-1:0] name);
    begin
      if (cond) begin n_pass = n_pass + 1; $display("PASS  %0s", name); end
      else      begin n_fail = n_fail + 1; $display("FAIL  %0s", name); end
      $fflush;
    end
  endtask

  // A spec feature (from Global_Architecture5) that the RTL does not implement yet.
  // Reported, never counted as a pass or a failure.
  task gap(input [8*150-1:0] what);
    begin n_gap = n_gap + 1; $display("GAP   %0s", what); $fflush; end
  endtask

  task finish(input [8*32-1:0] opname);
    begin
      $display("\nRESULT %0s: %0d passed, %0d failed, %0d spec gap(s)", opname, n_pass, n_fail, n_gap);
      $display("%0s", (n_fail == 0) ? "OP TESTBENCH OK" : "OP TESTBENCH FAILED");
      $finish;
    end
  endtask
