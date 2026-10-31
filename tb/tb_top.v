`timescale 1ns/1ps
// Self-checking testbench. Run: ./run_sim.sh
module tb_top;
  reg clk = 0, rst_n = 0;
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
  always @(posedge clk) thermal <= $random;

  sc_crypto_top dut (
      .clk(clk), .rst_n_async(rst_n),
      .cpu_valid(cpu_valid), .cpu_ready(cpu_ready), .cpu_cmd(cpu_cmd), .cpu_slot(cpu_slot),
      .cpu_a(cpu_a), .cpu_b(cpu_b), .cpu_attr(cpu_attr),
      .cpu_done(cpu_done), .cpu_err(cpu_err), .cpu_ok(cpu_ok), .cpu_result(cpu_result),
      .thermal_noise_in(thermal), .trng_alarm_clear(1'b0), .trng_alarm(trng_alarm));

  localparam [7:0] CMD_RANDOM = 8'h01, CMD_HASH = 8'h02, CMD_AES = 8'h03,
                   CMD_SIGN = 8'h10, CMD_VERIFY = 8'h11, CMD_ECDH = 8'h12,
                   CMD_KWR = 8'h20, CMD_KRD = 8'h21, CMD_CWR = 8'h30, CMD_CRD = 8'h31, CMD_CCHK = 8'h32;

  reg [511:0] r_result; reg r_err, r_ok;
  integer errors = 0;

  task run_cmd(input [7:0] c, input [3:0] slot, input [255:0] a, input [511:0] b, input [1:0] attr);
    begin
      @(posedge clk); while (!cpu_ready) @(posedge clk);
      cpu_cmd <= c; cpu_slot <= slot; cpu_a <= a; cpu_b <= b; cpu_attr <= attr; cpu_valid <= 1;
      @(posedge clk); cpu_valid <= 0;
      while (!cpu_done) @(posedge clk);
      r_result = cpu_result; r_err = cpu_err; r_ok = cpu_ok;
    end
  endtask

  task check(input [255:0] cond, input [8*40-1:0] name);
    begin
      if (cond) $display("PASS  %0s", name);
      else begin $display("FAIL  %0s", name); errors = errors + 1; end
    end
  endtask

  localparam [255:0] DA  = 256'h1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef;
  localparam [255:0] QBX = 256'hce01e429f9890a603e42e65059dbe7d2db39b000015b1d6630d045fadddefcbf;
  localparam [255:0] QBY = 256'hd153ffe95ef9da3a15976ff8c08d18e7dfe691689c5f2d89e264013fa35dd962;
  localparam [255:0] QAX = 256'h471c3e758c4904285bba7e53118ed0f524adeb0757d25bd2f8e7b0d76dfa714c;
  localparam [255:0] QAY = 256'hdd520f7aca8a8b917acc37f51de8f0c9bbe3ad858382e702dc25a12d09f7a858;
  localparam [255:0] SHARED = 256'h4db6d19eaf9c142dce10143033ff999737853d035fa56ce722792050291f7cfe;
  localparam [255:0] MSG  = 256'h000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f;
  localparam [255:0] MSGH = 256'h630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd;

  reg [255:0] rnd1, rnd2;
  reg [511:0] rs;

  initial begin
    #47 rst_n = 1;
    repeat (6) @(posedge clk);   // let the reset synchronizer release

    // 1. TRNG
    run_cmd(CMD_RANDOM, 0, 0, 0, 0); rnd1 = r_result[255:0];
    run_cmd(CMD_RANDOM, 0, 0, 0, 0); rnd2 = r_result[255:0];
    check(!r_err && rnd1 != 0 && rnd2 != 0 && rnd1 != rnd2, "TRNG two distinct words");

    // 2. HASH
    run_cmd(CMD_HASH, 0, MSG, 0, 0);
    check(r_result[255:0] == MSGH, "HASH sha256(00..1f)");

    // 3. Key store + AES (FIPS-197 vector), secret key
    run_cmd(CMD_KWR, 0, 256'h000102030405060708090a0b0c0d0e0f, 0, 2'b10);
    check(!r_err, "KEY_WRITE slot0 secret");
    run_cmd(CMD_AES, 0, 256'h00112233445566778899aabbccddeeff, 0, 0);
    check(r_result[127:0] == 128'h69c4e0d86a7b0430d8cdb78070b4c55a, "AES-128 FIPS-197");
    run_cmd(CMD_KRD, 0, 0, 0, 0);
    check(r_err, "KEY_READ of secret slot denied");
    run_cmd(CMD_KWR, 0, 256'h1, 0, 2'b00);
    run_cmd(CMD_KRD, 6, 0, 0, 0);
    check(r_err, "KEY_READ of empty slot denied");

    // 4. Certificates
    run_cmd(CMD_CWR, 1, MSGH, 0, 0);
    run_cmd(CMD_CCHK, 1, MSGH, 0, 0);
    check(!r_err && r_ok, "CERT_CHECK match");
    run_cmd(CMD_CCHK, 1, MSG, 0, 0);
    check(!r_err && !r_ok, "CERT_CHECK mismatch");

    // 5. ECDH: dA * QB
    run_cmd(CMD_KWR, 2, DA, 0, 2'b10);
    run_cmd(CMD_ECDH, 2, 0, {QBX, QBY}, 0);
    check(!r_err && r_ok && r_result[255:0] == SHARED, "ECDH matches python model");

    // 6. ECDSA sign + verify (public key in slots 4/5)
    run_cmd(CMD_KWR, 3, DA,  0, 2'b10);
    run_cmd(CMD_KWR, 4, QAX, 0, 2'b00);
    run_cmd(CMD_KWR, 5, QAY, 0, 2'b00);
    run_cmd(CMD_SIGN, 3, MSGH, 0, 0);
    rs = r_result;
    check(!r_err && r_ok && rs != 0, "ECDSA sign");
    run_cmd(CMD_VERIFY, 4, MSGH, rs, 0);
    check(!r_err && r_ok, "ECDSA verify good signature");
    run_cmd(CMD_VERIFY, 4, MSG, rs, 0);
    check(!r_err && !r_ok, "ECDSA verify rejects wrong hash");

    // 7. bad command
    run_cmd(8'hEE, 0, 0, 0, 0);
    check(r_err, "unknown command -> error");

    $display("\n%0s (%0d error(s))", errors == 0 ? "ALL TESTS PASSED" : "TESTS FAILED", errors);
    $finish;
  end

  initial begin #4_000_000_000; $display("TIMEOUT"); $finish; end
endmodule
