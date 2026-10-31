`timescale 1ns/1ps
// Operation 1: AES Encrypt/Decrypt (ECB, CBC)
//   commands 03 ECB encrypt, 04 ECB decrypt, 05 CBC encrypt, 06 CBC decrypt (one 128-bit block each;
//   for CBC the chaining value - IV or previous ciphertext block - is passed in cpu_b[127:0])
module tb_op1_aes;
  `include "tb_common.vh"
  integer i;
  reg [127:0] prev, x;
  reg [127:0] pt [0:3]; reg [127:0] ecb_ct [0:3]; reg [127:0] cbc_ct [0:3];

  initial begin
    pt[0] = AES_P2_0; pt[1] = AES_P2_1; pt[2] = AES_P2_2; pt[3] = AES_P2_3;
    ecb_ct[0] = AES_E2_0; ecb_ct[1] = AES_E2_1; ecb_ct[2] = AES_E2_2; ecb_ct[3] = AES_E2_3;
    cbc_ct[0] = AES_CB_0; cbc_ct[1] = AES_CB_1; cbc_ct[2] = AES_CB_2; cbc_ct[3] = AES_CB_3;
    power_up;

    // keys live in the key store; AES keys are secret slots (not readable over the bus)
    run_cmd(CMD_KWR, 0, {128'd0, AES_K1}, 0, ATTR_SECRET);   check(!r_err, "load FIPS-197 key into secret slot 0");
    run_cmd(CMD_KWR, 1, {128'd0, AES_K2}, 0, ATTR_SECRET);   check(!r_err, "load SP 800-38A key into secret slot 1");

    // ECB
    run_cmd(CMD_AES, 0, {128'd0, AES_P1}, 0, 0);
    check(!r_err && r_result[127:0] == AES_C1, "ECB encrypt, FIPS-197 C.1 vector");
    for (i = 0; i < 4; i = i + 1) begin
      run_cmd(CMD_AES, 1, {128'd0, pt[i]}, 0, 0);
      check(!r_err && r_result[127:0] == ecb_ct[i], "ECB encrypt, SP 800-38A F.1.1 block");
    end
    run_cmd(CMD_AES, 1, {128'd0, pt[0]}, 0, 0);  x = r_result[127:0];
    run_cmd(CMD_AES, 1, {128'd0, pt[0]}, 0, 0);
    check(r_result[127:0] == x, "ECB is deterministic (same block -> same ciphertext)");

    // ECB decrypt
    run_cmd(CMD_AESD, 0, {128'd0, AES_C1}, 0, 0);
    check(!r_err && r_result[127:0] == AES_P1, "ECB decrypt, FIPS-197 C.1 vector");
    for (i = 0; i < 4; i = i + 1) begin
      run_cmd(CMD_AESD, 1, {128'd0, ecb_ct[i]}, 0, 0);
      check(!r_err && r_result[127:0] == pt[i], "ECB decrypt, SP 800-38A F.1.2 block");
    end

    // CBC encrypt (native): chaining value passed in cpu_b
    prev = AES_IV;
    for (i = 0; i < 4; i = i + 1) begin
      run_cmd(CMD_CBCE, 1, {128'd0, pt[i]}, {384'd0, prev}, 0);
      check(!r_err && r_result[127:0] == cbc_ct[i], "CBC encrypt, SP 800-38A F.2.1 block");
      prev = r_result[127:0];
    end
    // CBC decrypt (native)
    prev = AES_IV;
    for (i = 0; i < 4; i = i + 1) begin
      run_cmd(CMD_CBCD, 1, {128'd0, cbc_ct[i]}, {384'd0, prev}, 0);
      check(!r_err && r_result[127:0] == pt[i], "CBC decrypt, SP 800-38A F.2.2 block");
      prev = cbc_ct[i];
    end
    // CBC with a zero IV equals ECB for the first block
    run_cmd(CMD_CBCE, 1, {128'd0, pt[0]}, 512'd0, 0);
    check(r_result[127:0] == ecb_ct[0], "CBC encrypt with a zero IV equals ECB on the first block");
    // round trips
    run_cmd(CMD_AES, 0, {128'd0, 128'h0123456789abcdeffedcba9876543210}, 0, 0);
    run_cmd(CMD_AESD, 0, r_result[255:0], 0, 0);
    check(r_result[127:0] == 128'h0123456789abcdeffedcba9876543210, "ECB encrypt then decrypt returns the plaintext");
    run_cmd(CMD_CBCE, 0, {128'd0, 128'hdeadbeefdeadbeef0123456701234567}, {384'd0, AES_IV}, 0);
    run_cmd(CMD_CBCD, 0, r_result[255:0], {384'd0, AES_IV}, 0);
    check(r_result[127:0] == 128'hdeadbeefdeadbeef0123456701234567, "CBC encrypt then decrypt returns the plaintext");
    check(r_result[255:128] == 128'd0, "upper result bits are zero for a 128-bit block");

    // key handling
    run_cmd(CMD_KRD, 0, 0, 0, 0);          check(r_err, "secret AES key cannot be read back over the secure bus");
    run_cmd(CMD_AES, 6, {128'd0, AES_P1}, 0, 0);  check(r_err, "AES with an empty key slot is rejected");
    run_cmd(CMD_AES, 9, {128'd0, AES_P1}, 0, 0);  check(r_err, "AES with an out-of-range key slot is rejected");
    run_cmd(CMD_AESD, 6, {128'd0, AES_C1}, 0, 0); check(r_err, "AES decrypt with an empty key slot is rejected");
    run_cmd(CMD_CBCD, 9, {128'd0, AES_C1}, 0, 0); check(r_err, "CBC decrypt with an out-of-range key slot is rejected");

    gap("AES key wrapping between Key Store and other engines is not implemented");
    finish("op1 AES");
  end
  initial begin #2_000_000_000; $display("TIMEOUT"); $finish; end
endmodule
