`timescale 1ns/1ps
// Operation 3: ECDSA Sign   -- command 10 (TRNG nonce + key store private key + ECC engine)
// Signatures are also dumped to sign_vectors.txt and re-verified by tools/check_sign_vectors.py
// with an independent Python implementation.
module tb_op3_ecdsa_sign;
  `include "tb_common.vh"
  integer fd;
  reg [255:0] r1, s1, r2, s2, r3, s3;
  localparam [255:0] E_ONES = {256{1'b1}};
  initial begin
    power_up;
    fd = $fopen("sign_vectors.txt", "w");
    run_cmd(CMD_KWR, 3, DA,  0, ATTR_SECRET);  check(!r_err, "load private key into secret slot 3");
    run_cmd(CMD_KWR, 4, QAX, 0, ATTR_PLAIN);   // public key pair, used for the hardware verify below
    run_cmd(CMD_KWR, 5, QAY, 0, ATTR_PLAIN);

    run_cmd(CMD_SLAST, 3, 0, 0, 0);       check(r_err, "hash-then-sign without a finished hash session is rejected");

    run_cmd(CMD_SIGN, 3, SIG1_E, 0, 0);
    r1 = r_result[511:256]; s1 = r_result[255:0];
    check(!r_err && r_ok, "sign completes without error");
    check(r1 != 0 && r1 < N_ORDER && s1 != 0 && s1 < N_ORDER, "r and s are in 1..n-1");
    $fdisplay(fd, "%h %h %h %h %h", SIG1_E, r1, s1, QAX, QAY);

    run_cmd(CMD_SIGN, 3, SIG1_E, 0, 0);
    r2 = r_result[511:256]; s2 = r_result[255:0];
    check(!r_err && r_ok && r2 != 0 && s2 != 0, "second signature of the same digest");
    check(r2 != r1 && s2 != s1, "fresh TRNG nonce: same digest gives a different signature");
    $fdisplay(fd, "%h %h %h %h %h", SIG1_E, r2, s2, QAX, QAY);

`ifndef QUICK
    run_cmd(CMD_SIGN, 3, E_ONES, 0, 0);
    r3 = r_result[511:256]; s3 = r_result[255:0];
    check(!r_err && r_ok && r3 != 0 && s3 != 0, "digest >= n (all ones) is signed (reduced mod n)");
    $fdisplay(fd, "%h %h %h %h %h", E_ONES, r3, s3, QAX, QAY);
`endif
    // hash-then-sign: the digest never leaves the chip; e = digest (SHA-256), leftmost 256 bits (SHA-384),
    // or the digest as an integer (SHA-224). Each signature is re-verified offline in Python.
    send_msg100(2, HM_MSG);
    run_cmd(CMD_SLAST, 3, 0, 0, 0);
    check(!r_err && r_ok && r_result[511:256] != 0 && r_result[255:0] != 0, "hash-then-sign with SHA-256 completes");
    $fdisplay(fd, "%h %h %h %h %h", HM_E256, r_result[511:256], r_result[255:0], QAX, QAY);
`ifndef QUICK
    send_msg100(3, HM_MSG);
    run_cmd(CMD_SLAST, 3, 0, 0, 0);
    check(!r_err && r_ok, "hash-then-sign with SHA-384 completes (leftmost 256 bits)");
    $fdisplay(fd, "%h %h %h %h %h", HM_E384, r_result[511:256], r_result[255:0], QAX, QAY);
    send_msg100(1, HM_MSG);
    run_cmd(CMD_SLAST, 3, 0, 0, 0);
    check(!r_err && r_ok, "hash-then-sign with SHA-224 completes (short digest)");
    $fdisplay(fd, "%h %h %h %h %h", HM_E224, r_result[511:256], r_result[255:0], QAX, QAY);
`endif
    $fclose(fd);

    // hardware round trip through ECDSA Verify (public key slots 4/5)
    run_cmd(CMD_VERIFY, 4, SIG1_E, {r1, s1}, 0);
    check(!r_err && r_ok, "hardware verify accepts the hardware signature");

    run_cmd(CMD_SIGN, 6, SIG1_E, 0, 0);   check(r_err, "sign with an empty key slot is rejected");
    run_cmd(CMD_KRD, 3, 0, 0, 0);         check(r_err, "private key cannot be read back over the secure bus");

    finish("op3 ECDSA sign");
  end
  initial begin #6_000_000_000; $display("TIMEOUT"); $finish; end
endmodule
