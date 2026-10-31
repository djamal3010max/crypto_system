`timescale 1ns/1ps
// Operation 4: ECDSA Verify   -- command 11 (public key only: no TRNG, no private key)
// Known-answer signature made by an independent Python implementation (tools/p256.py).
module tb_op4_ecdsa_verify;
  `include "tb_common.vh"
  initial begin
    power_up;
    // public keys in (even, odd) slot pairs: signer A -> 4/5, issuer -> 6/7, other party B -> 0/1
    run_cmd(CMD_KWR, 4, QAX, 0, ATTR_PLAIN);  run_cmd(CMD_KWR, 5, QAY, 0, ATTR_PLAIN);
    run_cmd(CMD_KWR, 6, QIX, 0, ATTR_PLAIN);  run_cmd(CMD_KWR, 7, QIY, 0, ATTR_PLAIN);
    run_cmd(CMD_KWR, 0, QBX, 0, ATTR_PLAIN);  run_cmd(CMD_KWR, 1, QBY, 0, ATTR_PLAIN);

    run_cmd(CMD_VLAST, 4, 0, {SIG1_R, SIG1_S}, 0);
    check(r_err, "hash-then-verify without a finished hash session is rejected");

    run_cmd(CMD_VERIFY, 4, SIG1_E, {SIG1_R, SIG1_S}, 0);
    check(!r_err && r_ok, "valid signature (Python known answer) accepted");

    run_cmd(CMD_VERIFY, 4, SIG1_E ^ 256'd1, {SIG1_R, SIG1_S}, 0);
    check(!r_err && !r_ok, "digest with one flipped bit rejected");

    run_cmd(CMD_VERIFY, 4, SIG1_E, {SIG1_R, 256'd0}, 0);
    check(!r_err && !r_ok, "s = 0 rejected");

    run_cmd(CMD_VERIFY, 2, SIG1_E, {SIG1_R, SIG1_S}, 0);
    check(r_err, "verify with an empty public-key pair is rejected");

    // hash-then-verify: signatures made by Python over SHA-256(message) of a 100-byte message
    send_msg100(2, HM_MSG);
    run_cmd(CMD_VLAST, 4, 0, {SIGM256_R, SIGM256_S}, 0);
    check(!r_err && r_ok, "hash-then-verify: SHA-256 signature over a 100-byte message accepted");
    send_msg100(2, HM_MSG_BAD);
    run_cmd(CMD_VLAST, 4, 0, {SIGM256_R, SIGM256_S}, 0);
    check(!r_err && !r_ok, "hash-then-verify: message with one flipped bit rejected");

    // public key that is not on the curve (valid x, y + 1): must be rejected before any use
    run_cmd(CMD_KWR, 2, QAX, 0, ATTR_PLAIN);  run_cmd(CMD_KWR, 3, QAY + 256'd1, 0, ATTR_PLAIN);
    run_cmd(CMD_VERIFY, 2, SIG1_E, {SIG1_R, SIG1_S}, 0);
    check(!r_err && !r_ok, "off-curve public key rejected");

    run_cmd(CMD_KWR, 2, BAD_PX, 0, ATTR_PLAIN);  run_cmd(CMD_KWR, 3, BAD_PY, 0, ATTR_PLAIN);
    run_cmd(CMD_VERIFY, 2, SIG1_E, {SIG1_R, SIG1_S}, 0);
    check(!r_err && !r_ok, "public key that is not on the curve is rejected");

`ifndef QUICK
    run_cmd(CMD_VERIFY, 4, SIG1_E, {SIG1_R ^ 256'd1, SIG1_S}, 0);
    check(!r_err && !r_ok, "signature with a flipped bit in r rejected");

    run_cmd(CMD_VERIFY, 4, SIG1_E, {SIG1_R, SIG1_S ^ 256'd1}, 0);
    check(!r_err && !r_ok, "signature with a flipped bit in s rejected");

    run_cmd(CMD_VERIFY, 0, SIG1_E, {SIG1_R, SIG1_S}, 0);
    check(!r_err && !r_ok, "valid signature checked against the wrong public key rejected");

    run_cmd(CMD_VERIFY, 4, SIG1_E, {256'd0, SIG1_S}, 0);
    check(!r_err && !r_ok, "r = 0 rejected");

    run_cmd(CMD_VERIFY, 4, SIG1_E, {N_ORDER, SIG1_S}, 0);
    check(!r_err && !r_ok, "r = n (out of range) rejected");

    send_msg100(3, HM_MSG);
    run_cmd(CMD_VLAST, 4, 0, {SIGM384_R, SIGM384_S}, 0);
    check(!r_err && r_ok, "hash-then-verify: SHA-384 (leftmost 256 bits) accepted");
    send_msg100(1, HM_MSG);
    run_cmd(CMD_VLAST, 4, 0, {SIGM224_R, SIGM224_S}, 0);
    check(!r_err && r_ok, "hash-then-verify: SHA-224 (short digest) accepted");

    run_cmd(CMD_VERIFY, 6, SIG2_E, {SIG2_R, SIG2_S}, 0);
    check(!r_err && r_ok, "second known-answer signature under the issuer key accepted");
`endif
    finish("op4 ECDSA verify");
  end
  initial begin #8_000_000_000; $display("TIMEOUT"); $finish; end
endmodule
