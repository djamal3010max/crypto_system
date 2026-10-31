`timescale 1ns/1ps
// Operation 5: ECDH Key Agreement   -- command 12 (shared secret = x-coordinate of d * peer)
module tb_op5_ecdh;
  `include "tb_common.vh"
  integer fd;
  reg [255:0] shared_ab, shared_ba, eph_d;
  reg [511:0] pubA, pubB;
  reg [255:0] sa, sb2;
  initial begin
    power_up;
    fd = $fopen("ecdh_vectors.txt", "w");
    run_cmd(CMD_KWR, 2, DA, 0, ATTR_SECRET);   run_cmd(CMD_KWR, 3, DB, 0, ATTR_SECRET);

    run_cmd(CMD_ECDH, 2, 0, {QBX, QBY}, 0);
    shared_ab = r_result[255:0];
    check(!r_err && r_ok && shared_ab == ECDH_SHARED, "A*QB equals the Python shared secret");

    run_cmd(CMD_ECDH, 3, 0, {QAX, QAY}, 0);
    shared_ba = r_result[255:0];
    check(!r_err && r_ok && shared_ba == ECDH_SHARED, "B*QA equals the Python shared secret");
    check(shared_ab == shared_ba, "both parties derive the same secret");

    // ephemeral public key = k * G  (peer = generator), known scalar
    run_cmd(CMD_KWR, 5, ECDH_EPH_D, 0, ATTR_SECRET);
    run_cmd(CMD_ECDH, 5, 0, {GX, GY}, 0);
    check(!r_err && r_ok && r_result[255:0] == ECDH_EPH_QX, "k*G x-coordinate matches Python (ephemeral public key)");

    // ephemeral scalar from the TRNG, then k*G; result re-checked offline against Python
    run_cmd(CMD_RANDOM, 0, 0, 0, 0);  eph_d = r_result[255:0];
    check(!r_err && eph_d != 0, "TRNG supplies an ephemeral scalar");
    run_cmd(CMD_KWR, 6, eph_d, 0, ATTR_SECRET);
    run_cmd(CMD_ECDH, 6, 0, {GX, GY}, 0);
    check(!r_err && r_ok && r_result[255:0] != 0, "k*G with a TRNG scalar completes");
    $fdisplay(fd, "%h %h", eph_d, r_result[255:0]);
    $fclose(fd);

    // ECDH + SP 800-56C one-step KDF: SHA-256(00000001 || Z || FixedInfo); Z is never exposed
    run_cmd(CMD_KDF, 2, KDF_INFO | 256'd7, {QBX, QBY}, 0);
    check(!r_err && r_ok && r_result[255:0] == KDF_OUT, "ECDH_KDF with 7-byte FixedInfo matches Python");
    check(r_result[255:0] != ECDH_SHARED && r_result[511:256] == 256'd0, "KDF output is not the raw shared secret");
    run_cmd(CMD_KDF, 2, 256'd0, {QBX, QBY}, 0);
    check(!r_err && r_ok && r_result[255:0] == KDF_OUT0, "ECDH_KDF without FixedInfo matches Python");
    run_cmd(CMD_KDF, 2, 256'd29, {QBX, QBY}, 0);   check(r_err, "ECDH_KDF with FixedInfo longer than 28 bytes is rejected");
    run_cmd(CMD_KDF, 1, 256'd0, {QBX, QBY}, 0);    check(r_err, "ECDH_KDF with an empty private-key slot is rejected");
    run_cmd(CMD_KDF, 2, 256'd0, {BAD_PX, BAD_PY}, 0);
    check(!r_err && !r_ok && r_result == 512'd0, "ECDH_KDF with an off-curve peer returns nothing");
`ifndef QUICK
    run_cmd(CMD_KDF, 3, KDF_INFO | 256'd7, {QAX, QAY}, 0);
    check(!r_err && r_ok && r_result[255:0] == KDF_OUT, "party B derives the same KDF key as party A");
`endif

    // ---------------- KEYGEN: TRNG scalar -> key store (secret) -> full public key ----------------
    run_cmd(CMD_KGEN, 12, 0, 0, 0);                     check(r_err, "key generation into an out-of-range slot is rejected");
    run_cmd(CMD_KWR, 4, 256'd1, 0, ATTR_SECRET_LOCK);
    run_cmd(CMD_KGEN, 4, 0, 0, 0);                      check(r_err, "key generation into a locked slot is refused");
    run_cmd(CMD_KGEN, 6, 0, 0, ATTR_PLAIN);
    pubA = r_result;
    check(!r_err && r_ok && pubA[511:256] != 0 && pubA[255:0] != 0, "key generation returns a public key {x,y}");
    run_cmd(CMD_KRD, 6, 0, 0, 0);                       check(r_err, "generated private key is secret even though the request asked for a plain slot");
    run_cmd(CMD_ECDH, 2, 0, pubA, 0);
    check(!r_err && r_ok && r_result[255:0] != 0, "generated public key is a valid curve point (accepted as an ECDH peer)");
`ifndef QUICK
    run_cmd(CMD_KGEN, 7, 0, 0, ATTR_PLAIN);
    pubB = r_result;
    check(!r_err && r_ok && pubB != pubA, "a second generated key pair differs from the first");
    run_cmd(CMD_ECDH, 6, 0, pubB, 0);   sa  = r_result[255:0];
    run_cmd(CMD_ECDH, 7, 0, pubA, 0);   sb2 = r_result[255:0];
    check(sa != 0 && sa == sb2, "ECDH between two generated key pairs agrees: public keys match their private keys");
`endif

    run_cmd(CMD_ECDH, 1, 0, {QBX, QBY}, 0);   check(r_err, "ECDH with an empty private-key slot is rejected");
    run_cmd(CMD_KRD, 2, 0, 0, 0);              check(r_err, "private key cannot be read back over the secure bus");

    // invalid peer keys are rejected before any scalar multiplication, so these cases are fast
    run_cmd(CMD_ECDH, 2, 0, 512'd0, 0);
    check(r_err || !r_ok, "peer = point at infinity rejected");

    // spec: "the peer's key must first be checked to be a valid curve point"
    run_cmd(CMD_ECDH, 2, 0, {BAD_PX, BAD_PY}, 0);
    check(r_err || !r_ok, "off-curve peer key rejected");
    check(r_result[255:0] == 256'd0, "no shared secret is released for an off-curve peer");
    finish("op5 ECDH");
  end
  initial begin #6_000_000_000; $display("TIMEOUT"); $finish; end
endmodule
