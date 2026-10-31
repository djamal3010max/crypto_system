`timescale 1ns/1ps
// Operation 6: Secure Load (key injection / rotation)
//   command 16 SECURE_LOAD: hash the package, ECDSA-verify it with the issuer key, AES-unwrap the key with a
//   KEK, write it to the key store - atomically, in that order; the key is written only if the signature verifies.
//   Also covers the key-store injection / rotation / lock / secret semantics underneath it.
module tb_op6_secure_load;
  `include "tb_common.vh"
  localparam [255:0] KEY_A = 256'hA1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1;
  localparam [255:0] KEY_B = 256'hB2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2;
  localparam [255:0] KEY_C = 256'hC3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3;
  initial begin
    power_up;

    // injection and rotation of a (non-secret, e.g. public) key
    run_cmd(CMD_KWR, 2, KEY_A, 0, ATTR_PLAIN);  check(!r_err, "inject key into slot 2");
    run_cmd(CMD_KRD, 2, 0, 0, 0);               check(!r_err && r_result[255:0] == KEY_A, "injected key reads back (non-secret slot)");
    run_cmd(CMD_KWR, 2, KEY_B, 0, ATTR_PLAIN);  check(!r_err, "rotate: rewrite unlocked slot 2");
    run_cmd(CMD_KRD, 2, 0, 0, 0);               check(!r_err && r_result[255:0] == KEY_B, "rotated key replaces the old key");

    // secret keys: writable, never readable over the bus, rotation still allowed
    run_cmd(CMD_KWR, 3, KEY_A, 0, ATTR_SECRET); check(!r_err, "inject secret key into slot 3");
    run_cmd(CMD_KRD, 3, 0, 0, 0);               check(r_err, "secret key cannot be read back");
    run_cmd(CMD_KWR, 3, KEY_B, 0, ATTR_SECRET); check(!r_err, "secret key can be rotated while unlocked");

    // locked slots cannot be rotated or overwritten
    run_cmd(CMD_KWR, 5, KEY_A, 0, ATTR_LOCK);   check(!r_err, "inject key with lock attribute into slot 5");
    run_cmd(CMD_KWR, 5, KEY_B, 0, ATTR_PLAIN);  check(r_err, "locked slot rejects rotation");
    run_cmd(CMD_KRD, 5, 0, 0, 0);               check(!r_err && r_result[255:0] == KEY_A, "locked slot still holds the original key");

    // key unwrap primitive: a wrapped working key is decrypted with a key-encryption key in the key store
    run_cmd(CMD_KWR, 0, {128'd0, AES_K1}, 0, ATTR_SECRET);              // KEK, never readable
    run_cmd(CMD_AESD, 0, {128'd0, UNWRAP_CT}, 0, 0);
    check(!r_err && r_result[127:0] == UNWRAP_PT, "AES decrypt unwraps the injected key with the KEK");
    run_cmd(CMD_KWR, 4, {128'd0, r_result[127:0]}, 0, ATTR_SECRET);     // host installs the unwrapped key
    check(!r_err, "unwrapped key written to a secret slot");
    run_cmd(CMD_AES, 4, 256'd0, 0, 0);
    check(!r_err, "unwrapped key is usable for AES");

    // out-of-range slot
    run_cmd(CMD_KWR, 12, KEY_A, 0, ATTR_PLAIN); check(r_err, "injection into an out-of-range slot is rejected");

    // ---------------- atomic SECURE_LOAD ----------------
    run_cmd(CMD_KWR, 0, {128'd0, AES_K1}, 0, ATTR_SECRET);              // KEK in slot 0 (already there, rewritten)
    run_cmd(CMD_KWR, 6, QIX, 0, ATTR_PLAIN);  run_cmd(CMD_KWR, 7, QIY, 0, ATTR_PLAIN);   // issuer public key pair
    // cheap argument checks first
    run_cmd(CMD_SLOAD, 12, SL_A, {SL_R, SL_S}, ATTR_SECRET);   check(r_err, "secure load: destination slot out of range rejected");
    run_cmd(CMD_SLOAD, 4, (SL_A & ~256'hff) | 256'h05, {SL_R, SL_S}, ATTR_SECRET);
    check(r_err, "secure load: odd issuer slot rejected");
    run_cmd(CMD_SLOAD, 4, (SL_A & ~256'hff) | 256'h00, {SL_R, SL_S}, ATTR_SECRET);
    check(r_err, "secure load: issuer pair with an empty slot rejected");
    run_cmd(CMD_SLOAD, 4, (SL_A & ~256'hff) | 256'h02, {SL_R, SL_S}, ATTR_SECRET);
    check(!r_err && !r_ok, "secure load: issuer 'public key' that is not on the curve fails authentication");
    run_cmd(CMD_AES, 4, 256'd0, 0, 0);                         // slot 4 was used by the unwrap test above
    // authentic package
    run_cmd(CMD_KWR, 4, 256'd0, 0, ATTR_PLAIN);                // clear the destination first (slot 4 -> known state)
    run_cmd(CMD_SLOAD, 4, SL_A, {SL_R, SL_S}, ATTR_SECRET);
    check(!r_err && r_ok, "secure load: authentic package accepted and installed");
    check(r_result == 512'd0, "secure load: nothing sensitive is returned to the CPU");
    run_cmd(CMD_AES, 4, {128'd0, SL_PT}, 0, 0);
    check(!r_err && r_result[127:0] == SL_CT, "secure load: installed key is exactly the unwrapped working key");
    run_cmd(CMD_KRD, 4, 0, 0, 0);                              check(r_err, "secure load: installed key was marked secret and cannot be read");
    // tampered package: wrapped key changed -> signature fails, destination stays untouched
    run_cmd(CMD_SLOAD, 1, SL_A ^ (256'd1 << 128), {SL_R, SL_S}, ATTR_SECRET);
    check(!r_err && !r_ok, "secure load: tampered wrapped key rejected");
    run_cmd(CMD_AES, 1, 256'd0, 0, 0);
    check(r_err, "secure load: nothing was written to the destination after a failed authentication");
    // ---- anti-replay: a version counter per destination slot (rejected before any cryptography) ----
    run_cmd(CMD_SLOAD, 4, SL_A, {SL_R, SL_S}, ATTR_SECRET);
    check(!r_err && !r_ok, "secure load: replay of an already installed package rejected");
    run_cmd(CMD_SLOAD, 4, SLOLD_A, {SLOLD_R, SLOLD_S}, ATTR_SECRET);
    check(!r_err && !r_ok, "secure load: validly signed OLDER version (downgrade) rejected");
    run_cmd(CMD_AES, 4, {128'd0, SL_PT}, 0, 0);
    check(!r_err && r_result[127:0] == SL_CT, "secure load: slot still holds the installed key after replay and downgrade attempts");
`ifndef QUICK
    // newer version for the same slot is accepted and replaces the key
    run_cmd(CMD_SLOAD, 4, SLNEW_A, {SLNEW_R, SLNEW_S}, ATTR_SECRET);
    check(!r_err && r_ok, "secure load: newer version (key rotation) accepted");
    run_cmd(CMD_AES, 4, {128'd0, SL_PT}, 0, 0);
    check(!r_err && r_result[127:0] == SLNEW_CT, "secure load: rotated key replaced the old one");
    run_cmd(CMD_SLOAD, 4, SL_A, {SL_R, SL_S}, ATTR_SECRET);
    check(!r_err && !r_ok, "secure load: the previous package can no longer be installed after the rotation");
    // package replayed to a different destination slot: destination is part of the signed message
    run_cmd(CMD_SLOAD, 2, SL_A, {SL_R, SL_S}, ATTR_SECRET);
    check(!r_err && !r_ok, "secure load: package for slot 4 rejected when aimed at slot 2");
    // authentic package, locked destination: authentication passes, the key-store write is refused -> error
    run_cmd(CMD_KWR, 5, 256'd1, 0, ATTR_SECRET_LOCK);          // slot 5 holds a different key and is locked
    run_cmd(CMD_SLOAD, 5, SLLCK_A, {SLLCK_R, SLLCK_S}, ATTR_SECRET);
    check(r_err, "secure load: authentic package aimed at a locked slot is refused");
    run_cmd(CMD_AES, 5, {128'd0, SL_PT}, 0, 0);
    check(!r_err && r_result[127:0] != SLLCK_CT, "secure load: locked slot still holds its previous key");
`endif
    gap("version counters are volatile flip-flops here; they must live in non-volatile memory to survive power-down");
    finish("op6 Secure Load");
  end
  initial begin #4_000_000_000; $display("TIMEOUT"); $finish; end
endmodule
