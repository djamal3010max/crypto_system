`timescale 1ns/1ps
// Operation 7: Certificate Parse/Verify
//   command 17 CERT_VERIFY: hash-then-verify requested by certificate management: the digest of the certificate
//   body (streamed through the hash engine first) is ECDSA-verified with the issuer key and, only if the signature
//   is valid, recorded in a certificate entry. With attr[0] set it also PARSES the certificate body (SCC-1:
//   version byte 0x01 + subject public key x||y, 65 bytes), validates the subject key and installs it as a
//   public-key pair, so a certificate chain can be walked. Also covers the certificate store itself.
module tb_op7_certificate;
  `include "tb_common.vh"
  reg [255:0] digest;
  localparam [1:0] ATTR_INSTALL = 2'b01;
  // stream a 65-byte certificate body: 64-byte update + 1-byte final
  task send_body65(input [519:0] body);
    begin
      run_cmd(CMD_HINIT, 2, 0, 0, 0);
      run_cmd(CMD_HUPD, 0, 256'd64, body[519:8], 0);
      run_cmd(CMD_HFIN, 0, 256'd1, {body[7:0], 504'd0}, 0);
    end
  endtask
  initial begin
    power_up;
    run_cmd(CMD_KWR, 6, QIX, 0, ATTR_PLAIN);  run_cmd(CMD_KWR, 7, QIY, 0, ATTR_PLAIN);   // issuer (CA) public key

    // certificate store
    run_cmd(CMD_CRD, 1, 0, 0, 0);                   check(r_err, "reading an empty certificate entry is rejected");
    run_cmd(CMD_CWR, 1, CERT_HASH, 0, 0);           check(!r_err, "store certificate hash in entry 1");
    run_cmd(CMD_CRD, 1, 0, 0, 0);                   check(!r_err && r_result[255:0] == CERT_HASH, "stored certificate hash reads back");
    run_cmd(CMD_CCHK, 1, CERT_HASH, 0, 0);          check(!r_err && r_ok, "certificate check: matching hash");
    run_cmd(CMD_CCHK, 1, CERT_HASH ^ 256'd1, 0, 0); check(!r_err && !r_ok, "certificate check: one flipped bit is a mismatch");
    run_cmd(CMD_CWR, 5, CERT_HASH, 0, 0);           check(r_err, "certificate entry index >= 4 is rejected (no aliasing)");
    run_cmd(CMD_CRD, 0, 0, 0, 0);                   check(r_err, "entry 0 untouched by the out-of-range write");

    // hash, then verify (host-sequenced): SHA-256 of the 32-byte certificate body, issuer signature over it
    run_cmd(CMD_HASH, 0, CERT_BODY, 0, 0);
    digest = r_result[255:0];
    check(!r_err && digest == CERT_HASH, "HASH of the certificate body matches the Python digest");

`ifndef QUICK
    run_cmd(CMD_VERIFY, 6, digest, {CERT_R, CERT_S}, 0);
    check(!r_err && r_ok, "issuer signature over the certificate digest verifies");
    run_cmd(CMD_CCHK, 1, digest, 0, 0);
    check(!r_err && r_ok, "verified certificate digest equals the stored trust-chain hash");

    run_cmd(CMD_HASH, 0, CERT_BAD_BODY, 0, 0);
    check(r_result[255:0] != CERT_HASH, "altered certificate body gives a different digest");
    run_cmd(CMD_VERIFY, 6, r_result[255:0], {CERT_R, CERT_S}, 0);
    check(!r_err && !r_ok, "issuer signature does not verify for the altered certificate");
`endif

    // ---------------- CERT_VERIFY (hash, then verify, then record) ----------------
    run_cmd(CMD_CVER, 6, 256'd2, {CERT_R, CERT_S}, 0);
    check(r_err, "cert verify without a finished hash session is rejected");
    run_cmd(CMD_HINIT, 2, 0, 0, 0);
    run_cmd(CMD_HFIN, 0, 256'd32, {CERT_BODY, 256'd0}, 0);
    run_cmd(CMD_CVER, 6, 256'd7, {CERT_R, CERT_S}, 0);        check(r_err, "cert verify with an entry index >= 4 is rejected");
    run_cmd(CMD_CVER, 5, 256'd2, {CERT_R, CERT_S}, 0);        check(r_err, "cert verify with an odd issuer slot is rejected");
    run_cmd(CMD_CVER, 2, 256'd2, {CERT_R, CERT_S}, 0);        check(r_err, "cert verify with an empty issuer key pair is rejected");
    run_cmd(CMD_CRD, 2, 0, 0, 0);                              check(r_err, "entry 2 is still empty after the rejected attempts");
    run_cmd(CMD_CVER, 6, 256'd2, {CERT_R, CERT_S}, 0);
    check(!r_err && r_ok, "authentic certificate verified by hash-then-verify");
    run_cmd(CMD_CRD, 2, 0, 0, 0);
    check(!r_err && r_result[255:0] == CERT_HASH, "the verified digest was recorded in the certificate entry");
    run_cmd(CMD_CCHK, 2, CERT_HASH, 0, 0);                     check(!r_err && r_ok, "certificate check against the recorded digest passes");
`ifndef QUICK
    run_cmd(CMD_HINIT, 2, 0, 0, 0);
    run_cmd(CMD_HFIN, 0, 256'd32, {CERT_BAD_BODY, 256'd0}, 0);
    run_cmd(CMD_CVER, 6, 256'd3, {CERT_R, CERT_S}, 0);
    check(!r_err && !r_ok, "altered certificate body fails hash-then-verify");
    run_cmd(CMD_CRD, 3, 0, 0, 0);
    check(r_err, "nothing is recorded for a certificate that failed verification");
`endif

    // ---------------- certificate parsing and subject-key installation (SCC-1) ----------------
    run_cmd(CMD_HINIT, 2, 0, 0, 0);
    run_cmd(CMD_CVER, 6, 256'd17, {SCC_R, SCC_S}, ATTR_INSTALL);
    check(r_err, "install without a finished hash session is rejected");
    run_cmd(CMD_HINIT, 2, 0, 0, 0);
    run_cmd(CMD_HFIN, 0, 256'd64, SCC_BODY[519:8], 0);
    run_cmd(CMD_CVER, 6, 256'd17, {SCC_R, SCC_S}, ATTR_INSTALL);
    check(r_err, "malformed certificate (64 bytes instead of 65) is rejected");
    send_body65(SCCVER_BODY);
    run_cmd(CMD_CVER, 6, 256'd17, {SCC_R, SCC_S}, ATTR_INSTALL);
    check(r_err, "certificate with an unknown format version is rejected");
    // regression for a length-counter wrap: 65 + 256 = 321 bytes must NOT look like a 65-byte body
    run_cmd(CMD_HINIT, 2, 0, 0, 0);
    run_cmd(CMD_HUPD, 0, 256'd64, SCC_BODY[519:8], 0);
    repeat (4) run_cmd(CMD_HUPD, 0, 256'd64, 512'd0, 0);
    run_cmd(CMD_HFIN, 0, 256'd1, 512'd0, 0);
    run_cmd(CMD_CVER, 6, 256'd17, {SCC_R, SCC_S}, ATTR_INSTALL);
    check(r_err, "321-byte message rejected as a certificate body (length saturates)");
    send_body65(SCC_BODY);
    run_cmd(CMD_CVER, 6, 256'd21, {SCC_R, SCC_S}, ATTR_INSTALL);   // destination slot 5 (odd)
    check(r_err, "install into an odd destination slot is rejected");
    run_cmd(CMD_CVER, 6, 256'd33, {SCC_R, SCC_S}, ATTR_INSTALL);   // destination slot 8 (out of range)
    check(r_err, "install into an out-of-range destination slot is rejected");
    run_cmd(CMD_VERIFY, 4, CHAIN_E, {CHAIN_R, CHAIN_S}, 0);
    check(r_err, "destination pair is still empty after the rejected installs");
    // authentic certificate: signature checks out, subject key is installed in slots 4/5, digest recorded in entry 1
    run_cmd(CMD_CVER, 6, 256'd17, {SCC_R, SCC_S}, ATTR_INSTALL);
    check(!r_err && r_ok, "authentic certificate parsed, verified and its subject key installed");
    run_cmd(CMD_CRD, 1, 0, 0, 0);
    check(!r_err && r_result[255:0] == SCC_E, "certificate digest recorded in entry 1");
    run_cmd(CMD_VERIFY, 4, CHAIN_E, {CHAIN_R, CHAIN_S}, 0);
    check(!r_err && r_ok, "signature made by the certified subject key verifies with the installed key (chain of trust)");
`ifndef QUICK
    send_body65(SCC_TAMPER_BODY);
    run_cmd(CMD_CVER, 6, 256'd11, {SCC_R, SCC_S}, ATTR_INSTALL);   // destination slots 2/3, entry 3
    check(!r_err && !r_ok, "certificate with an altered subject key fails verification");
    send_body65(SCCOFF_BODY);
    run_cmd(CMD_CVER, 6, 256'd11, {SCCOFF_R, SCCOFF_S}, ATTR_INSTALL);
    check(!r_err && !r_ok, "validly signed certificate carrying an off-curve subject key is not installed");
    run_cmd(CMD_VERIFY, 2, CHAIN_E, {CHAIN_R, CHAIN_S}, 0);
    check(r_err, "slots 2/3 are still empty after the failed installs");
    run_cmd(CMD_CRD, 3, 0, 0, 0);
    check(r_err, "no certificate entry recorded for the failed installs");
`endif
    gap("only the compact SCC-1 certificate format is parsed; there is no X.509 / CV-certificate (ASN.1) parser");
    finish("op7 Certificate");
  end
  initial begin #4_000_000_000; $display("TIMEOUT"); $finish; end
endmodule
