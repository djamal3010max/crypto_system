`timescale 1ns/1ps
// Operation 2: HASH / Digest
//   command 02: SHA-256 of one 256-bit message (single shot)
//   commands 07/08/09: streaming interface (init / update / final) for SHA-1 (legacy), SHA-224/256,
//   SHA-384/512 and SHA3-224/256/384/512, messages of any length in chunks of 0..64 bytes
module tb_op2_hash;
  `include "tb_common.vh"
  reg [255:0] d1;
  reg [2399:0] mv;
  integer pos, take, hs_n, hs_bad;
  reg [511:0] cm;

  // one complete streaming hash through the CPU command interface, compared against hashlib
  task hs(input integer alg, input integer len, input integer ch, input [2399:0] msg, input [511:0] exp, input integer bits);
    begin
      hs_n = hs_n + 1;
      run_cmd(CMD_HINIT, alg[3:0], 256'd0, 512'd0, 0);
      if (r_err) hs_bad = hs_bad + 1;
      pos = 0; mv = msg;
      while ((len - pos) > ch) begin
        take = ch;
        run_cmd(CMD_HUPD, 0, take, mv[2399 -: 512], 0);
        if (r_err) hs_bad = hs_bad + 1;
        mv = mv << (8*take); pos = pos + take;
      end
      take = len - pos;
      run_cmd(CMD_HFIN, 0, take, mv[2399 -: 512], 0);
      cm = ~({512{1'b1}} >> bits);
      if (r_err || !r_ok || ((r_result & cm) !== (exp & cm))) begin
        hs_bad = hs_bad + 1; $display("      stream mismatch: alg=%0d len=%0d chunk=%0d", alg, len, ch);
      end
    end
  endtask
  initial begin
    power_up;
    run_cmd(CMD_HASH, 0, H_M0, 0, 0);  check(!r_err && r_result[255:0] == H_D0, "SHA-256 of 32 zero bytes");
    run_cmd(CMD_HASH, 0, H_M1, 0, 0);  check(!r_err && r_result[255:0] == H_D1, "SHA-256 of 32 x 0xFF");
    run_cmd(CMD_HASH, 0, H_M2, 0, 0);  check(!r_err && r_result[255:0] == H_D2, "SHA-256 of bytes 00..1f");
    run_cmd(CMD_HASH, 0, H_M3, 0, 0);  check(!r_err && r_result[255:0] == H_D3, "SHA-256 of an ASCII message");
    run_cmd(CMD_HASH, 0, H_M4, 0, 0);  check(!r_err && r_result[255:0] == H_D4, "SHA-256 of a digest (hash chaining input)");
    run_cmd(CMD_HASH, 0, H_M2, 0, 0);  d1 = r_result[255:0];
    run_cmd(CMD_HASH, 0, H_M2, 0, 0);  check(r_result[255:0] == d1, "digest is repeatable back to back");
    run_cmd(CMD_HASH, 0, H_M0 ^ 256'd1, 0, 0);
    check(r_result[255:0] != H_D0, "flipping one input bit changes the digest");
    check(r_result[511:256] == 256'd0, "upper result bits are zero for a 256-bit digest");


    // ---- streaming interface: 9 algorithms x 6 lengths x 2 chunk sizes ----
    hs_n = 0; hs_bad = 0;
`include "hash_stream.vh"
    check(hs_bad == 0, "streaming SHA-1/224/256/384/512 and SHA3-224/256/384/512 match hashlib (108 messages)");

    // interleaving: a legacy single-shot hash while a streaming session is open
    run_cmd(CMD_HINIT, 2, 0, 0, 0);
    run_cmd(CMD_HUPD, 0, 32, {H_M2, 256'd0}, 0);
    run_cmd(CMD_HASH, 0, H_M0, 0, 0);
    check(!r_err && r_result[255:0] == H_D0, "single-shot HASH works while a streaming session is open");
    run_cmd(CMD_HFIN, 0, 0, 0, 0);
    check(!r_err && r_result[511:256] == H_D2, "interrupted streaming session still produces the right digest");

    // error handling
    run_cmd(CMD_HUPD, 0, 5, 0, 0);          check(r_err, "update after the session ended is rejected");
    run_cmd(CMD_HINIT, 15, 0, 0, 0);        check(r_err, "unknown hash algorithm is rejected");
    run_cmd(CMD_HINIT, 2, 0, 0, 0);
    run_cmd(CMD_HUPD, 0, 65, 0, 0);         check(r_err, "chunk longer than 64 bytes is rejected");
    run_cmd(CMD_HFIN, 0, 0, 0, 0);
    check(!r_err && r_result[511:256] == 256'he3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855,
          "empty message gives the SHA-256 empty-string digest");
    gap("certificate management does not call the hash engine by itself (host sequences HASH and VERIFY)");
    finish("op2 HASH");
  end
  initial begin #500_000_000; $display("TIMEOUT"); $finish; end
endmodule
