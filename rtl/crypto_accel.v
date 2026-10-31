`timescale 1ns/1ps
// "Cryptographic accelerators" box: HASH, AES, ECC engine (ECDSA/ECDH).
// op: 0 HASH, 1 AES-128 ECB encrypt, 2 ECDSA sign, 3 ECDSA verify, 4 ECDH,
//     5 AES-128 ECB decrypt, 6 AES-128 CBC encrypt, 7 AES-128 CBC decrypt
//     12 ECC point validation only: is the point in b on the curve? (ok = valid)
//     11 ECC public key: k*P of the key slot's private key and the point in b (G for key generation), full {x,y}
//     8 HASH init (a[3:0] = algorithm), 9 HASH update, 10 HASH final  (streaming hash_engine:
//       a[6:0] = byte count 0..64, b = data left-aligned; the final returns the digest left-aligned)
// CBC takes the chaining value (IV, or the previous ciphertext block) in b[127:0] and returns the
// processed block; the host feeds the returned/previous ciphertext as the next IV.
module crypto_accel #(parameter BA_W = 4, parameter BA_SECRET = 0) (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,
    input  wire [3:0]   op,
    input  wire [255:0] a,          // HASH msg / AES plaintext[127:0] / ECDSA hash
    input  wire [511:0] b,          // verify: {r,s}; ECDH: peer {x,y}
    input  wire [255:0] k_rand,     // per-signature random from TRNG
    input  wire [255:0] key0,       // slot data (priv key, AES key[127:0], or Qx)
    input  wire [255:0] key1,       // paired slot (Qy)
    output reg          done,
    output reg          err,
    output reg          ok,
    output reg  [511:0] result
);
  reg [3:0] op_q;
  reg       running;

  wire is_ecc_op = (op >= 4'd2) && (op <= 4'd4) || (op == 4'd11) || (op == 4'd12);
  // engine op: 0 sign, 1 verify, 2 ECDH (x only), 3 public key k*P (full point)
  wire [2:0] ecc_op = (op == 4'd2) ? 3'd0 : (op == 4'd3) ? 3'd1 : (op == 4'd4) ? 3'd2 : (op == 4'd11) ? 3'd3 : 3'd4;

  wire hash_start = start && (op == 4'd0);
  wire he_init = start && (op == 4'd8);
  wire he_go   = start && (op == 4'd9 || op == 4'd10);
  wire he_fin  = (op == 4'd10);
  wire         he_done, he_err;
  wire [511:0] he_dig;
  hash_engine u_heng (.clk(clk), .rst_n(rst_n), .init_cmd(he_init), .alg(a[3:0]), .go(he_go), .is_final(he_fin),
                      .chunk(b), .clen(a[6:0]), .done(he_done), .err(he_err), .digest(he_dig), .busy());
  wire is_aes_op = (op == 4'd1) || (op >= 4'd5 && op <= 4'd7);
  wire aes_start  = start && is_aes_op;
  wire aes_dec_in = (op == 4'd5) || (op == 4'd7);
  wire aes_cbc_in = (op == 3'd6) || (op == 3'd7);
  wire ecc_start  = start && is_ecc_op;

  wire         hash_done, aes_done, ecc_done, ecc_ok, hash_busy, aes_busy;
  wire [255:0] hash_dig;
  wire [127:0] aes_out;
  wire [127:0] aes_iv   = b[127:0];
  // CBC encrypt: P xor IV before the cipher; CBC decrypt: D(C) xor IV after it
  wire [127:0] aes_din  = (op == 4'd6) ? (a[127:0] ^ aes_iv) : a[127:0];
  wire [127:0] aes_res  = (op_q == 4'd7) ? (aes_out ^ aes_iv) : aes_out;
  wire [511:0] ecc_res;

  hash_core u_hash (.clk(clk), .rst_n(rst_n), .start(hash_start), .msg(a),
                    .busy(hash_busy), .done(hash_done), .digest(hash_dig));

  aes128_core u_aes (.clk(clk), .rst_n(rst_n), .start(aes_start), .dec(aes_dec_in),
                     .key(key0[127:0]), .din(aes_din),
                     .busy(aes_busy), .done(aes_done), .dout(aes_out));

  ecc_engine #(.BA_W(BA_W), .BA_SECRET(BA_SECRET)) u_ecc (
      .clk(clk), .rst_n(rst_n), .start(ecc_start), .op(ecc_op),
      .hash(a), .operand(b), .k_rand(k_rand), .d(key0), .qx(key0), .qy(key1),
      .done(ecc_done), .result(ecc_res), .ok(ecc_ok));

  always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      done <= 1'b0; err <= 1'b0; ok <= 1'b0; result <= 512'd0; op_q <= 3'd0; running <= 1'b0;
    end else begin
      done <= 1'b0;
      if (start) begin
        op_q <= op;
        if (1'b0) begin err <= 1'b1; ok <= 1'b0; done <= 1'b1; end
        else begin err <= 1'b0; running <= 1'b1; end
      end
      if (he_done) begin result <= he_dig; ok <= !he_err; err <= he_err; done <= 1'b1; running <= 1'b0; end
      if (hash_done) begin result <= {256'd0, hash_dig};       ok <= 1'b1; done <= 1'b1; running <= 1'b0; end
      if (aes_done)  begin result <= {384'd0, aes_res};         ok <= 1'b1; done <= 1'b1; running <= 1'b0; end
      if (ecc_done)  begin result <= ecc_res;                  ok <= ecc_ok; done <= 1'b1; running <= 1'b0; end
    end
  end
endmodule
