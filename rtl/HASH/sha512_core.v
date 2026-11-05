`timescale 1ns/1ps
// SHA-512 compression core: one 1024-bit block per start, one round per clock.
//   cont = 0 : start from the SHA-512 IV
//   cont = 1 : continue from the previous chaining value (digest register)
// digest holds the full 512-bit chaining value (the SHA-512 digest).
module sha512_core (
    input  wire          clk,
    input  wire          rst_n,
    input  wire          start,
    input  wire          cont,
    input  wire [1023:0] block,
    output reg           busy,
    output reg           done,
    output reg  [511:0]  digest
);
  localparam [511:0] IV512 = {64'h6a09e667f3bcc908, 64'hbb67ae8584caa73b, 64'h3c6ef372fe94f82b, 64'ha54ff53a5f1d36f1, 64'h510e527fade682d1, 64'h9b05688c2b3e6c1f, 64'h1f83d9abfb41bd6b, 64'h5be0cd19137e2179};

  reg [63:0]  a, b, c, d, e, f, g, h;
  reg [63:0]  W [0:15];
  reg [511:0] hprev;
  reg [7:0]   t;
  reg         fin;
  integer     i;

  function [63:0] rotr(input [63:0] x, input integer n);
    rotr = (x >> n) | (x << (64 - n));
  endfunction

  function [63:0] K(input [6:0] idx);
    case (idx)
      7'd0: K = 64'h428a2f98d728ae22;
      7'd1: K = 64'h7137449123ef65cd;
      7'd2: K = 64'hb5c0fbcfec4d3b2f;
      7'd3: K = 64'he9b5dba58189dbbc;
      7'd4: K = 64'h3956c25bf348b538;
      7'd5: K = 64'h59f111f1b605d019;
      7'd6: K = 64'h923f82a4af194f9b;
      7'd7: K = 64'hab1c5ed5da6d8118;
      7'd8: K = 64'hd807aa98a3030242;
      7'd9: K = 64'h12835b0145706fbe;
      7'd10: K = 64'h243185be4ee4b28c;
      7'd11: K = 64'h550c7dc3d5ffb4e2;
      7'd12: K = 64'h72be5d74f27b896f;
      7'd13: K = 64'h80deb1fe3b1696b1;
      7'd14: K = 64'h9bdc06a725c71235;
      7'd15: K = 64'hc19bf174cf692694;
      7'd16: K = 64'he49b69c19ef14ad2;
      7'd17: K = 64'hefbe4786384f25e3;
      7'd18: K = 64'h0fc19dc68b8cd5b5;
      7'd19: K = 64'h240ca1cc77ac9c65;
      7'd20: K = 64'h2de92c6f592b0275;
      7'd21: K = 64'h4a7484aa6ea6e483;
      7'd22: K = 64'h5cb0a9dcbd41fbd4;
      7'd23: K = 64'h76f988da831153b5;
      7'd24: K = 64'h983e5152ee66dfab;
      7'd25: K = 64'ha831c66d2db43210;
      7'd26: K = 64'hb00327c898fb213f;
      7'd27: K = 64'hbf597fc7beef0ee4;
      7'd28: K = 64'hc6e00bf33da88fc2;
      7'd29: K = 64'hd5a79147930aa725;
      7'd30: K = 64'h06ca6351e003826f;
      7'd31: K = 64'h142929670a0e6e70;
      7'd32: K = 64'h27b70a8546d22ffc;
      7'd33: K = 64'h2e1b21385c26c926;
      7'd34: K = 64'h4d2c6dfc5ac42aed;
      7'd35: K = 64'h53380d139d95b3df;
      7'd36: K = 64'h650a73548baf63de;
      7'd37: K = 64'h766a0abb3c77b2a8;
      7'd38: K = 64'h81c2c92e47edaee6;
      7'd39: K = 64'h92722c851482353b;
      7'd40: K = 64'ha2bfe8a14cf10364;
      7'd41: K = 64'ha81a664bbc423001;
      7'd42: K = 64'hc24b8b70d0f89791;
      7'd43: K = 64'hc76c51a30654be30;
      7'd44: K = 64'hd192e819d6ef5218;
      7'd45: K = 64'hd69906245565a910;
      7'd46: K = 64'hf40e35855771202a;
      7'd47: K = 64'h106aa07032bbd1b8;
      7'd48: K = 64'h19a4c116b8d2d0c8;
      7'd49: K = 64'h1e376c085141ab53;
      7'd50: K = 64'h2748774cdf8eeb99;
      7'd51: K = 64'h34b0bcb5e19b48a8;
      7'd52: K = 64'h391c0cb3c5c95a63;
      7'd53: K = 64'h4ed8aa4ae3418acb;
      7'd54: K = 64'h5b9cca4f7763e373;
      7'd55: K = 64'h682e6ff3d6b2b8a3;
      7'd56: K = 64'h748f82ee5defb2fc;
      7'd57: K = 64'h78a5636f43172f60;
      7'd58: K = 64'h84c87814a1f0ab72;
      7'd59: K = 64'h8cc702081a6439ec;
      7'd60: K = 64'h90befffa23631e28;
      7'd61: K = 64'ha4506cebde82bde9;
      7'd62: K = 64'hbef9a3f7b2c67915;
      7'd63: K = 64'hc67178f2e372532b;
      7'd64: K = 64'hca273eceea26619c;
      7'd65: K = 64'hd186b8c721c0c207;
      7'd66: K = 64'heada7dd6cde0eb1e;
      7'd67: K = 64'hf57d4f7fee6ed178;
      7'd68: K = 64'h06f067aa72176fba;
      7'd69: K = 64'h0a637dc5a2c898a6;
      7'd70: K = 64'h113f9804bef90dae;
      7'd71: K = 64'h1b710b35131c471b;
      7'd72: K = 64'h28db77f523047d84;
      7'd73: K = 64'h32caab7b40c72493;
      7'd74: K = 64'h3c9ebe0a15c9bebc;
      7'd75: K = 64'h431d67c49c100d4c;
      7'd76: K = 64'h4cc5d4becb3e42b6;
      7'd77: K = 64'h597f299cfc657e2a;
      7'd78: K = 64'h5fcb6fab3ad6faec;
      7'd79: K = 64'h6c44198c4a475817;
      default: K = 64'h0;
    endcase
  endfunction

  wire [63:0] w0  = W[0];
  wire [63:0] w1  = W[1];
  wire [63:0] w9  = W[9];
  wire [63:0] w14 = W[14];
  wire [63:0] sg0 = rotr(w1, 1)  ^ rotr(w1, 8)  ^ (w1  >> 7);
  wire [63:0] sg1 = rotr(w14, 19) ^ rotr(w14, 61) ^ (w14 >> 6);
  wire [63:0] wt  = (t < 16) ? w0 : (sg1 + w9 + sg0 + w0);

  wire [63:0] bs1 = rotr(e, 14) ^ rotr(e, 18) ^ rotr(e, 41);
  wire [63:0] ch  = (e & f) ^ (~e & g);
  wire [63:0] t1  = h + bs1 + ch + K(t[6:0]) + wt;
  wire [63:0] bs0 = rotr(a, 28) ^ rotr(a, 34) ^ rotr(a, 39);
  wire [63:0] maj = (a & b) ^ (a & c) ^ (b & c);
  wire [63:0] t2  = bs0 + maj;

  wire [511:0] iv_sel = cont ? digest : IV512;

  always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      busy <= 1'b0; done <= 1'b0; fin <= 1'b0; t <= 8'd0; digest <= 512'd0; hprev <= 512'd0;
      {a,b,c,d,e,f,g,h} <= 512'd0;
    end else begin
      done <= 1'b0;
      if (start && !busy) begin
        busy <= 1'b1; fin <= 1'b0; t <= 8'd0;
        hprev <= iv_sel;
        {a,b,c,d,e,f,g,h} <= iv_sel;
        for (i = 0; i < 16; i = i + 1) W[i] <= block[1023 - 64*i -: 64];
      end else if (busy && !fin) begin
        h <= g; g <= f; f <= e; e <= d + t1;
        d <= c; c <= b; b <= a; a <= t1 + t2;
        for (i = 0; i < 15; i = i + 1) W[i] <= W[i+1];
        W[15] <= wt;
        t <= t + 8'd1;
        if (t == 8'd79) fin <= 1'b1;
      end else if (fin) begin
        digest <= {hprev[511:448] + a, hprev[447:384] + b, hprev[383:320] + c, hprev[319:256] + d,
                   hprev[255:192] + e, hprev[191:128] + f, hprev[127:64]  + g, hprev[63:0]    + h};
        fin <= 1'b0; busy <= 1'b0; done <= 1'b1;
      end
    end
  end
endmodule
