`timescale 1ns/1ps
// SHA-256 compression core: one 512-bit (already padded) block per start.
// One round per clock, 64 rounds + 1 finalisation cycle.
module sha256_core (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,
    input  wire         cont,        // 1: continue from the previous chaining value (digest)
    input  wire [511:0] block,
    output reg          busy,
    output reg          done,      // 1-cycle pulse, digest valid
    output reg  [255:0] digest
);
  localparam [255:0] H256 = 256'h6a09e667_bb67ae85_3c6ef372_a54ff53a_510e527f_9b05688c_1f83d9ab_5be0cd19;
  reg  [255:0] hprev;
  wire [255:0] iv_sel = cont ? digest : H256;

  reg [31:0] a, b, c, d, e, f, g, h;
  reg [31:0] W [0:15];
  reg [6:0]  t;
  reg        fin;
  integer    i;

  function [31:0] rotr(input [31:0] x, input integer n);
    rotr = (x >> n) | (x << (32 - n));
  endfunction

  function [31:0] K(input [5:0] idx);
    case (idx)
      6'd0: K = 32'h428a2f98;
      6'd1: K = 32'h71374491;
      6'd2: K = 32'hb5c0fbcf;
      6'd3: K = 32'he9b5dba5;
      6'd4: K = 32'h3956c25b;
      6'd5: K = 32'h59f111f1;
      6'd6: K = 32'h923f82a4;
      6'd7: K = 32'hab1c5ed5;
      6'd8: K = 32'hd807aa98;
      6'd9: K = 32'h12835b01;
      6'd10: K = 32'h243185be;
      6'd11: K = 32'h550c7dc3;
      6'd12: K = 32'h72be5d74;
      6'd13: K = 32'h80deb1fe;
      6'd14: K = 32'h9bdc06a7;
      6'd15: K = 32'hc19bf174;
      6'd16: K = 32'he49b69c1;
      6'd17: K = 32'hefbe4786;
      6'd18: K = 32'h0fc19dc6;
      6'd19: K = 32'h240ca1cc;
      6'd20: K = 32'h2de92c6f;
      6'd21: K = 32'h4a7484aa;
      6'd22: K = 32'h5cb0a9dc;
      6'd23: K = 32'h76f988da;
      6'd24: K = 32'h983e5152;
      6'd25: K = 32'ha831c66d;
      6'd26: K = 32'hb00327c8;
      6'd27: K = 32'hbf597fc7;
      6'd28: K = 32'hc6e00bf3;
      6'd29: K = 32'hd5a79147;
      6'd30: K = 32'h06ca6351;
      6'd31: K = 32'h14292967;
      6'd32: K = 32'h27b70a85;
      6'd33: K = 32'h2e1b2138;
      6'd34: K = 32'h4d2c6dfc;
      6'd35: K = 32'h53380d13;
      6'd36: K = 32'h650a7354;
      6'd37: K = 32'h766a0abb;
      6'd38: K = 32'h81c2c92e;
      6'd39: K = 32'h92722c85;
      6'd40: K = 32'ha2bfe8a1;
      6'd41: K = 32'ha81a664b;
      6'd42: K = 32'hc24b8b70;
      6'd43: K = 32'hc76c51a3;
      6'd44: K = 32'hd192e819;
      6'd45: K = 32'hd6990624;
      6'd46: K = 32'hf40e3585;
      6'd47: K = 32'h106aa070;
      6'd48: K = 32'h19a4c116;
      6'd49: K = 32'h1e376c08;
      6'd50: K = 32'h2748774c;
      6'd51: K = 32'h34b0bcb5;
      6'd52: K = 32'h391c0cb3;
      6'd53: K = 32'h4ed8aa4a;
      6'd54: K = 32'h5b9cca4f;
      6'd55: K = 32'h682e6ff3;
      6'd56: K = 32'h748f82ee;
      6'd57: K = 32'h78a5636f;
      6'd58: K = 32'h84c87814;
      6'd59: K = 32'h8cc70208;
      6'd60: K = 32'h90befffa;
      6'd61: K = 32'ha4506ceb;
      6'd62: K = 32'hbef9a3f7;
      6'd63: K = 32'hc67178f2;
      default: K = 32'h0;
    endcase
  endfunction

  wire [31:0] w0  = W[0];
  wire [31:0] w1  = W[1];
  wire [31:0] w9  = W[9];
  wire [31:0] w14 = W[14];
  wire [31:0] sg0 = rotr(w1, 7)  ^ rotr(w1, 18)  ^ (w1  >> 3);
  wire [31:0] sg1 = rotr(w14, 17) ^ rotr(w14, 19) ^ (w14 >> 10);
  wire [31:0] wt  = (t < 16) ? w0 : (sg1 + w9 + sg0 + w0);

  wire [31:0] bs1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
  wire [31:0] ch  = (e & f) ^ (~e & g);
  wire [31:0] t1  = h + bs1 + ch + K(t[5:0]) + wt;
  wire [31:0] bs0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
  wire [31:0] maj = (a & b) ^ (a & c) ^ (b & c);
  wire [31:0] t2  = bs0 + maj;

  always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      busy <= 1'b0; done <= 1'b0; fin <= 1'b0; t <= 7'd0; digest <= 256'd0; hprev <= 256'd0;
      {a,b,c,d,e,f,g,h} <= 256'd0;
    end else begin
      done <= 1'b0;
      if (start && !busy) begin
        busy <= 1'b1; fin <= 1'b0; t <= 7'd0;
        hprev <= iv_sel;
        {a,b,c,d,e,f,g,h} <= iv_sel;
        for (i = 0; i < 16; i = i + 1) W[i] <= block[511 - 32*i -: 32];
      end else if (busy && !fin) begin
        h <= g; g <= f; f <= e; e <= d + t1;
        d <= c; c <= b; b <= a; a <= t1 + t2;
        for (i = 0; i < 15; i = i + 1) W[i] <= W[i+1];
        W[15] <= wt;
        t <= t + 7'd1;
        if (t == 7'd63) fin <= 1'b1;
      end else if (fin) begin
        digest <= {hprev[255:224] + a, hprev[223:192] + b, hprev[191:160] + c, hprev[159:128] + d,
                   hprev[127:96]  + e, hprev[95:64]   + f, hprev[63:32]   + g, hprev[31:0]    + h};
        fin <= 1'b0; busy <= 1'b0; done <= 1'b1;
      end
    end
  end
endmodule
