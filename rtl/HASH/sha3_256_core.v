`timescale 1ns/1ps
// Keccak-f[1600] sponge core for SHA-3 (SHA3-224/256/384/512): XORs one rate-sized block into the
// state and runs the 24-round permutation, one round per clock.
//   init = 1 : zero the state before absorbing (first block of a message)
// State byte i is sq[8*i +: 8] (little-endian lanes: lane n = sq[64*n +: 64]).
// The input block is big-endian-ordered: byte 0 is block[1151:1144]; only the first `bs` bytes are used.
module sha3_256_core (
    input  wire          clk,
    input  wire          rst_n,
    input  wire          start,
    input  wire          init,
    input  wire [8:0]    bs,           // rate in bytes (72, 104, 136 or 144)
    input  wire [1151:0] block,
    output reg           busy,
    output reg           done,
    output reg [255:0] digest

);
  reg [4:0] rnd;

  function [63:0] rc(input [4:0] i);
    case (i)
      5'd0: rc = 64'h0000000000000001;
      5'd1: rc = 64'h0000000000008082;
      5'd2: rc = 64'h800000000000808a;
      5'd3: rc = 64'h8000000080008000;
      5'd4: rc = 64'h000000000000808b;
      5'd5: rc = 64'h0000000080000001;
      5'd6: rc = 64'h8000000080008081;
      5'd7: rc = 64'h8000000000008009;
      5'd8: rc = 64'h000000000000008a;
      5'd9: rc = 64'h0000000000000088;
      5'd10: rc = 64'h0000000080008009;
      5'd11: rc = 64'h000000008000000a;
      5'd12: rc = 64'h000000008000808b;
      5'd13: rc = 64'h800000000000008b;
      5'd14: rc = 64'h8000000000008089;
      5'd15: rc = 64'h8000000000008003;
      5'd16: rc = 64'h8000000000008002;
      5'd17: rc = 64'h8000000000000080;
      5'd18: rc = 64'h000000000000800a;
      5'd19: rc = 64'h800000008000000a;
      5'd20: rc = 64'h8000000080008081;
      5'd21: rc = 64'h8000000000008080;
      5'd22: rc = 64'h0000000080000001;
      5'd23: rc = 64'h8000000080008008;
      default: rc = 64'h0;
    endcase
  endfunction

  function [1599:0] round(input [1599:0] s, input [4:0] r);
    reg [63:0] A [0:24];
    reg [63:0] B [0:24];
    reg [63:0] C [0:4];
    reg [63:0] D [0:4];
    integer x, y, n;
    reg [1599:0] o;
    begin
      for (n = 0; n < 25; n = n + 1) A[n] = s[64*n +: 64];
      for (x = 0; x < 5; x = x + 1) C[x] = A[x] ^ A[x+5] ^ A[x+10] ^ A[x+15] ^ A[x+20];
      for (x = 0; x < 5; x = x + 1) D[x] = C[(x+4)%5] ^ {C[(x+1)%5][62:0], C[(x+1)%5][63]};
      for (n = 0; n < 25; n = n + 1) A[n] = A[n] ^ D[n%5];
      B[0] = A[0];
      B[16] = {A[5][27:0], A[5][63:28]};
      B[7] = {A[10][60:0], A[10][63:61]};
      B[23] = {A[15][22:0], A[15][63:23]};
      B[14] = {A[20][45:0], A[20][63:46]};
      B[10] = {A[1][62:0], A[1][63:63]};
      B[1] = {A[6][19:0], A[6][63:20]};
      B[17] = {A[11][53:0], A[11][63:54]};
      B[8] = {A[16][18:0], A[16][63:19]};
      B[24] = {A[21][61:0], A[21][63:62]};
      B[20] = {A[2][1:0], A[2][63:2]};
      B[11] = {A[7][57:0], A[7][63:58]};
      B[2] = {A[12][20:0], A[12][63:21]};
      B[18] = {A[17][48:0], A[17][63:49]};
      B[9] = {A[22][2:0], A[22][63:3]};
      B[5] = {A[3][35:0], A[3][63:36]};
      B[21] = {A[8][8:0], A[8][63:9]};
      B[12] = {A[13][38:0], A[13][63:39]};
      B[3] = {A[18][42:0], A[18][63:43]};
      B[19] = {A[23][7:0], A[23][63:8]};
      B[15] = {A[4][36:0], A[4][63:37]};
      B[6] = {A[9][43:0], A[9][63:44]};
      B[22] = {A[14][24:0], A[14][63:25]};
      B[13] = {A[19][55:0], A[19][63:56]};
      B[4] = {A[24][49:0], A[24][63:50]};
      for (y = 0; y < 5; y = y + 1)
        for (x = 0; x < 5; x = x + 1)
          A[x+5*y] = B[x+5*y] ^ (~B[(x+1)%5+5*y] & B[(x+2)%5+5*y]);
      A[0] = A[0] ^ rc(r);
      for (n = 0; n < 25; n = n + 1) o[64*n +: 64] = A[n];
      round = o;
    end
  endfunction

  // XOR the first bs bytes of the big-endian block into the state
  function [1599:0] absorb(input [1599:0] s, input [1151:0] blk, input [8:0] n_bytes);
    integer i;
    reg [1599:0] o;
    begin
      o = s;
      for (i = 0; i < 144; i = i + 1)
        if (i < n_bytes) o[8*i +: 8] = s[8*i +: 8] ^ blk[1151 - 8*i -: 8];
      absorb = o;
    end
  endfunction
  reg [1599:0] sq;

  
wire [1599:0] final_state;
assign final_state = round(sq, rnd);

always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
        busy   <= 1'b0;
        done   <= 1'b0;
        rnd    <= 5'd0;
        sq     <= 1600'd0;
        digest <= 256'd0;
    end
    else begin
        done <= 1'b0;

        if (start && !busy) begin
            sq <= absorb(init ? 1600'd0 : sq, block, bs);
            rnd <= 5'd0;
            busy <= 1'b1;
        end
        else if (busy) begin
            sq <= final_state;

            if (rnd == 5'd23) begin
                busy <= 1'b0;
                done <= 1'b1;
                begin : rv integer j; for (j=0;j<32;j=j+1) digest[255-8*j -: 8] <= final_state[8*j +: 8]; end
            end
            else begin
                rnd <= rnd + 5'd1;
            end
        end
    end
end

endmodule
