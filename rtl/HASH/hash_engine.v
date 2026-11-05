`timescale 1ns/1ps

module hash_engine (
    input  wire         clk,       
    input  wire         rst_n,     
    input  wire         init_cmd,  
    input  wire [1:0]   alg,       
    input  wire         go,        
    input  wire         is_final,  
    input  wire [511:0] msg,       
    input  wire [6:0]   clen,      
    output reg          done,      
    output reg          err,       
    output reg  [511:0] digest,    
    output wire         busy       
);

  localparam [1:0] A_SHA256 = 2'd1,
                   A_SHA512 = 2'd2,
                   A_SHA3   = 2'd3;
  localparam [2:0] S_IDLE  = 3'd0,  
                   S_CHK   = 3'd1,  
                   S_COMP  = 3'd2,  
                   S_CWAIT = 3'd3,  
                   S_PAD   = 3'd4,  
                   S_PAD2  = 3'd5,  
                   S_OUT   = 3'd6;  
  reg [2:0]   st;       
  reg [1:0]   alg_c;    
  reg         inited;   
  reg         first;    
  reg         fin_q;    
  reg         last;     
  reg         pstage; //padding stage  
  reg [8:0]   fill;     
  reg [127:0] total;    

  localparam BW = 1600;
  reg [BW-1:0] buf_r;   

  wire is_sha3 = (alg_c == A_SHA3);
  wire is_512  = (alg_c == A_SHA512);


  wire [8:0] BS   = is_sha3 ? 9'd136 : (is_512 ? 9'd128 : 9'd64);

  wire [8:0] LENB = is_512 ? 9'd16 : 9'd8;

  assign busy = (st != S_IDLE);

  wire [511:0]  msg_m  = msg & ~({512{1'b1}} >> {clen, 3'b000});
  wire [BW-1:0] buf_n  = buf_r | ({msg_m, {(BW-512){1'b0}}} >> {fill, 3'b000});
  wire [8:0]    fill_n = fill + {2'b00, clen};

  wire [BW-1:0] pad80   = {8'h80, {(BW-8){1'b0}}} >> {fill, 3'b000};
  wire [BW-1:0] pad06   = {8'h06, {(BW-8){1'b0}}} >> {fill, 3'b000};
  wire [BW-1:0] padlast = {8'h80, {(BW-8){1'b0}}} >> {(BS - 9'd1), 3'b000};
  wire [11:0]   len_sh  = 12'd1600 - {BS, 3'b000};
  wire [BW-1:0] lenfld  = {{(BW-128){1'b0}}, total} << len_sh;

  reg  c_start;
  wire s256_start = c_start && (alg_c == A_SHA256);
  wire s512_start = c_start && is_512;
  wire kec_start  = c_start && is_sha3;

  wire s256_done, s512_done, kec_done;
  wire s256_busy, s512_busy, kec_busy;
  wire [255:0]  s256_dig;
  wire [511:0]  s512_dig;
  wire [255:0]  kec_dig;

  sha256_core u_s256 (
      .clk(clk), .rst_n(rst_n), .start(s256_start),
      .cont(!first),
      .block(buf_r[BW-1:BW-512]),
      .busy(s256_busy), .done(s256_done), .digest(s256_dig)
  );

  sha512_core u_s512 (
      .clk(clk), .rst_n(rst_n), .start(s512_start),
      .cont(!first),
      .block(buf_r[BW-1:BW-1024]),
      .busy(s512_busy), .done(s512_done), .digest(s512_dig)
  );

  sha3_256_core u_kec (
      .clk(clk), .rst_n(rst_n), .start(kec_start),
      .init(first), .bs(9'd136),
      .block({buf_r[BW-1:BW-1088],64'd0}),
      .busy(kec_busy), .done(kec_done), .digest(kec_dig)
  );

  wire core_done = s256_done | s512_done | kec_done;

  reg [511:0] dig_out;
  always @* begin
    dig_out = 512'd0;
    case (alg_c)
      A_SHA256: dig_out = {s256_dig, 256'd0};
      A_SHA512: dig_out = s512_dig;
      default:  dig_out = {kec_dig, 256'd0};   // SHA3-256
    endcase
  end

  always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      st      <= S_IDLE;
      alg_c   <= 2'd0;
      inited  <= 1'b0;
      first   <= 1'b1;
      fin_q   <= 1'b0;
      last    <= 1'b0;
      pstage  <= 1'b0;
      fill    <= 9'd0;
      total   <= 128'd0;
      buf_r   <= {BW{1'b0}};
      c_start <= 1'b0;
      done    <= 1'b0;
      err     <= 1'b0;
      digest  <= 512'd0;
    end else begin
      done    <= 1'b0;
      c_start <= 1'b0;
      case (st)
        S_IDLE: begin
          if (init_cmd) begin
            if (alg == 2'd0) begin           
              err    <= 1'b1;
              done   <= 1'b1;
              inited <= 1'b0;
            end else begin
              alg_c  <= alg;
              buf_r  <= {BW{1'b0}};
              fill   <= 9'd0;
              total  <= 128'd0;
              inited <= 1'b1;
              first  <= 1'b1;
              pstage <= 1'b0;
              err    <= 1'b0;
              done   <= 1'b1;
            end
          end else if (go) begin
            if (!inited || clen > 7'd64) begin
              err  <= 1'b1;
              done <= 1'b1;
            end else begin
              err   <= 1'b0;
              buf_r <= buf_n;
              fill  <= fill_n;
              total <= total + {121'd0, clen} * 128'd8;
              fin_q <= is_final;
              st    <= S_CHK;
            end
          end
        end
        S_CHK: begin
          if (fill >= BS) begin
            last <= 1'b0;
            st   <= S_COMP;
          end else if (fin_q) begin
            st <= pstage ? S_PAD2 : S_PAD;
          end else begin
            done <= 1'b1;
            st   <= S_IDLE;
          end
        end
        S_COMP: begin
          c_start <= 1'b1;
          st      <= S_CWAIT;
        end
        S_CWAIT: begin
          if (core_done) begin
            first <= 1'b0;
            buf_r <= buf_r << {BS, 3'b000};
            fill  <= fill - BS;
            st    <= last ? S_OUT : S_CHK;
          end
        end
        S_PAD: begin
          if (is_sha3) begin
            buf_r <= buf_r | pad06 | padlast;
            fill  <= BS;
            last  <= 1'b1;
          end else if (fill >= BS - LENB) begin
            buf_r  <= buf_r | pad80;
            fill   <= BS;
            pstage <= 1'b1;
            last   <= 1'b0;
          end else begin
            buf_r <= buf_r | pad80 | lenfld;
            fill  <= BS;
            last  <= 1'b1;
          end
          st <= S_COMP;
        end
        S_PAD2: begin
          buf_r  <= lenfld;
          fill   <= BS;
          pstage <= 1'b0;
          last   <= 1'b1;
          st     <= S_COMP;
        end
        S_OUT: begin
          digest <= dig_out;
          inited <= 1'b0;
          done   <= 1'b1;
          err    <= 1'b0;
          st     <= S_IDLE;
        end
        default: st <= S_IDLE;
      endcase
    end
  end
endmodule
