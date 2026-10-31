`timescale 1ns/1ps

//=============================================================================
// MODULE: hash_engine
// PURPOSE:
//   Top-level controller presenting one streaming interface for three hash
//   functions: SHA-256, SHA-512 and SHA3-256. It collects input bytes, forms
//   algorithm-specific blocks, starts the matching compression core, adds the
//   final padding, and places the digest on a common 512-bit output bus.
//
// SUPPORTED ALGORITHM CODES (`alg`):
//   0 : invalid
//   1 : SHA-256   (64-byte block,  256-bit digest)
//   2 : SHA-512   (128-byte block, 512-bit digest)
//   3 : SHA3-256  (136-byte rate,  256-bit digest)
//
// BASIC TRANSACTION SEQUENCE:
//   1. Pulse `init_cmd` with a valid `alg` to clear the previous message and
//      select the algorithm. `done` pulses when this command is accepted.
//   2. For each message chunk, assert `go`, provide `clen` (0..64 bytes), and
//      put the chunk in the MOST-SIGNIFICANT bytes of `msg`.
//   3. Set `is_final=1` on the final chunk. The engine adds the appropriate
//      padding, processes the final block(s), and updates `digest`.
//   4. `done` pulses when a command finishes. For the final chunk, the digest
//      is valid when `done` pulses.
//   5. `busy` is high whenever the controller is not in S_IDLE.
//
// DATA LAYOUT:
//   - `msg[511:504]` is byte 0, `msg[503:496]` is byte 1, and so on.
//   - `digest[511:504]` is the first digest byte. 256-bit digests are left-
//     aligned; the unused low-order 256 bits are zero.
//=============================================================================
module hash_engine (
    input  wire         clk,       // Rising-edge clock for the controller and hash cores.
    input  wire         rst_n,     // Active-low asynchronous reset.
    input  wire         init_cmd,  // Start a fresh hashing session and select `alg`.
    input  wire [1:0]   alg,       // Algorithm code; sampled when init_cmd is accepted.
    input  wire         go,        // Submit one input chunk; sampled in S_IDLE.
    input  wire         is_final,  // Marks this submitted chunk as the final message chunk.
    input  wire [511:0] msg,       // Up to 64 input bytes, left-aligned in this 512-bit word.
    input  wire [6:0]   clen,      // Number of valid bytes in msg (0 through 64).
    output reg          done,      // One-clock pulse indicating command completion/acceptance.
    output reg          err,       // Error indicator; set for invalid command/algorithm conditions.
    output reg  [511:0] digest,    // Left-aligned digest, zero-padded on the right.
    output wire         busy       // High while the FSM is processing a chunk or final block.
);

  // Algorithm codes
  localparam [1:0] A_SHA256 = 2'd1,
                   A_SHA512 = 2'd2,
                   A_SHA3   = 2'd3;

  // FSM states
  localparam [2:0] S_IDLE  = 3'd0,  // wait for init_cmd or go
                   S_CHK   = 3'd1,  // full block buffered? final? more data?
                   S_COMP  = 3'd2,  // one-cycle start pulse to the core
                   S_CWAIT = 3'd3,  // wait for the core
                   S_PAD   = 3'd4,  // first final padded block
                   S_PAD2  = 3'd5,  // SHA-2 length-only block
                   S_OUT   = 3'd6;  // publish digest

  reg [2:0]   st;       // Current FSM state.
  reg [1:0]   alg_c;    // Latched algorithm for the active session.
  reg         inited;   // 1 only after a valid init_cmd and before final output.
  reg         first;    // 1 until the first block is processed; selects core IV/init.
  reg         fin_q;    // Latched is_final for the submitted chunk.
  reg         last;     // The block being compressed is the final block.
  reg         pstage;   // SHA-2 needs a second block holding the length field.
  reg [8:0]   fill;     // Valid bytes currently stored at the front of buf_r.
  reg [127:0] total;    // Total message length in BITS.

  // Largest block is 136 bytes (SHA3-256 rate); plus one 64-byte chunk = 200
  // bytes = 1600 bits.
  localparam BW = 1600;
  reg [BW-1:0] buf_r;   // Message/padding buffer; valid bytes kept at the MSB end.

  wire is_sha3 = (alg_c == A_SHA3);
  wire is_512  = (alg_c == A_SHA512);

  // Block / rate size in BYTES.
  wire [8:0] BS   = is_sha3 ? 9'd136 : (is_512 ? 9'd128 : 9'd64);
  // SHA-2 length-field size in bytes (64-bit for SHA-256, 128-bit for SHA-512).
  wire [8:0] LENB = is_512 ? 9'd16 : 9'd8;

  assign busy = (st != S_IDLE);

  //-------------------------------------------------------------------------
  // INPUT CHUNK APPENDING (byte granular, MSB-aligned)
  //-------------------------------------------------------------------------
  wire [511:0]  msg_m  = msg & ~({512{1'b1}} >> {clen, 3'b000});
  wire [BW-1:0] buf_n  = buf_r | ({msg_m, {(BW-512){1'b0}}} >> {fill, 3'b000});
  wire [8:0]    fill_n = fill + {2'b00, clen};

  //-------------------------------------------------------------------------
  // PADDING / LENGTH-FIELD HELPERS
  //   SHA-2 : 0x80, zeros, then the message length in bits.
  //   SHA-3 : 0x06 after the message, 0x80 in the last rate byte.
  //-------------------------------------------------------------------------
  wire [BW-1:0] pad80   = {8'h80, {(BW-8){1'b0}}} >> {fill, 3'b000};
  wire [BW-1:0] pad06   = {8'h06, {(BW-8){1'b0}}} >> {fill, 3'b000};
  wire [BW-1:0] padlast = {8'h80, {(BW-8){1'b0}}} >> {(BS - 9'd1), 3'b000};
  wire [11:0]   len_sh  = 12'd1600 - {BS, 3'b000};
  wire [BW-1:0] lenfld  = {{(BW-128){1'b0}}, total} << len_sh;

  //-------------------------------------------------------------------------
  // HASH CORE INTERFACE
  //-------------------------------------------------------------------------
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
      .init(first),
      .block(buf_r[BW-1:BW-1088]),
      .busy(kec_busy), .done(kec_done), .digest(kec_dig)
  );

  wire core_done = s256_done | s512_done | kec_done;

  //-------------------------------------------------------------------------
  // DIGEST FORMATTING: 256-bit digests are left-aligned, low bits cleared.
  //-------------------------------------------------------------------------
  reg [511:0] dig_out;
  always @* begin
    dig_out = 512'd0;
    case (alg_c)
      A_SHA256: dig_out = {s256_dig, 256'd0};
      A_SHA512: dig_out = s512_dig;
      default:  dig_out = {kec_dig, 256'd0};   // SHA3-256
    endcase
  end

  //=========================================================================
  // SEQUENTIAL CONTROLLER
  //=========================================================================
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

        // IDLE: accept a new algorithm/session or one message chunk.
        S_IDLE: begin
          if (init_cmd) begin
            if (alg == 2'd0) begin           // only codes 1..3 are valid
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

        // CHECK BUFFER: full block, more data, or final padding.
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

        // START COMPRESSION: one-cycle start pulse to the chosen core.
        S_COMP: begin
          c_start <= 1'b1;
          st      <= S_CWAIT;
        end

        // WAIT FOR CORE.
        S_CWAIT: begin
          if (core_done) begin
            first <= 1'b0;
            buf_r <= buf_r << {BS, 3'b000};
            fill  <= fill - BS;
            st    <= last ? S_OUT : S_CHK;
          end
        end

        // FIRST FINAL PADDING BLOCK.
        S_PAD: begin
          if (is_sha3) begin
            buf_r <= buf_r | pad06 | padlast;
            fill  <= BS;
            last  <= 1'b1;
          end else if (fill >= BS - LENB) begin
            // SHA-2: no room for marker + length; length goes in S_PAD2.
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

        // SECOND SHA-2 PADDING BLOCK: length field only.
        S_PAD2: begin
          buf_r  <= lenfld;
          fill   <= BS;
          pstage <= 1'b0;
          last   <= 1'b1;
          st     <= S_COMP;
        end

        // OUTPUT: transfer the final digest.
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
