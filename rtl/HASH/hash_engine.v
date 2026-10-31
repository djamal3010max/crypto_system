`timescale 1ns/1ps

//=============================================================================
// MODULE: hash_engine
// PURPOSE:
//   Top-level controller that presents one streaming interface for several
//   SHA-2 and SHA-3 hash variants. It collects input bytes, forms algorithm-
//   specific blocks, starts the appropriate compression core, adds final
//   padding, and places the digest into a common 512-bit output bus.
//
// SUPPORTED ALGORITHM CODES (`alg`):
//   0 : invalid
//   1 : SHA-224
//   2 : SHA-256
//   3 : SHA-384
//   4 : SHA-512
//   5 : SHA3-224
//   6 : SHA3-256
//   7 : SHA3-384
//   8 : SHA3-512
//
// BASIC TRANSACTION SEQUENCE:
//   1. Pulse `init_cmd` with a valid `alg` to clear the previous message and
//      select the algorithm. `done` pulses when this command is accepted.
//   2. For each message chunk, assert `go`, provide `clen` (0..64 bytes), and
//      put the chunk in the MOST-SIGNIFICANT bytes of `msg`.
//   3. Set `is_final=1` on the final chunk. The engine adds the appropriate
//      padding, processes the final block(s), and updates `digest`.
//   4. `done` pulses when a command finishes. For the final chunk, the digest
//      is valid after the final output state has been reached.
//   5. `busy` is high whenever the controller is not in S_IDLE.
//
// DATA LAYOUT:
//   - `msg[511:504]` is byte 0, `msg[503:496]` is byte 1, and so on.
//   - Only the first `clen` bytes, starting at the most-significant end, are
//     appended to the internal buffer.
//   - `digest[511:504]` is the first digest byte. Short digests are left-
//     aligned; all unused low-order bits are zero.
//
// IMPORTANT DESIGN NOTE:
//   This is a wrapper/controller, not the SHA-2/SHA-3 round-function itself.
//   The actual round operations are performed by `sha256_core`, `sha512_core`,
//   and `sha3_256_core`. Those modules must be present and compatible with the
//   ports instantiated below.
//=============================================================================
module hash_engine (
    input  wire         clk,       // Rising-edge clock for the controller and hash cores.
    input  wire         rst_n,     // Active-low asynchronous reset.
    input  wire         init_cmd,  // Start a fresh hashing session and select `alg`.
    input  wire [3:0]   alg,       // Algorithm code; sampled when init_cmd is accepted.
    input  wire         go,        // Submit one input chunk; sampled in S_IDLE.
    input  wire         is_final,  // Marks this submitted chunk as the final message chunk.
    input  wire [511:0] msg,       // Up to 64 input bytes, left-aligned in this 512-bit word.
    input  wire [6:0]   clen,      // Number of valid bytes in msg (0 through 64).
    output reg          done,      // One-clock pulse indicating command completion/acceptance.
    output reg          err,       // Error indicator; set for invalid command/algorithm conditions.
    output reg  [511:0] digest,    // Left-aligned digest, zero-padded on the right.
    output wire         busy       // High while the FSM is processing a chunk or final block.
);

  //-------------------------------------------------------------------------
  // FINITE-STATE MACHINE (FSM)
  //
  // S_IDLE  : Wait for init_cmd or a new chunk (go).
  // S_CHK   : Decide whether a complete hash block is buffered, or whether
  //           the message can return to the caller / needs final padding.
  // S_COMP  : Issue a one-cycle start request to the selected hash core.
  // S_CWAIT : Wait for the selected core to finish its block.
  // S_PAD   : Construct the first final padded block.
  // S_PAD2  : Construct the extra length-only block required by SHA-2 when
  //           the padding marker leaves insufficient room for the length.
  // S_OUT   : Copy the finished digest to the external output and pulse done.
  //
  // The state register is 4 bits wide; seven state encodings are currently used.
  //-------------------------------------------------------------------------
  localparam [3:0] S_IDLE = 4'd0,
                   S_CHK  = 4'd1,
                   S_COMP = 4'd2,
                   S_CWAIT= 4'd3,
                   S_PAD  = 4'd4,
                   S_PAD2 = 4'd5,
                   S_OUT  = 4'd6;

  reg [3:0] st;       // Current FSM state.
  reg [3:0] alg_c;    // Latched algorithm selection for the active session.
  reg       inited;   // 1 only after a valid init_cmd and before final output.
  reg       first;    // 1 until the first data/padding block is processed; selects core IV/init.
  reg       fin_q;    // Latched is_final value for the currently submitted chunk.
  reg       last;     // Marks the block currently being compressed as the final block.
  reg       pstage;   // Records that SHA-2 needs a second block containing the length field.
  reg [8:0] fill;     // Number of valid bytes currently stored at the front of buf_r.
  reg [127:0] total;  // Total message length in BITS, accumulated across all chunks.

  // Maximum block size among these algorithms is 144 bytes (SHA3-224 rate).
  // The buffer is 208 bytes = 1664 bits, allowing a 144-byte rate block plus
  // an incoming 64-byte chunk. This gives the controller room to append a
  // chunk before deciding which full block(s) to process.
  localparam BW = 1664;
  reg [BW-1:0] buf_r; // Message/padding buffer; valid bytes are kept at the MSB end.

  // Algorithm-family helpers:
  //   is_sha3 = true for codes 5..8 (all SHA-3 variants).
  //   is_512  = true for SHA-384 and SHA-512, which use 128-byte SHA-2 blocks
  //             and a 128-bit encoded message length.
  wire is_sha3 = (alg_c >= 4'd5);
  wire is_512  = (alg_c == 4'd3) || (alg_c == 4'd4);

  // Return the compression/rate block size in BYTES for each algorithm.
  // SHA-224/SHA-256 use 64 bytes; SHA-384/SHA-512 use 128 bytes.
  // SHA-3 uses its sponge rate: 144, 136, 104, or 72 bytes depending on digest.
  function [8:0] bs_of(input [3:0] a);
    begin
      case (a)
        4'd1, 4'd2: bs_of = 9'd64;   // SHA-224 / SHA-256
        4'd3, 4'd4: bs_of = 9'd128;  // SHA-384 / SHA-512
        4'd5:       bs_of = 9'd144;  // SHA3-224 rate
        4'd6:       bs_of = 9'd136;  // SHA3-256 rate
        4'd7:       bs_of = 9'd104;  // SHA3-384 rate
        default:    bs_of = 9'd72;   // SHA3-512 rate (and fallback)
      endcase
    end
  endfunction

  // Number of digest bytes to expose. This controls output formatting and
  // is not the same as the compression block/rate size.
  function [6:0] dlen_of(input [3:0] a);
    begin
      case (a)
        4'd1: dlen_of = 7'd28; // SHA-224
        4'd2: dlen_of = 7'd32; // SHA-256
        4'd3: dlen_of = 7'd48; // SHA-384
        4'd4: dlen_of = 7'd64; // SHA-512
        4'd5: dlen_of = 7'd28; // SHA3-224
        4'd6: dlen_of = 7'd32; // SHA3-256
        4'd7: dlen_of = 7'd48; // SHA3-384
        default: dlen_of = 7'd64; // SHA3-512
      endcase
    end
  endfunction

  wire [8:0] BS = bs_of(alg_c); // Active algorithm block size/rate, in bytes.

  // SHA-2 appends an encoded message length at the end of the final block:
  //   SHA-224/256: 8-byte (64-bit) length field.
  //   SHA-384/512: 16-byte (128-bit) length field.
  // SHA-3 does not use this SHA-2 length field; its padding is handled below
  // using the SHA-3 domain-separation byte and the final rate-byte marker.
  wire [8:0] LENB = is_512 ? 9'd16 : 9'd8;

  // busy is a combinational view of the FSM state. In this design the engine
  // is considered idle only in S_IDLE.
  assign busy = (st != S_IDLE);

  //-------------------------------------------------------------------------
  // INPUT CHUNK APPENDING
  //
  // `msg` is MSB-first. `msg_m` masks off all bytes after `clen`; `buf_n`
  // positions the valid bytes immediately after the `fill` bytes already
  // buffered. `fill_n` is the resulting byte count.
  //
  // The buffer uses bit shifts in multiples of 8, so `fill` is a BYTE count,
  // not a bit count. The shift direction follows the MSB-aligned convention.
  //-------------------------------------------------------------------------
  wire [511:0] msg_m = msg & ~({512{1'b1}} >> {clen, 3'b000});
  wire [BW-1:0] buf_n = buf_r | ({msg_m, {(BW-512){1'b0}}} >> {fill, 3'b000});
  wire [8:0] fill_n = fill + {2'b00, clen};

  //-------------------------------------------------------------------------
  // PADDING / LENGTH-FIELD HELPERS
  //
  // SHA-2 padding starts with byte 0x80, followed by zeros, and ends with the
  // original message length in bits. `pad80` inserts 0x80 after the current
  // message bytes. `lenfld` places the 128-bit `total` value at the end of
  // the active SHA-2 block. The shift amount is chosen relative to the 1664-
  // bit top-level buffer width.
  //
  // SHA-3 uses 0x06 as the first padding byte (SHA-3 domain separation) and
  // sets the high bit of the last byte of the rate block (0x80). `pad06`
  // inserts 0x06 after the message and `padlast` marks the last rate byte.
  //-------------------------------------------------------------------------
  wire [BW-1:0] pad80   = {8'h80, {(BW-8){1'b0}}} >> {fill, 3'b000};
  wire [BW-1:0] pad06   = {8'h06, {(BW-8){1'b0}}} >> {fill, 3'b000};
  wire [BW-1:0] padlast = {8'h80, {(BW-8){1'b0}}} >> {(BS - 9'd1), 3'b000};
  wire [11:0] len_sh = 12'd1664 - {BS, 3'b000};
  wire [BW-1:0] lenfld = {{(BW-128){1'b0}}, total} << len_sh;

  //-------------------------------------------------------------------------
  // HASH CORE INTERFACE
  //
  // c_start is generated by the FSM. The individual start signals ensure
  // that only the core matching the selected algorithm receives a start pulse.
  //
  // `first` controls whether the core initializes its internal state (initial
  // vector for SHA-2, initial sponge state for SHA-3) or continues from the
  // previous block's state.
  //-------------------------------------------------------------------------
  reg c_start;
  wire s256_start = c_start && (alg_c == 4'd1 || alg_c == 4'd2);
  wire s512_start = c_start && is_512;
  wire kec_start  = c_start && is_sha3;

  wire s256_done, s512_done, kec_done; // Completion pulses from each core.
  wire s256_busy, s512_busy, kec_busy; // Busy indications (not combined here).
  wire [255:0]  s256_dig;              // 256-bit state/digest from SHA-224/256 core.
  wire [511:0]  s512_dig;              // 512-bit state/digest from SHA-384/512 core.
  wire [1599:0] kec_sq;                // 1600-bit Keccak sponge state returned by SHA-3 core.

  // SHA-224 and SHA-256 share the SHA-256 compression core; iv224 selects
  // the SHA-224 initial vector. `cont` tells it to continue instead of reset.
  sha256_core u_s256 (
      .clk(clk), .rst_n(rst_n), .start(s256_start),
      .cont(!first), .iv224(alg_c == 4'd1),
      .block(buf_r[BW-1:BW-512]),
      .busy(s256_busy), .done(s256_done), .digest(s256_dig)
  );

  // SHA-384 and SHA-512 share the SHA-512 compression core; iv384 selects
  // the SHA-384 initial vector. The core consumes a 1024-bit (128-byte) block.
  sha512_core u_s512 (
      .clk(clk), .rst_n(rst_n), .start(s512_start),
      .cont(!first), .iv384(alg_c == 4'd3),
      .block(buf_r[BW-1:BW-1024]),
      .busy(s512_busy), .done(s512_done), .digest(s512_dig)
  );

  // All SHA-3 variants use the Keccak-f[1600] permutation. The `bs` port tells
  // the core how many bytes of the 1600-bit state form the input rate.
  sha3_256_core u_kec (
      .clk(clk), .rst_n(rst_n), .start(kec_start),
      .init(first), .bs(BS),
      .block(buf_r[BW-1:BW-1152]),
      .busy(kec_busy), .done(kec_done), .sq(kec_sq)
  );

  // Any selected core completing its operation advances the controller.
  wire core_done = s256_done | s512_done | kec_done;

  //-------------------------------------------------------------------------
  // DIGEST FORMATTING
  //
  // The common output is always 512 bits. SHA-224 and SHA-384 are shorter
  // variants, so their valid digest bits are placed at the MSB end and the
  // remaining low bits are cleared. SHA-3 digests are extracted byte-by-byte
  // from the Keccak state. This assumes the core's `kec_sq` byte ordering
  // matches the indexing convention used here.
  //-------------------------------------------------------------------------
  reg [511:0] dig_out;
  integer bi;
  always @* begin
    dig_out = 512'd0; // Default: all unused output bits are zero.
    case (alg_c)
      4'd1: dig_out = {s256_dig[255:32], 288'd0}; // SHA-224: 224 bits.
      4'd2: dig_out = {s256_dig, 256'd0};         // SHA-256: 256 bits.
      4'd3: dig_out = {s512_dig[511:128], 128'd0}; // SHA-384: 384 bits.
      4'd4: dig_out = s512_dig;                    // SHA-512: 512 bits.
      default: begin
        // For SHA-3, copy exactly the requested number of digest bytes.
        // The source byte is selected from `kec_sq`; the destination byte is
        // written from the most-significant end of the common digest bus.
        for (bi = 0; bi < 64; bi = bi + 1)
          if (bi < dlen_of(alg_c))
            dig_out[511 - 8*bi -: 8] = kec_sq[8*bi +: 8];
      end
    endcase
  end

  //=========================================================================
  // SEQUENTIAL CONTROLLER
  //
  // All state/register updates occur on the rising clock edge. Reset is
  // asynchronous and active-low. `done` and `c_start` are cleared by default
  // every active clock, so assignments that set them to 1 create one-cycle
  // pulses (unless a later assignment in the same clocked block overrides it).
  //=========================================================================
  always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      // Reset the FSM and all session bookkeeping.
      st      <= S_IDLE;
      alg_c   <= 4'd0;
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
      // Default pulse outputs low every cycle; individual states assert them
      // when a command is accepted or a result becomes available.
      done    <= 1'b0;
      c_start <= 1'b0;

      case (st)

        //===================================================================
        // IDLE: accept a new algorithm/session or one message chunk.
        //===================================================================
        S_IDLE: begin
          if (init_cmd) begin
            // Reject algorithm code 0 and any code above 8.
            if (alg == 4'd0 || alg > 4'd8) begin
              err    <= 1'b1;
              done   <= 1'b1; // The invalid init command is rejected immediately.
              inited <= 1'b0;
            end else begin
              // Begin a new session: clear buffered bytes and message length,
              // latch the selected algorithm, and mark the next block as first.
              alg_c  <= alg;
              buf_r  <= {BW{1'b0}};
              fill   <= 9'd0;
              total  <= 128'd0;
              inited <= 1'b1;
              first  <= 1'b1;
              pstage <= 1'b0;
              err    <= 1'b0;
              done   <= 1'b1; // init_cmd has been accepted.
            end
          end else if (go) begin
            // A chunk is legal only after init_cmd and may contain at most
            // 64 bytes because `msg` is exactly 512 bits wide.
            if (!inited || clen > 7'd64) begin
              err  <= 1'b1;
              done <= 1'b1; // Reject malformed/uninitialized submission.
            end else begin
              err <= 1'b0;

              // Append the valid bytes to the current buffer.
              buf_r <= buf_n;
              fill  <= fill_n;

              // Keep total message length in BITS, not bytes. The multiplication
              // by 8 converts the current chunk length from bytes to bits.
              total <= total + {121'd0, clen} * 128'd8;

              // Remember whether this chunk closes the message. The FSM uses
              // this registered value after the input handshake cycle.
              fin_q <= is_final;
              st    <= S_CHK;
            end
          end
        end

        //===================================================================
        // CHECK BUFFER: process a full block, return for more data, or pad.
        //===================================================================
        S_CHK: begin
          if (fill >= BS) begin
            // At least one complete block/rate is buffered.
            // `last=0` here means this is not a padding-marked final block.
            last <= 1'b0;
            st   <= S_COMP;
          end else if (fin_q) begin
            // Final chunk received, but fewer than one complete block remains:
            // build final padding. pstage selects the second SHA-2 padding block.
            st <= pstage ? S_PAD2 : S_PAD;
          end else begin
            // No full block is ready and this was not the final chunk.
            // Tell the caller this chunk has been accepted and wait for more.
            done <= 1'b1;
            st   <= S_IDLE;
          end
        end

        //===================================================================
        // START COMPRESSION: issue a one-cycle start pulse to the chosen core.
        //===================================================================
        S_COMP: begin
          c_start <= 1'b1;
          st      <= S_CWAIT;
        end

        //===================================================================
        // WAIT FOR CORE: wait for the selected compression/permutation core.
        //===================================================================
        S_CWAIT: begin
          if (core_done) begin
            // Once the first block is complete, later blocks must continue
            // from the core's accumulated chaining/sponge state.
            first <= 1'b0;

            // Remove the block just consumed by shifting remaining bytes toward
            // the MSB end. Subtract the block/rate size from the buffered count.
            buf_r <= buf_r << {BS, 3'b000};
            fill  <= fill - BS;

            // If the consumed block was marked as final, publish the digest;
            // otherwise check whether another full block is buffered.
            st <= last ? S_OUT : S_CHK;
          end
        end

        //===================================================================
        // FIRST FINAL PADDING BLOCK.
        //===================================================================
        S_PAD: begin
          if (is_sha3) begin
            // SHA-3 padding: XOR/OR the 0x06 suffix after the message and set
            // the final bit (0x80) at the end of the rate block.
            // The core consumes the active rate bytes from the buffer MSB end.
            buf_r <= buf_r | pad06 | padlast;
            fill  <= BS;
            last  <= 1'b1; // This padded rate block is the final block.
          end else if (fill >= BS - LENB) begin
            // SHA-2 special case: there is not enough room for both the 0x80
            // marker and the length field in this block. Process a block with
            // the marker/zeros first, then S_PAD2 will create a length-only block.
            buf_r <= buf_r | pad80;
            fill  <= BS;
            pstage <= 1'b1;
            last   <= 1'b0; // Another block must be compressed before output.
          end else begin
            // SHA-2 normal case: marker and encoded bit length fit in one block.
            buf_r <= buf_r | pad80 | lenfld;
            fill  <= BS;
            last  <= 1'b1; // This block completes the hash.
          end
          st <= S_COMP; // Compress the padded block just constructed.
        end

        //===================================================================
        // SECOND SHA-2 PADDING BLOCK: contains the encoded message length.
        // This state is reached only when the first final block had no room
        // for the length field. The buffer is replaced by lenfld, then hashed.
        //===================================================================
        S_PAD2: begin
          buf_r <= lenfld;
          fill  <= BS;
          pstage <= 1'b0;
          last   <= 1'b1;
          st     <= S_COMP;
        end

        //===================================================================
        // OUTPUT: transfer the final digest to the output register.
        //===================================================================
        S_OUT: begin
          digest <= dig_out; // Capture the combinationally formatted digest.
          inited <= 1'b0;    // Require a new init_cmd before another message.
          done   <= 1'b1;    // Final result is now available.
          err    <= 1'b0;
          st     <= S_IDLE;
        end

        // Defensive recovery for an unexpected state encoding.
        default: st <= S_IDLE;
      endcase
    end
  end
endmodule
