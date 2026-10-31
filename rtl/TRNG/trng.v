`timescale 1ns/1ps
// ---------------------------------------------------------------------------
// Entropy source 1: bank of free-running ring oscillators (jitter).
// Synthesis: odd-length inverter chains with different lengths (keep them!).
// Simulation (-DSIM): behavioral oscillators with random period jitter.
// ---------------------------------------------------------------------------
module ring_osc_bank #(parameter N = 4) (
    input  wire en,
    output wire osc
);
`ifdef SIM
  reg [N-1:0] r;
  integer j;
  initial r = {N{1'b0}};
  genvar gi;
  generate
    for (gi = 0; gi < N; gi = gi + 1) begin : ro
      always begin
        #(3 + gi + ($random & 3));
        if (en) r[gi] = ~r[gi];
      end
    end
  endgenerate
  assign osc = ^r;
`else
  wire [N-1:0] o;
  genvar gi;
  generate
    for (gi = 0; gi < N; gi = gi + 1) begin : ro
      localparam L = 2*gi + 3;                 // odd number of inversions
`ifdef USE_TECH_RO
      // Foundry flow: map to a hard macro / dont_touch inverter cells (tech_ro is
      // a wrapper you write against your PDK cells: odd STAGES chain + NAND enable).
      tech_ro #(.STAGES(L)) u_tech_ro (.en(en), .osc(o[gi]));
`else
      (* keep = "true" *) wire [L-1:0] s;
      genvar gj;
      for (gj = 0; gj < L; gj = gj + 1) begin : stg
        if (gj == 0) begin : first
          assign s[0] = ~(s[L-1] & en);
        end else begin : rest
          assign s[gj] = ~s[gj-1];
        end
      end
      assign o[gi] = s[L-1];
`endif
    end
  endgenerate
  assign osc = ^o;
`endif
endmodule

// ---------------------------------------------------------------------------
// Sampler ("ADC"): 1-bit sampling of ring-oscillator XOR thermal-noise
// comparator every DIV clocks. 2-FF synchronisers (metastability is welcome
// here, but must not propagate).
// ---------------------------------------------------------------------------
module entropy_sampler #(parameter DIV = 16) (
    input  wire clk,
    input  wire rst_n,
    input  wire en,
    input  wire ro_in,
    input  wire thermal_in,
    output reg  raw_bit,
    output reg  raw_valid
);
  reg [1:0] ro_s, th_s;
  reg [15:0] cnt;
  always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      ro_s <= 2'b00; th_s <= 2'b00; cnt <= 16'd0; raw_bit <= 1'b0; raw_valid <= 1'b0;
    end else begin
      ro_s <= {ro_s[0], ro_in};
      th_s <= {th_s[0], thermal_in};
      raw_valid <= 1'b0;
      if (en) begin
        if (cnt == DIV-1) begin
          cnt <= 16'd0;
          raw_bit <= ro_s[1] ^ th_s[1];
          raw_valid <= 1'b1;
        end else cnt <= cnt + 16'd1;
      end
    end
  end
endmodule

// ---------------------------------------------------------------------------
// Health monitor: startup discard + the two continuous tests of NIST SP 800-90B.
//   Repetition Count Test:  CUTOFF = 1 + ceil(20/H); 41 assumes H = 0.5 bit/sample.
//   Adaptive Proportion Test (binary source, window W = 1024): the first sample of a window is the
//     reference; the test fails when the reference value appears APT_CUTOFF times in the window.
//     APT_CUTOFF = 1 + CRITBINOM(W, 2^-H, 1 - 2^-20) = 793 for H = 0.5 (589 for H = 1).
// fail is sticky until reset or clear; good_* carries samples only while no test has failed.
// ---------------------------------------------------------------------------
module health_monitor #(parameter CUTOFF = 41, parameter APT_CUTOFF = 793, parameter APT_W = 1024,
                        parameter STARTUP_N = 64) (
    input  wire clk,
    input  wire rst_n,
    input  wire clear,
    input  wire bit_in,
    input  wire bit_valid,
    output wire fail,
    output reg  rct_fail,
    output reg  apt_fail,
    output reg  good_valid,      // sample passed startup and is usable
    output reg  good_bit
);
  reg        last;
  reg [7:0]  rep;
  reg [15:0] startup_cnt;
  reg        apt_ref;
  reg [10:0] apt_n;             // samples seen in the current window
  reg [10:0] apt_cnt;           // occurrences of the reference value
  assign fail = rct_fail | apt_fail;

  always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      rct_fail <= 1'b0; apt_fail <= 1'b0; good_valid <= 1'b0; good_bit <= 1'b0;
      last <= 1'b0; rep <= 8'd0; startup_cnt <= 16'd0;
      apt_ref <= 1'b0; apt_n <= 11'd0; apt_cnt <= 11'd0;
    end else begin
      good_valid <= 1'b0;
      if (clear) begin
        rct_fail <= 1'b0; apt_fail <= 1'b0; rep <= 8'd0; startup_cnt <= 16'd0; apt_n <= 11'd0; apt_cnt <= 11'd0;
      end else if (bit_valid) begin
        if (startup_cnt < STARTUP_N) begin
          startup_cnt <= startup_cnt + 16'd1;
          last <= bit_in; rep <= 8'd1; apt_n <= 11'd0; apt_cnt <= 11'd0;
        end else begin
          // ---- repetition count test ----
          if (bit_in == last) begin
            rep <= rep + 8'd1;
            if (rep + 8'd1 >= CUTOFF) rct_fail <= 1'b1;
          end else begin
            rep <= 8'd1; last <= bit_in;
          end
          // ---- adaptive proportion test ----
          if (apt_n == 11'd0) begin                       // first sample of a window: new reference
            apt_ref <= bit_in; apt_cnt <= 11'd1; apt_n <= 11'd1;
          end else begin
            if (bit_in == apt_ref) begin
              apt_cnt <= apt_cnt + 11'd1;
              if (apt_cnt + 11'd1 >= APT_CUTOFF) apt_fail <= 1'b1;
            end
            apt_n <= (apt_n == APT_W - 1) ? 11'd0 : apt_n + 11'd1;
          end
          if (!rct_fail && !apt_fail) begin good_valid <= 1'b1; good_bit <= bit_in; end
        end
      end
    end
  end
endmodule

// ---------------------------------------------------------------------------
// von Neumann corrector: looks at non-overlapping pairs of healthy raw bits, drops 00 and 11 and
// outputs one bit per unequal pair (01 -> 0, 10 -> 1). Removes bias if the raw bits are independent;
// at most one output bit per four input bits on average (exactly 2pq per pair).
// ---------------------------------------------------------------------------
module von_neumann (
    input  wire clk,
    input  wire rst_n,
    input  wire flush,           // drop a half-collected pair (health failure / restart)
    input  wire in_valid,
    input  wire in_bit,
    output reg  out_valid,
    output reg  out_bit
);
  reg have_first, first;
  always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin have_first <= 1'b0; first <= 1'b0; out_valid <= 1'b0; out_bit <= 1'b0; end
    else begin
      out_valid <= 1'b0;
      if (flush) have_first <= 1'b0;
      else if (in_valid) begin
        if (!have_first) begin first <= in_bit; have_first <= 1'b1; end
        else begin
          have_first <= 1'b0;
          if (first != in_bit) begin out_valid <= 1'b1; out_bit <= first; end
        end
      end
    end
  end
endmodule

// ---------------------------------------------------------------------------
// Post-processing: collect 512 healthy raw bits, condition with SHA-256
// ("cryptographic hash") -> 256 bits.
// ---------------------------------------------------------------------------
module trng_post_process (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         space,        // output buffer empty
    input  wire         in_valid,
    input  wire         in_bit,
    output wire         collecting,   // asks sampler side to keep feeding
    output reg          out_valid,
    output reg  [255:0] out_data
);
  reg [511:0] acc;
  reg [9:0]   cnt;
  reg         hashing, go;
  wire        h_busy, h_done;
  wire [255:0] dig;

  assign collecting = space && !hashing && !go;

  sha256_core u_cond (.clk(clk), .rst_n(rst_n), .start(go), .cont(1'b0), .iv224(1'b0), .block(acc),
                      .busy(h_busy), .done(h_done), .digest(dig));

  always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      acc <= 512'd0; cnt <= 10'd0; hashing <= 1'b0; go <= 1'b0;
      out_valid <= 1'b0; out_data <= 256'd0;
    end else begin
      go <= 1'b0; out_valid <= 1'b0;
      if (collecting && in_valid) begin
        acc <= {acc[510:0], in_bit};
        if (cnt == 10'd511) begin cnt <= 10'd0; go <= 1'b1; hashing <= 1'b1; end
        else cnt <= cnt + 10'd1;
      end
      if (h_done) begin
        hashing <= 1'b0; out_valid <= 1'b1; out_data <= dig;
      end
    end
  end
endmodule

// ---------------------------------------------------------------------------
// Output buffer: single 256-bit word, cleared on ack or alarm.
// ---------------------------------------------------------------------------
module trng_output_buffer (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         flush,
    input  wire         in_valid,
    input  wire [255:0] in_data,
    input  wire         ack,
    output reg          valid,
    output reg  [255:0] data
);
  always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin valid <= 1'b0; data <= 256'd0; end
    else if (flush) begin valid <= 1'b0; data <= 256'd0; end
    else if (in_valid && !valid) begin valid <= 1'b1; data <= in_data; end
    else if (ack) begin valid <= 1'b0; data <= 256'd0; end
  end
endmodule

// ---------------------------------------------------------------------------
// Randomness unit (TRNG)
// ---------------------------------------------------------------------------
module trng #(parameter DIV = 16, parameter N_RO = 4) (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         thermal_in,   // comparator output of the thermal-noise source
    input  wire         alarm_clear,
    input  wire         rnd_ack,
    output wire         rnd_valid,
    output wire [255:0] rnd_data,
    output wire         alarm
);
  wire osc, raw_bit, raw_valid, good_valid, good_bit, pp_valid, collecting, vn_valid, vn_bit;
  wire [255:0] pp_data;

  ring_osc_bank #(.N(N_RO)) u_ro (.en(1'b1), .osc(osc));

  entropy_sampler #(.DIV(DIV)) u_samp (
      .clk(clk), .rst_n(rst_n), .en(1'b1), .ro_in(osc), .thermal_in(thermal_in),
      .raw_bit(raw_bit), .raw_valid(raw_valid));

  wire rct_fail_w, apt_fail_w;                       // kept as named nets so the individual tests can be observed
  health_monitor u_health (
      .clk(clk), .rst_n(rst_n), .clear(alarm_clear), .bit_in(raw_bit), .bit_valid(raw_valid),
      .fail(alarm), .rct_fail(rct_fail_w), .apt_fail(apt_fail_w), .good_valid(good_valid), .good_bit(good_bit));

  // post-processing stage 1: von Neumann corrector (bias removal), stage 2: SHA-256 conditioner
  von_neumann u_vn (.clk(clk), .rst_n(rst_n), .flush(alarm | !collecting), .in_valid(good_valid && collecting),
                    .in_bit(good_bit), .out_valid(vn_valid), .out_bit(vn_bit));

  trng_post_process u_pp (
      .clk(clk), .rst_n(rst_n), .space(!rnd_valid && !alarm),
      .in_valid(vn_valid), .in_bit(vn_bit), .collecting(collecting),
      .out_valid(pp_valid), .out_data(pp_data));

  trng_output_buffer u_buf (
      .clk(clk), .rst_n(rst_n), .flush(alarm), .in_valid(pp_valid && !alarm), .in_data(pp_data),
      .ack(rnd_ack), .valid(rnd_valid), .data(rnd_data));
endmodule
