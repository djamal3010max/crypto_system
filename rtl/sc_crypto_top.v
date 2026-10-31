`timescale 1ns/1ps
// Smart-Card Cryptographic Subsystem (top level)
//
//   smart-card CPU <--secure bus--> Controller (FSM) <--> Crypto accelerators
//                                       |  |               (HASH, AES, ECC[ECDSA/ECDH/BA-RADIX])
//                                       |  +--secure bus--> Key management unit (key store, certs)
//                                       +---- true random bits <-- TRNG
module sc_crypto_top #(parameter TRNG_DIV = 16, parameter BA_W = 4, parameter BA_SECRET = 0) (
    input  wire         clk,
    input  wire         rst_n_async,   // asynchronous, active low (asserted async, released synchronously inside)
    // smart-card CPU side
    input  wire         cpu_valid,
    output wire         cpu_ready,
    input  wire [7:0]   cpu_cmd,
    input  wire [3:0]   cpu_slot,
    input  wire [255:0] cpu_a,
    input  wire [511:0] cpu_b,
    input  wire [1:0]   cpu_attr,
    output wire         cpu_done,
    output wire         cpu_err,
    output wire         cpu_ok,
    output wire [511:0] cpu_result,
    // analog front-end: comparator output of the thermal-noise source
    input  wire         thermal_noise_in,
    input  wire         trng_alarm_clear,
    output wire         trng_alarm
);
  // reset: asynchronous assert, synchronous release
  wire rst_n;
  reset_sync u_rst (.clk(clk), .rst_n_in(rst_n_async), .rst_n_out(rst_n));

  // controller <-> TRNG
  wire         rng_ack, rng_valid;
  wire [255:0] rng_data;
  // controller <-> accelerators
  wire         acc_start, acc_done, acc_err, acc_ok;
  wire [3:0]   acc_op;
  wire [255:0] acc_a, acc_k;
  wire [511:0] acc_b, acc_result;
  // controller <-> key management (secure bus + direct key port)
  wire         sb_valid, sb_we, sb_ready, sb_err;
  wire [7:0]   sb_addr;
  wire [255:0] sb_wdata, sb_rdata;
  wire [1:0]   sb_attr;
  wire [2:0]   key_sel;
  wire [255:0] key_d0, key_d1;
  wire         key_v0, key_v1;

  controller_fsm u_ctrl (
      .clk(clk), .rst_n(rst_n),
      .cpu_valid(cpu_valid), .cpu_ready(cpu_ready), .cpu_cmd(cpu_cmd), .cpu_slot(cpu_slot),
      .cpu_a(cpu_a), .cpu_b(cpu_b), .cpu_attr(cpu_attr),
      .cpu_done(cpu_done), .cpu_err(cpu_err), .cpu_ok(cpu_ok), .cpu_result(cpu_result),
      .rng_ack(rng_ack), .rng_valid(rng_valid), .rng_data(rng_data), .rng_alarm(trng_alarm),
      .acc_start(acc_start), .acc_op(acc_op), .acc_a(acc_a), .acc_b(acc_b), .acc_k(acc_k),
      .acc_done(acc_done), .acc_err(acc_err), .acc_ok(acc_ok), .acc_result(acc_result),
      .key_sel(key_sel), .key_v0(key_v0), .key_v1(key_v1),
      .sb_valid(sb_valid), .sb_we(sb_we), .sb_addr(sb_addr), .sb_wdata(sb_wdata), .sb_attr(sb_attr),
      .sb_ready(sb_ready), .sb_err(sb_err), .sb_rdata(sb_rdata));

  crypto_accel #(.BA_W(BA_W), .BA_SECRET(BA_SECRET)) u_accel (
      .clk(clk), .rst_n(rst_n), .start(acc_start), .op(acc_op), .a(acc_a), .b(acc_b),
      .k_rand(acc_k), .key0(key_d0), .key1(key_d1),
      .done(acc_done), .err(acc_err), .ok(acc_ok), .result(acc_result));

  key_mgmt_unit u_kmu (
      .clk(clk), .rst_n(rst_n),
      .sb_valid(sb_valid), .sb_we(sb_we), .sb_addr(sb_addr), .sb_wdata(sb_wdata), .sb_attr(sb_attr),
      .sb_ready(sb_ready), .sb_err(sb_err), .sb_rdata(sb_rdata),
      .key_sel(key_sel), .key_d0(key_d0), .key_d1(key_d1), .key_v0(key_v0), .key_v1(key_v1));

  trng #(.DIV(TRNG_DIV)) u_trng (
      .clk(clk), .rst_n(rst_n), .thermal_in(thermal_noise_in), .alarm_clear(trng_alarm_clear),
      .rnd_ack(rng_ack), .rnd_valid(rng_valid), .rnd_data(rng_data), .alarm(trng_alarm));
endmodule

// Two-flop reset synchronizer: async assert, synchronous de-assert.
module reset_sync (
    input  wire clk,
    input  wire rst_n_in,
    output wire rst_n_out
);
  (* async_reg = "true" *) reg [1:0] q;
  always @(posedge clk or negedge rst_n_in) begin
    if (!rst_n_in) q <= 2'b00;
    else           q <= {q[0], 1'b1};
  end
  assign rst_n_out = q[1];
endmodule
