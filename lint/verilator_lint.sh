#!/bin/sh
# Verilator lint of the synthesizable RTL (needs Verilator 5). Expect these known, intentional findings:
#   UNOPTFLAT   ring-oscillator inverter chains in trng.v (replace with a hard macro: USE_TECH_RO)
#   BLKSEQ      keccak_core round() function locals (blocking assignments to function variables)
#   WIDTHEXPAND comparisons of narrow counters with loop integers in the mux/demux loops
#   SYNCASYNCNET rst_n is used as an async reset in some modules and as a synchronous reset in others
#   UNUSED*     status outputs and spare localparams
cd "$(dirname "$0")/.."
verilator --lint-only -Wall --top-module sc_crypto_top rtl/*.v "$@"
