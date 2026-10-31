#!/bin/sh
# Requires Icarus Verilog.  Usage:  ./run_sim.sh [core|all]
#   core : ECC core only vs Python vectors (about 1 minute)
#   all  : full-system regression (about 6-7 minutes, prints progress)
set -e
cd "$(dirname "$0")"
case "${1:-all}" in
  core)
    iverilog -g2005 -o ecc_core.out rtl/modmul_serial.v rtl/ecc_ucode.v rtl/ba_recoder.v rtl/ecc_core.v tb/tb_ecc_core.v
    stdbuf -oL vvp ecc_core.out ;;
  all)
    iverilog -g2005 -DSIM -o sim.out rtl/*.v tb/tb_top.v
    stdbuf -oL vvp sim.out ;;
  *) echo "usage: $0 [core|all]"; exit 1 ;;
esac
