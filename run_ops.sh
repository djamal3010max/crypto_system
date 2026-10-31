#!/bin/sh
# Runs the 8 operation testbenches (Icarus Verilog) and prints a summary.
#   sh run_ops.sh            all checks (about 35 minutes: each scalar multiplication is ~1-2M clock cycles)
#   QUICK=1 sh run_ops.sh    skips the slow repeated elliptic-curve cases (about 5 minutes)
#   sh run_ops.sh op3 op8    only the named testbenches
cd "$(dirname "$0")"
python3 tools/gen_vectors.py >/dev/null || exit 1
mkdir -p build_ops && cd build_ops
DEF="-DSIM"; [ -n "$QUICK" ] && DEF="$DEF -DQUICK"
SEL="${*:-op1 op2 op3 op4 op5 op6 op7 op8}"
: > summary.txt
for t in $SEL; do
  f=$(ls ../tb/ops/tb_${t}_*.v) || continue
  n=$(basename "$f" .v)
  iverilog -g2005 $DEF -I../tb/ops -o "$n.out" ../rtl/*.v "$f" || { echo "$n: COMPILE ERROR" >> summary.txt; continue; }
  stdbuf -oL vvp "$n.out" > "$n.log" 2>&1
  grep "^RESULT" "$n.log" >> summary.txt || echo "$n: NO RESULT (timeout or crash)" >> summary.txt
  grep -q "^FAIL\|TIMEOUT" "$n.log" && echo "  -> see build_ops/$n.log" >> summary.txt
done
python3 ../tools/check_vectors.py . >> summary.txt 2>&1
echo; echo "=========== SUMMARY ==========="; cat summary.txt
