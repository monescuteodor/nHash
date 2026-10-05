#!/usr/bin/env bash
B=/tmp/corehash_bench
echo "############ CoreHash benchmark on i5-2500K (6MB L3, 4C/4T) ############"
echo
echo "===== scratchpad-size sweep (single thread, 4s each) ====="
$B sweep 4
echo
echo "===== thread scaling at 2MB and 4MB (4s each) ====="
for mb in 2 4; do
  echo "--- ${mb}MB scratchpad ---"
  for t in 1 2 3 4; do
    line=$($B bench $t 4 $mb | grep Hashrate)
    printf "  %d thread(s): %s\n" "$t" "$line"
  done
done
echo
echo "===== phase profile (2MB and 4MB) ====="
$B profile 60 2 | grep -E 'mix|total'
$B profile 60 4 | grep -E 'mix|total'
echo
echo "############ done ############"
