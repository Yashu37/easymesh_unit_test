#!/bin/bash
# Quick build + run of ONE unified-wifi-mesh harness (seconds, not the 10-min full make).
# usage: ./quick.sh <function>      e.g. ./quick.sh cmd_beaconmetricsquery
#        ./quick.sh cmd_beaconmetricsquery crash    (show only the crash reports)
fn=$1
[ -z "$fn" ] && { echo "usage: $0 <function> [crash]"; exit 1; }
cd "$(dirname "$0")"
out=/tmp/quick_$fn; mkdir -p $out
F="-g -O0 -fpermissive -fsanitize=address -w -I."
for f in $fn construct_$fn ${fn}_test quick_stubs; do
  g++ $F -c $f.cpp -o $out/$f.o || exit 1
done
printf "void run_all_tests_$fn();\nint main(){run_all_tests_$fn();return 0;}\n" > $out/main.cpp
g++ $F -c $out/main.cpp -o $out/main.o
g++ $out/*.o -o $out/run -fsanitize=address -ljansson -lcjson || exit 1
if [ "$2" = "crash" ]; then
  FORK_CRASH=1 ASAN_OPTIONS=detect_leaks=0 $out/run 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | grep -E "Running Test: crash|ERROR: AddressSanitizer|SUMMARY|^    #[0-4] |CRASH CONFIRMED|pass,"
else
  ASAN_OPTIONS=detect_leaks=0 $out/run 2>&1
fi
