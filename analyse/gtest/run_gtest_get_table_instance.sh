#!/bin/bash
# Builds gtest/test_l1_get_table_instance.cpp against the cmd_channelselect harness copy of get_table_instance (namespace ccs) under ASan.
# The harness keeps the function in its header, so the shim is the only translation unit that uses it.
cd "$(dirname "$0")/.."
out=/tmp/gtest_gti; mkdir -p $out
F="-g -O0 -fpermissive -fsanitize=address -w -I."
sed -E -e 's/#include "em_ctrl.h"/#include "cmd_channelselect.h"/' -e 's/\bdm_easy_mesh_ctrl_t\b/ccs::dm_easy_mesh_ctrl_t/g' gtest/test_l1_get_table_instance.cpp > $out/test_shim.cpp
g++ $F -c $out/test_shim.cpp -o $out/test_shim.o || exit 1
g++ $F -c quick_stubs.cpp -o $out/quick_stubs.o || exit 1
g++ $out/*.o -o $out/gtest_run -fsanitize=address -lgtest -lgtest_main -lpthread -ljansson -lcjson || exit 1
ASAN_OPTIONS=detect_leaks=1 $out/gtest_run "$@"
