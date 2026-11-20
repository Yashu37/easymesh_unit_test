#!/bin/bash
# Builds gtest/test_l1_analyze_remove_device.cpp against the analyze_remove_device harness (namespace ard) under ASan and runs it.
# The test file is written for the official tree (real em_ctrl_t / data model); here the ard stand-ins are used by qualifying the names.
# usage: ./gtest/run_gtest_remove_device.sh [gtest args]
cd "$(dirname "$0")/.."
out=/tmp/gtest_remove_device; mkdir -p $out
F="-g -O0 -fpermissive -fsanitize=address -w -I."
sed -E \
 -e 's/#include "em_ctrl.h"/#include "analyze_remove_device.h"/' \
 -e 's#/\* HARNESS_SETUP \*/#ard::g_chain = 3;   /* the real em_cmd_remove_device_t has 3 orchestration steps */#' \
 -e 's/\b(em_ctrl_t|dm_easy_mesh_ctrl_t|dm_device_t|em_bus_event_t|em_cmd_t|em_interface_t|em_profile_type_1)\b/ard::\1/g' \
 gtest/test_l1_analyze_remove_device.cpp > $out/test_shim.cpp
for f in analyze_remove_device construct_analyze_remove_device analyze_remove_device_test quick_stubs; do
  g++ $F -c $f.cpp -o $out/$f.o || exit 1
done
g++ $F -I. -c $out/test_shim.cpp -o $out/test_shim.o || exit 1
g++ $out/*.o -o $out/gtest_run -fsanitize=address -lgtest -lgtest_main -lpthread -ljansson -lcjson || exit 1
ASAN_OPTIONS=detect_leaks=0 $out/gtest_run "$@"
