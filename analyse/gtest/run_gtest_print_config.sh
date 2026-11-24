#!/bin/bash
# Builds the PR #936 print_config tests (PR936_files/print_config_tests.inc) against the print_config harness (namespace pcf) under ASan.
# print_config() logs through em_printfout(); the harness records the lines, so the test's stdout capture is replaced by a join of them.
cd "$(dirname "$0")/.."
out=/tmp/gtest_pcf; mkdir -p $out
F="-g -O0 -fpermissive -fsanitize=address -w -I."
{ echo '#include <gtest/gtest.h>'; echo '#include <cstring>'; echo '#include <memory>'; echo '#include <string>'; echo '#include "print_config.h"';
  echo 'static std::string pcf_joined() { std::string s; for (auto &l : pcf::g_lines) { s += l; s += "\n"; } return s; }';
  sed -E 's/\b(dm_easy_mesh_t|em_channel_scan_cap_radio_t)\b/pcf::\1/g; s/TEST\(pcf::dm_easy_mesh_t,/TEST(dm_easy_mesh_t,/; s/testing::internal::CaptureStdout\(\)/pcf::g_lines.clear()/; s/testing::internal::GetCapturedStdout\(\)/pcf_joined()/' ${1:-$HOME/Desktop/PR936_files/print_config_tests.inc}; } > $out/test_shim.cpp
for f in print_config construct_print_config print_config_test quick_stubs; do g++ $F -c $f.cpp -o $out/$f.o || exit 1; done
g++ $F -c $out/test_shim.cpp -o $out/test_shim.o || exit 1
g++ $out/*.o -o $out/gtest_run -fsanitize=address -lgtest -lgtest_main -lpthread -ljansson -lcjson || exit 1
ASAN_OPTIONS=detect_leaks=0 $out/gtest_run
