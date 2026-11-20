#!/bin/bash
# Builds the PR #924 string_to_macbytes tests (PR924_files/string_to_macbytes_tests.inc) against the stm harness under ASan+UBSan.
cd "$(dirname "$0")/.."
out=/tmp/gtest_stm; mkdir -p $out
F="-g -O0 -fpermissive -fsanitize=address,undefined -w -I."
{ echo '#include <gtest/gtest.h>'; echo '#include <cstring>'; echo '#include "string_to_macbytes.h"';
  sed -E 's/\b(dm_easy_mesh_t)\b/stm::\1/g; s/\bmac_address_t\b/stm::mac_address_t/g; s/TEST\(stm::dm_easy_mesh_t,/TEST(dm_easy_mesh_t,/' ${1:-$HOME/Desktop/PR924_files/string_to_macbytes_tests.inc}; } > $out/test_shim.cpp
for f in string_to_macbytes construct_string_to_macbytes string_to_macbytes_test quick_stubs; do g++ $F -c $f.cpp -o $out/$f.o || exit 1; done
g++ $F -c $out/test_shim.cpp -o $out/test_shim.o || exit 1
g++ $out/*.o -o $out/gtest_run -fsanitize=address,undefined -lgtest -lgtest_main -lpthread -ljansson -lcjson || exit 1
$out/gtest_run
