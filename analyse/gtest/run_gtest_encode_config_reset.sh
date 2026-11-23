#!/bin/bash
# Builds the PR #935 encode_config_reset tests (PR935_files/encode_config_reset_tests.inc) against the config_reset harness (namespace ecr) under ASan.
cd "$(dirname "$0")/.."
out=/tmp/gtest_ecr; mkdir -p $out
F="-g -O0 -fpermissive -fsanitize=address -w -I."
{ echo '#include <gtest/gtest.h>'; echo '#include <cstring>'; echo '#include <string>'; echo '#include "config_reset.h"';
  sed -E 's/\b(dm_easy_mesh_t|em_subdoc_info_t|em_interface_t)\b/ecr::\1/g; s/TEST\(ecr::dm_easy_mesh_t,/TEST(dm_easy_mesh_t,/' ${1:-$HOME/Desktop/PR935_files/encode_config_reset_tests.inc}; } > $out/test_shim.cpp
for f in config_reset construct_config_reset config_reset_test quick_stubs; do g++ $F -c $f.cpp -o $out/$f.o || exit 1; done
g++ $F -c $out/test_shim.cpp -o $out/test_shim.o || exit 1
g++ $out/*.o -o $out/gtest_run -fsanitize=address -lgtest -lgtest_main -lpthread -ljansson -lcjson || exit 1
$out/gtest_run
