#!/bin/bash
# Builds gtest/test_l1_dm_bss_encode.cpp against the dm_bss_encode harness (namespace dbe, real cJSON) under ASan+UBSan.
cd "$(dirname "$0")/.."
out=/tmp/gtest_dbe; mkdir -p $out
F="-g -O0 -fpermissive -fsanitize=address,undefined -w -I."
sed -E -e 's/#include "dm_bss.h"/#include "dm_bss_encode.h"/' \
 -e 's/\b(dm_bss_t|em_bss_info_t|em_haul_type_max)\b/dbe::\1/g' \
 gtest/test_l1_dm_bss_encode.cpp > $out/test_shim.cpp
for f in dm_bss_encode construct_dm_bss_encode dm_bss_encode_test quick_stubs; do g++ $F -c $f.cpp -o $out/$f.o || exit 1; done
g++ $F -c $out/test_shim.cpp -o $out/test_shim.o || exit 1
g++ $out/*.o -o $out/gtest_run -fsanitize=address,undefined -lgtest -lgtest_main -lpthread -ljansson -lcjson || exit 1
$out/gtest_run
