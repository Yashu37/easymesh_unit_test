#!/bin/bash
# Builds gtest/test_l1_stamld_tget_params.cpp against the stamld_tget_params harness (namespace smt) under ASan and runs it.
# The test file is written for the official tree (real em_ctrl_t / data model); here the smt stand-ins are used by qualifying the names.
# usage: ./gtest/run_gtest_stamld.sh [gtest args]
cd "$(dirname "$0")/.."
out=/tmp/gtest_stamld; mkdir -p $out
F="-g -O0 -fpermissive -fsanitize=address -w -I."
sed -E \
 -e 's/#include "em_ctrl.h"/#include "stamld_tget_params.h"/' \
 -e 's/\b(em_ctrl_t|dm_easy_mesh_t|dm_easy_mesh_ctrl_t|em_ap_mld_info_t|em_assoc_sta_mld_info_t|bus_data_prop_t|bus_error_t|bus_error_success|bus_error_invalid_input|bus_data_type_string)\b/smt::\1/g' \
 gtest/test_l1_stamld_tget_params.cpp > $out/test_shim.cpp
for f in stamld_tget_params construct_stamld_tget_params stamld_tget_params_test quick_stubs; do
  g++ $F -c $f.cpp -o $out/$f.o || exit 1
done
g++ $F -I. -c $out/test_shim.cpp -o $out/test_shim.o || exit 1
g++ $out/*.o -o $out/gtest_run -fsanitize=address -lgtest -lgtest_main -lpthread -ljansson -lcjson || exit 1
ASAN_OPTIONS=detect_leaks=1 $out/gtest_run "$@"
