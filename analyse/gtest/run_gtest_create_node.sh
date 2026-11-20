#!/bin/bash
# Builds gtest/test_l1_em_mgr_create_node.cpp against the create_node harness (namespace cnd) under ASan and runs it.
# The test file is written for the official tree (real em_mgr_t / em_t); here the cnd stand-ins are used: the real em_mgr_t
# subclass (REAL_MGR_BEGIN..END) is replaced by a small stand-in subclass and the enumerators by plain numbers.
# usage: ./gtest/run_gtest_create_node.sh [gtest args]
cd "$(dirname "$0")/.."
out=/tmp/gtest_create_node; mkdir -p $out
F="-g -O0 -fpermissive -fsanitize=address -w -I."
sed -E \
 -e 's/#include "em_mgr.h"/#include "create_node.h"/' -e '/#include "em.h"/d' \
 -e '/REAL_MGR_BEGIN/,/REAL_MGR_END/c\
class CreateNodeTestMgr : public cnd::em_mgr_t { public: bool has_node(const char *k) { return has_node_(k); } };' \
 -e 's#/\* HARNESS_SETUP \*/#cnd::g_throw_on_null_dm = true;#' \
 -e 's/\bem_freq_band_24\b/1/g' -e 's/\bem_profile_type_1\b/1/g' -e 's/\bem_service_type_ctrl\b/0/g' \
 -e 's/\b(em_interface_t|em_t|em_mgr_t|dm_easy_mesh_t)\b/cnd::\1/g' \
 gtest/test_l1_em_mgr_create_node.cpp > $out/test_shim.cpp
for f in create_node construct_create_node create_node_test quick_stubs; do
  g++ $F -c $f.cpp -o $out/$f.o || exit 1
done
g++ $F -I. -c $out/test_shim.cpp -o $out/test_shim.o || exit 1
g++ $out/*.o -o $out/gtest_run -fsanitize=address -lgtest -lgtest_main -lpthread -ljansson -lcjson || exit 1
ASAN_OPTIONS=detect_leaks=1 $out/gtest_run "$@"
