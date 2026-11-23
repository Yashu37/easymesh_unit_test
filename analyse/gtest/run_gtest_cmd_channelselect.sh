#!/bin/bash
# Builds gtest/test_l1_cmd_channelselect.cpp against the cmd_channelselect harness (namespace ccs: one device with id 1, one radio 1) under ASan.
# The real controller setup (REAL_SETUP_BEGIN..END) is replaced by the harness's fixed device. The harness header defines the helpers it copies
# (get_table_instance, tr181_*) and so does cmd_channelselect.o, hence --allow-multiple-definition (identical copies).
cd "$(dirname "$0")/.."
out=/tmp/gtest_ccsel; mkdir -p $out
F="-g -O0 -fpermissive -fsanitize=address -w -I."
python3 - > $out/test_shim.cpp <<'P'
import re
s=open('gtest/test_l1_cmd_channelselect.cpp').read()
s=s.replace('#include <sanitizer/lsan_interface.h>\n','')
s=s.replace('#include "em_ctrl.h"','#include "cmd_channelselect.h"')
s=re.sub(r'\b(bus_error_t|bus_data_prop_t|bus_error_invalid_input|bus_error_invalid_method|bus_error_invalid_namespace|em_ctrl_t)\b',r'ccs::\1',s)
s=re.sub(r'/\* REAL_SETUP_BEGIN \*/.*?/\* REAL_SETUP_END \*/','    static void SetUpTestSuite() { static ccs::em_ctrl_t ctrl; memset(&ctrl.m_data_model.dm, 0, sizeof(ctrl.m_data_model.dm)); ccs::ctrl_instance_ptr = &ctrl; dev = "1"; }',s,flags=re.S)
print(s)
P
for f in cmd_channelselect construct_cmd_channelselect cmd_channelselect_test quick_stubs; do g++ $F -c $f.cpp -o $out/$f.o || exit 1; done
g++ $F -c $out/test_shim.cpp -o $out/test_shim.o || exit 1
g++ $out/*.o -o $out/gtest_run -fsanitize=address -Wl,--allow-multiple-definition -lgtest -lgtest_main -lpthread -ljansson -lcjson -lcrypto || exit 1
ASAN_OPTIONS=detect_leaks=0 $out/gtest_run "$@"
