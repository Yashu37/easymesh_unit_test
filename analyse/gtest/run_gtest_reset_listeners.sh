#!/bin/bash
# Builds gtest/test_l1_em_mgr_reset_listeners.cpp against the nodes_listener harness (namespace nls) under ASan+UBSan.
# The official-tree includes/helpers (REAL_*_BEGIN..END) are replaced by stand-ins that build nls::em_t nodes.
cd "$(dirname "$0")/.."
out=/tmp/gtest_reset_listeners; mkdir -p $out
F="-g -O0 -fpermissive -fsanitize=address,undefined -w -I."
python3 - "$1" > $out/test_shim.cpp <<'P'
import re,sys
s=open('gtest/test_l1_em_mgr_reset_listeners.cpp').read()
s=re.sub(r'/\* REAL_INCLUDES_BEGIN \*/.*?/\* REAL_INCLUDES_END \*/','#include "nodes_listener.h"',s,flags=re.S)
h='''struct ResetListenersTestMgr : public nls::em_mgr_t {
    std::vector<nls::em_t *> owned;
    ResetListenersTestMgr() { nls::g_calls = 0; nls::g_len0 = -1; memset((void *)static_cast<nls::em_mgr_t *>(this), 0, sizeof(nls::em_mgr_t)); pthread_mutex_init(&m_mutex, NULL); m_em_map = new nls::hash_map_t; }
    ~ResetListenersTestMgr() { for (auto *e : owned) delete e; delete m_em_map; }
};
static void add_em(ResetListenersTestMgr &mgr, const char *, int fd, bool al)
{ nls::em_t *e = new nls::em_t; e->m_fd = fd; e->m_al = al; mgr.owned.push_back(e); mgr.m_em_map->v.push_back(e); }
static size_t frames_parsed(ResetListenersTestMgr &) { return (size_t)nls::g_calls; }
static long first_frame_len(ResetListenersTestMgr &) { return nls::g_len0; }'''
s=re.sub(r'/\* REAL_HELPERS_BEGIN \*/.*?/\* REAL_HELPERS_END \*/',h,s,flags=re.S)
print(s)
P
# the harness handler with the real select() / read() (the scripted stand-ins are only for the main harness)
sed -e '/^#define select select_stub/d' -e '/^#define read read_stub/d' nodes_listener.cpp > $out/nodes_listener_realio.cpp
g++ $F -I. -c $out/nodes_listener_realio.cpp -o $out/nodes_listener.o || exit 1
for f in construct_nodes_listener nodes_listener_test quick_stubs; do g++ $F -c $f.cpp -o $out/$f.o || exit 1; done
g++ $F -c $out/test_shim.cpp -o $out/test_shim.o || exit 1
g++ $out/*.o -o $out/gtest_run -fsanitize=address,undefined -lgtest -lgtest_main -lpthread -ljansson -lcjson || exit 1
$out/gtest_run
