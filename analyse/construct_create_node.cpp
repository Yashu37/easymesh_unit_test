/*
 * TEST CASES / CONSTRUCTOR: construct_create_node
 *
 * ruid = {name "", mac 02:00:00:00:00:aa} lives in ruid_store between CND_GUARD poisoned bytes on each side (the handler
 * writes ruid->name and reads ruid->mac). Fields: null_ruid, is_al, init_rc, ctor_throws, name_found, preexisting,
 * expect (0 NULL / 1 new node / 2 the existing node), expect_map (entries afterwards), expect_key.
 * The case crash_* ABORTS on the original handler: the em_t constructor of the AL node throws std::runtime_error
 * (EC manager init failure) and nothing catches it. It runs last and UNFORKED; FORK_CRASH=1 forks it.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "create_node.h"

namespace cnd {
alignas(16) unsigned char ruid_store[CND_GUARD + sizeof(em_interface_t) + CND_GUARD];

/* {name, null_ruid, is_al, init_rc, ctor_throws, name_found, preexisting, expect, expect_map, expect_key, crash} */
test_case_t suite[] = {
 {"ok_new_node",                      false, false, 0,  false, true,  false, 1, 1, "02:00:00:00:00:aa", false},
 {"ok_new_al_node_key_has_suffix",    false, true,  0,  false, true,  false, 1, 1, "02:00:00:00:00:aa_al", false},
 {"ok_name_not_resolved_still_created", false, false, 0, false, false, false, 1, 1, "02:00:00:00:00:aa", false},
 {"ok_existing_node_returned",        false, false, 0,  false, true,  true,  2, 1, NULL, false},
 {"ok_existing_al_node_returned",     false, true,  0,  false, true,  true,  2, 1, NULL, false},
 {"rej_null_ruid",                    true,  false, 0,  false, true,  false, 0, 0, NULL, false},
 {"rej_null_ruid_al",                 true,  true,  0,  false, true,  false, 0, 0, NULL, false},
 {"rej_init_fails",                   false, false, -1, false, true,  false, 0, 0, NULL, false},
 {"rej_init_fails_al",                false, true,  -1, false, true,  false, 0, 0, NULL, false},
 {"rej_init_fails_does_not_replace_existing", false, false, -1, false, true, true, 2, 1, NULL, false},
 {"ok_ctor_throws_but_not_al",        false, false, 0,  true,  true,  false, 1, 1, "02:00:00:00:00:aa", false},
 /* ---- CRASH case on the original handler: runs last, unforked ---- */
 {"crash_al_ctor_throws_uncaught",    false, true,  0,  true,  true,  false, 0, 0, NULL, true},
 {NULL, false, false, 0, false, false, false, 0, 0, NULL, false}
};

void construct_input(const test_case_t *tc)
{
    memset(ruid_store, 0, sizeof(ruid_store));
    g_ruid = (em_interface_t *)(ruid_store + CND_GUARD);
    unsigned char m[6] = {2, 0, 0, 0, 0, 0xaa}; memcpy(g_ruid->mac, m, 6);
    g_init_rc = tc->init_rc; g_ctor_throws = tc->ctor_throws; g_name_found = tc->name_found; g_ctor_calls = g_init_calls = 0;
    g_mgr = new em_mgr_t;
    if (tc->preexisting) {
        em_t *e = new em_t(g_ruid, 1, NULL, g_mgr, 3, 1, false);
        g_mgr->m_map.push_back({strdup(tc->is_al ? "02:00:00:00:00:aa_al" : "02:00:00:00:00:aa"), e});
    }
    g_ret = NULL;
}

void teardown(void)
{
    for (auto &e : g_mgr->m_map) { free(e.key); delete e.em; }
    delete g_mgr; g_mgr = NULL;
}
} /* namespace cnd */
