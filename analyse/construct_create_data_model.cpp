/*
 * TEST CASES / CONSTRUCTOR: construct_create_data_model
 *
 * net_id lives in name_store at offset CDM_LEFT (runner poisons the bytes in front of it and past its NUL); al_intf sits in
 * al_store between CDM_GUARD poisoned bytes (mac 02:00:00:00:00:aa). Every data model the handler creates gets its
 * device-info guard (members behind id[]) poisoned by the runner through on_dm_created(). Preconditions (pre):
 *   1 reference dm of net "OneWifiMesh" (ctrl AL mac 02:00:00:00:00:01, 2 network SSIDs) is in the list under its proper key
 *   2 a dm with that network exists, but under a key that does not match its controller AL mac (controller dm "not found")
 *   3 as 1 (also the controller dm used by a colocated agent)
 * Checks: returned dm, entries in the list, flags (bit0 controller, bit1 colocated, bit2 agent id set), network SSIDs copied,
 * whether get_data_model(net_id, al mac) finds the new dm, always 8 policies / 6 channels / device net_id / profile 3.
 * [spec] cases: the key is built in a 64 byte array, so a net_id of 60+ characters is truncated and the new dm cannot be found
 * again (no abort). Cases named crash_* ABORT on the original handler: they run last and UNFORKED so a plain `make` stops
 * with the ASan report / assertion; FORK_CRASH=1 forks each one.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "create_data_model.h"

namespace cdm {
alignas(16) char name_store[CDM_LEFT + CDM_NAME_SZ + CDM_PAD];
alignas(16) unsigned char al_store[CDM_GUARD + sizeof(em_interface_t) + CDM_GUARD];
em_interface_t *g_al = NULL;

#define NET GLOBAL_NET_ID
/* {name, net_id, long_len, al_null, controller, name_found, pre, expect, expect_list, expect_flags, expect_ssids, expect_findable, crash} */
test_case_t suite[] = {
 {"ok_controller_basic",                   NET, 0, false, true,  false, 0, 1, 1, 1, 0, 1, false},
 {"ok_agent_not_colocated",                NET, 0, false, false, false, 0, 1, 1, 4, 0, 1, false},
 {"ok_agent_colocated_no_network",         NET, 0, false, false, true,  0, 1, 1, 6, 0, 1, false},
 {"ok_agent_colocated_with_controller_dm", NET, 0, false, false, true,  3, 1, 2, 6, 2, 1, false},
 {"ok_second_dm_copies_network_ssids",     NET, 0, false, true,  false, 1, 1, 2, 1, 2, 1, false},
 {"ok_reference_dm_not_found_controller",  NET, 0, false, true,  false, 2, 1, 2, 1, 0, 1, false},
 {"ok_reference_dm_not_found_agent",       NET, 0, false, false, false, 2, 1, 2, 4, 0, 1, false},
 {"ok_net_id_empty",                       "",  0, false, true,  false, 0, 1, 1, 1, 0, 1, false},
 {"ok_net_id_one_char",                    "N", 0, false, true,  false, 0, 1, 1, 1, 0, 1, false},
 {"ok_net_id_40_chars_key_fits",           NULL, 40, false, true, false, 0, 1, 1, 1, 0, 1, false},
 {"ok_net_id_127_chars_fits_net_id_field", NULL, 127, false, true, false, 0, 1, 1, 1, 0, -1, false},
 /* ---- [spec]: wrong behaviour, no abort ---- */
 {"spec_key_truncated_net_id_60 [spec]",   NULL, 60, false, true, false, 0, 1, 1, 1, 0, 1, false},
 {"spec_key_truncated_net_id_127 [spec]",  NULL, 127, false, true, false, 0, 1, 1, 1, 0, 1, false},
 /* ---- were CRASH cases on the original handler (NULL args / net_id over 127 chars rejected, missing controller dm skipped) ---- */
 {"rej_net_id_null",                     NULL, 0,   false, true,  false, 0, 0, 0, -1, -1, -1, false},
 {"rej_al_intf_null",                    NET,  0,   true,  true,  false, 0, 0, 0, -1, -1, -1, false},
 {"rej_net_id_300_chars",                NULL, 300, false, true,  false, 0, 0, 0, -1, -1, -1, false},
 {"ok_colocated_agent_controller_dm_missing", NET, 0, false, false, true, 2, 1, 2, 6, 0, 1, false},
 {NULL, NULL, 0, false, false, false, 0, 0, 0, 0, 0, 0, false}
};

static dm_easy_mesh_t *make_ref(const char *key, const char *net, bool with_ssids)
{
    dm_easy_mesh_t *r = new dm_easy_mesh_t; memset((void *)r, 0, sizeof(*r)); g_dms.push_back(r);
    snprintf(r->m_network.m_net_info.id, sizeof(r->m_network.m_net_info.id), "%s", net);
    unsigned char c[6] = {2, 0, 0, 0, 0, 1}; memcpy(r->m_network.m_net_info.ctrl_id.mac, c, 6);
    r->num_ssid = with_ssids ? 2 : 0;
    hash_map_put(g_list->m_list, strdup(key), r);
    return r;
}
void construct_input(const test_case_t *tc)
{
    memset(name_store, 0, sizeof(name_store));
    if (tc->long_len > 0) memset(name_store + CDM_LEFT, 'N', (size_t)tc->long_len);
    else if (tc->net_id) snprintf(name_store + CDM_LEFT, CDM_NAME_SZ, "%s", tc->net_id);
    memset(al_store, 0, sizeof(al_store));
    g_al = (em_interface_t *)(al_store + CDM_GUARD);
    unsigned char m[6] = {2, 0, 0, 0, 0, 0xaa}; memcpy(g_al->mac, m, 6);
    g_name_found = tc->name_found;
    g_list = new dm_easy_mesh_list_t; g_list->m_list = new hash_map_t;
    if (tc->pre == 1 || tc->pre == 3) make_ref(NET "@02:00:00:00:00:01", NET, true);
    if (tc->pre == 2) make_ref("other@ff:ff:ff:ff:ff:ff", NET, false);
    g_ret = NULL;
}
void teardown(void)
{
    for (auto &e : g_list->m_list->v) free(e.first);
    for (dm_easy_mesh_t *d : g_dms) delete d;
    g_dms.clear(); delete g_list->m_list; delete g_list; g_list = NULL;
}
} /* namespace cdm */
