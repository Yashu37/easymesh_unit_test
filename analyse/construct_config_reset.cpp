/*
 * TEST CASES / CONSTRUCTOR: construct_config_reset
 *
 * One dm_easy_mesh_t per case on the heap between poisoned guards: interface i has MAC 02:00:00:00:00:(i+1) and name "eth<i>"
 * (name_mode 1: the first name fills all 32 bytes with 'N', name_mode 2: the whole interface array is filled with 'A'), SSID i is
 * "ssid<i>", the network id is "net1". PASS = return value, number of entries in Interfaces.List and NetworkSSIDList, the first
 * interface string and, when requested, that subdoc->buff holds complete JSON.
 * Cases named clamp_* ABORTED on the original code (net SSID count above 5 read past m_network_ssid[5], an interface array without NUL
 * terminators made snprintf("%s") run on to the guard): fix 1 clamps the SSID count, fix 2 bounds the name with %.*s. [spec] cases: wrong behaviour, no abort.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "config_reset.h"

namespace ecr {
/* {name, num_ifaces, name_mode, num_ssids, key, null_subdoc, ret, ifaces, ssids, iface0, parse, crash} */
test_case_t suite[] = {
 {"ok_empty_model",                     0, 0, 0, "dm", false, 0, 0, 0, NULL, 1, false},
 {"ok_one_interface",                   1, 0, 0, "dm", false, 0, 1, 0, "02:00:00:00:00:01 (eth0)", 1, false},
 {"ok_eight_interfaces",                8, 0, 0, "dm", false, 0, 8, 0, "02:00:00:00:00:01 (eth0)", 1, false},
 {"ok_nine_interfaces_capped_at_eight", 9, 0, 0, "dm", false, 0, 8, 0, NULL, 1, false},
 {"ok_one_ssid",                        0, 0, 1, "dm", false, 0, 0, 1, NULL, 1, false},
 {"ok_five_ssids_max",                  3, 0, 5, "dm", false, 0, 3, 5, NULL, 1, false},
 {"ok_null_key_rejected",               1, 0, 1, NULL, false, -1, -1, -1, NULL, 0, false},
 {"ok_empty_key_rejected",              1, 0, 1, "", false, -1, -1, -1, NULL, 0, false},
 {"ok_null_subdoc_rejected",            1, 0, 1, "dm", true, -1, -1, -1, NULL, 0, false},
 {"ok_key_3000_chars",                  1, 0, 1, "#3000", false, 0, 1, 1, NULL, 1, false},
 /* ---- [spec]: wrong behaviour, no abort ---- */
 {"spec_oversized_output_must_not_be_truncated [spec]",     1, 0, 1, "#5000", false, 0, 1, 1, NULL, 1, false},
 {"clamp_interface_name_32_chars_no_nul_must_not_read_on", 1, 1, 0, "dm", false, 0, 1, 0, "02:00:00:00:00:01 (NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN)", 1, false},
 /* ---- were CRASH cases on the original code ---- */
 {"clamp_six_ssids_read_past_array",    0, 0, 6, "dm", false, 0, 0, 5, NULL, 1, false},
 {"clamp_hundred_ssids",                0, 0, 100, "dm", false, 0, 0, 5, NULL, 1, false},
 {"clamp_million_ssids",                0, 0, 1000000, "dm", false, 0, 0, 5, NULL, 1, false},
 {"clamp_interface_array_without_nul",  8, 2, 0, "dm", false, 0, 8, 0, NULL, 1, false},
 {NULL, 0, 0, 0, NULL, false, 0, 0, 0, NULL, 0, false}
};

void construct_input(const test_case_t *tc)
{
    g_box = (box_t *)calloc(1, sizeof(box_t));
    dm_easy_mesh_t *d = &g_box->dm;
    d->m_num_interfaces = tc->num_ifaces; d->m_num_net_ssids = tc->num_ssids;
    for (int i = 0; i < EM_MAX_INTERFACES; i++) {
        unsigned char m[6] = {2,0,0,0,0,(unsigned char)(i + 1)}; memcpy(d->m_interfaces[i].mac, m, 6);
        snprintf(d->m_interfaces[i].name, sizeof(d->m_interfaces[i].name), "eth%d", i);
    }
    if (tc->name_mode == 1) memset(d->m_interfaces[0].name, 'N', sizeof(d->m_interfaces[0].name));
    if (tc->name_mode == 2) memset(d->m_interfaces, 'A', sizeof(d->m_interfaces));
    snprintf(d->m_network.id, sizeof(d->m_network.id), "net1");
    for (int i = 0; i < EM_MAX_NET_SSIDS; i++) snprintf(d->m_network_ssid[i].ssid, sizeof(d->m_network_ssid[i].ssid), "ssid%d", i);
}
void teardown(void) { free(g_box); g_box = NULL; }
} /* namespace ecr */
