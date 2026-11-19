/*
 * TEST CASES / CONSTRUCTOR: construct_print_config
 *
 * One dm_easy_mesh_t per case on the heap between poisoned guards: SSID i "ssid<i>", BSS / radio MACs 02:00:00:00:00:xx, radio 0 gets the
 * channel scan capability: op_classes_num entries, entry k has op_class 115 + k and oc_num channels (entry 63 may be overridden with
 * last_oc_num), channel values by fill (0: 1..64, 1: 100 + i, 2: 36 + 4i). PASS = number of printed lines (4 + SSIDs + BSSs + 6 per radio
 * + op classes of radio 0) and, when requested, the channel list of the first op class. Cases named crash_* ABORT on the original code
 * (net SSID / BSS / radio / op class counts above the array sizes, an op class num above 64 on the last entry): they run last and
 * UNFORKED so a plain `make` stops with the report; FORK_CRASH=1 forks each one. [spec] cases: wrong behaviour, no abort.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "print_config.h"

namespace pcf {
/* {name, ssids, bss, radios, op_classes_num, oc_num, last_oc_num, fill, expect_lines(unused, always computed), expect_ch_line, crash} */
test_case_t suite[] = {
 {"ok_empty_model",                       0, 0, 0, 0, 0, -1, 0, -2, NULL, false},
 {"ok_one_ssid",                          1, 0, 0, 0, 0, -1, 0, -2, NULL, false},
 {"ok_five_ssids_max",                    5, 0, 0, 0, 0, -1, 0, -2, NULL, false},
 {"ok_24_bss_max",                        0, 24, 0, 0, 0, -1, 0, -2, NULL, false},
 {"ok_three_radios_max",                  0, 0, 3, 0, 0, -1, 0, -2, NULL, false},
 {"ok_two_op_classes",                    0, 0, 1, 2, 3, -1, 2, -2, "channels=[36 40 44 ]", false},
 {"ok_op_class_num_zero_prints_all",      0, 0, 1, 1, 0, -1, 2, -2, "channels=[all]", false},
 {"ok_64_op_classes_max",                 0, 0, 1, 64, 3, -1, 2, -2, "channels=[36 40 44 ]", false},
 {"ok_64_two_digit_channels",             0, 0, 1, 1, 64, -1, 0, -2, "channels=[1 2 3 4 5 ", false},
 {"ok_everything_at_max",                 5, 24, 3, 64, 64, 64, 0, -2, NULL, false},
 /* ---- [spec]: wrong behaviour, no abort ---- */
 {"spec_64_three_digit_channels_list_must_not_be_truncated [spec]", 0, 0, 1, 1, 64, -1, 1, -2, "163 ]", false},
 /* ---- CRASH cases on the original code: run last, unforked ---- */
 {"crash_six_net_ssids",                  6, 0, 0, 0, 0, -1, 0, -2, NULL, true},
 {"crash_25_bss",                         0, 25, 0, 0, 0, -1, 0, -2, NULL, true},
 {"crash_four_radios",                    0, 0, 4, 0, 0, -1, 0, -2, NULL, true},
 {"crash_65_op_classes",                  0, 0, 1, 65, 3, -1, 2, -2, NULL, true},
 {"crash_last_op_class_num_255",          0, 0, 1, 64, 3, 255, 0, -2, NULL, true},
 {NULL, 0, 0, 0, 0, 0, 0, 0, 0, NULL, false}
};

void construct_input(const test_case_t *tc)
{
    g_box = (box_t *)calloc(1, sizeof(box_t));
    dm_easy_mesh_t *d = &g_box->dm;
    snprintf(d->m_network.m_net_info.id, sizeof(d->m_network.m_net_info.id), "net1");
    d->m_num_net_ssids = tc->num_ssids; d->m_num_bss = tc->num_bss; d->m_num_radios = tc->num_radios; d->m_num_opclass = 0;
    for (int i = 0; i < EM_MAX_NET_SSIDS; i++) snprintf(d->m_network_ssid[i].m_network_ssid_info.ssid, sizeof(d->m_network_ssid[i].m_network_ssid_info.ssid), "ssid%d", i);
    for (int i = 0; i < EM_MAX_BSSS; i++) { unsigned char m[6] = {2,0,0,0,1,(unsigned char)i}; memcpy(d->m_bss[i].info.ruid.mac, m, 6); memcpy(d->m_bss[i].info.bssid.mac, m, 6); }
    for (int i = 0; i < EM_MAX_BANDS; i++) {
        unsigned char m[6] = {2,0,0,0,2,(unsigned char)i}; memcpy(d->m_radio[i].info.intf.mac, m, 6); d->m_radio[i].info.band = i; d->m_radio[i].info.transmit_power_limit = 20;
        memcpy(d->m_radio_cap[i].info.ruid.mac, m, 6);
    }
    em_channel_scan_cap_radio_t *cs = &d->m_radio_cap[0].info.ch_scan;
    cs->op_classes_num = (unsigned char)tc->op_classes_num;
    int n = tc->op_classes_num > EM_MAX_OPCLASS ? EM_MAX_OPCLASS : (int)tc->op_classes_num;
    for (int k = 0; k < EM_MAX_OPCLASS; k++) {
        cs->op_classes[k].op_class = (unsigned char)(115 + k);
        cs->op_classes[k].num = (unsigned char)((k < n || tc->last_oc_num >= 0) ? tc->oc_num : 0);
        for (int i = 0; i < EM_MAX_CHANNELS_IN_LIST; i++)
            cs->op_classes[k].channels.channel[i] = (unsigned char)(tc->fill == 0 ? i + 1 : tc->fill == 1 ? 100 + i : 36 + 4 * i);
    }
    if (tc->last_oc_num >= 0) cs->op_classes[63].num = (unsigned char)tc->last_oc_num;
    g_lines.clear();
}
void teardown(void) { free(g_box); g_box = NULL; g_lines.clear(); }
} /* namespace pcf */
