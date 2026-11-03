/*
 * TEST CASES / CONSTRUCTOR: construct_monitor_enable_instant_msmt
 *
 * The query MAC lives in men_mac_buf (runner poisons past its 6 bytes). The
 * wifi_mgr stand-in (men_mgr_buf) has radio_presence[0]=true. g_harvester_module
 * holds inst_msmt.active / sta_mac. men_found_vap is the vap index at which the
 * stubbed is_harvester_device_associated returns true.
 *
 * Cases: stop_match (active + !enable + mac matches -> stop), active_enable
 * (active + enable -> just return), active_nomatch (active + !enable + other
 * mac -> return, no stop), found_start (inactive + sta found -> start),
 * notfound (inactive + not found -> nothing).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

alignas(16) char men_mgr_buf[sizeof(wifi_mgr_t) + MEN_PAD];
unsigned char men_mac_buf[6 + MEN_PAD];
int men_num_vaps, men_found_vap, men_assoc_checks, men_start_calls, men_stop_calls;

em_men_test_case_t monitor_enable_instant_msmt_suite[] = {
    /* name           active enable mac_match found_vap want_start want_stop */
    { "stop_match",     1,    0,     1,        -1,       0,         1 },
    { "active_enable",  1,    1,     0,        -1,       0,         0 },
    { "active_nomatch", 1,    0,     0,        -1,       0,         0 },
    { "found_start",    0,    1,     0,         1,       1,         0 },
    { "notfound",       0,    1,     0,        -1,       0,         0 },
    { NULL, 0, 0, 0, 0, 0, 0 }  /* sentinel */
};

void construct_monitor_enable_instant_msmt_input(const em_men_test_case_t *tc)
{
    memset(&g_harvester_module, 0, sizeof(g_harvester_module));
    memset(men_mgr_buf, 0, sizeof(men_mgr_buf));
    memset(men_mac_buf, 0, sizeof(men_mac_buf));
    men_assoc_checks = men_start_calls = men_stop_calls = 0;

    unsigned char qmac[6] = {0x30,0x31,0x32,0x33,0x34,0x35};
    memcpy(men_mac_buf, qmac, 6);

    g_harvester_module.inst_msmt.active = tc->active ? true : false;
    /* the active sta_mac: matches the query only when mac_match */
    if (tc->mac_match) memcpy(g_harvester_module.inst_msmt.sta_mac, qmac, 6);
    else { unsigned char other[6] = {0x99,0x99,0x99,0x99,0x99,0x99}; memcpy(g_harvester_module.inst_msmt.sta_mac, other, 6); }

    wifi_mgr_t *m = (wifi_mgr_t *)men_mgr_buf;
    m->hal_cap.wifi_prop.radio_presence[0] = true;

    men_num_vaps = 3;
    men_found_vap = tc->found_vap;  /* is_harvester_device_associated returns true at this vap */
}
