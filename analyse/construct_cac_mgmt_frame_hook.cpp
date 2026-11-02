/*
 * TEST CASES / CONSTRUCTOR: construct_cac_mgmt_frame_hook
 * No caller buffers; behaviour driven by stub flags (hotspot, type, config).
 * Cases: not-hotspot, wrong frame type, vap-name fail, config fail, probe
 * with disabled rates (NL_OK), a threshold enabled (NL_SKIP), all disabled.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

char cmh_slot_vap[CMH_VAP_SZ + CMH_PAD];
char cmh_mgr_buf[sizeof(wifi_mgr_t) + CMH_PAD];
int  cmh_is_hotspot, cmh_vap_fail, cmh_cfg_fail;
char cmh_rssi[32], cmh_rates[32];

cac_mgmt_frame_hook_test_case_t cac_mgmt_frame_hook_suite[] = {
    /* name            hotspot type vapfail cfgfail rssi        rates       expect_ret */
    { "not_hotspot",     0,     0,   0,      0,      "disabled", "disabled", 0 },  /* NL_OK  */
    { "wrong_type",      1,     99,  0,      0,      "disabled", "disabled", 0 },  /* NL_OK  */
    { "vap_name_fail",   1,     0,   1,      0,      "disabled", "disabled", 0 },  /* NL_OK  */
    { "cfg_fail",        1,     1,   0,      1,      "disabled", "disabled", 0 },  /* NL_OK  */
    { "probe_dis_rates", 1,     0,   0,      0,      "disabled", "disabled", 0 },  /* NL_OK  */
    { "rssi_enabled",    1,     1,   0,      0,      "-80",      "disabled", 1 },  /* NL_SKIP */
    { "all_disabled",    1,     1,   0,      0,      "disabled", "disabled", 0 },  /* NL_OK  */
    { NULL, 0, 0, 0, 0, NULL, NULL, 0 }
};

void construct_cac_mgmt_frame_hook_input(const cac_mgmt_frame_hook_test_case_t *tc)
{
    memset(cmh_mgr_buf, 0, sizeof(cmh_mgr_buf));
    cmh_is_hotspot = tc->hotspot; cmh_vap_fail = tc->vapfail; cmh_cfg_fail = tc->cfgfail;
    snprintf(cmh_rssi, sizeof(cmh_rssi), "%s", tc->rssi);
    snprintf(cmh_rates, sizeof(cmh_rates), "%s", tc->rates);
}
