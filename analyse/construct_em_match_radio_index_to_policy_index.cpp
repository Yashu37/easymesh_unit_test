/*
 * TEST CASES / CONSTRUCTOR: construct_em_match_radio_index_to_policy_index
 *
 * The wifi_prop's radio_interface_map has entries for radio_index 0 and 1
 * (rest -1). radio_count = 2. The policies live at emm_pol_buf (runner poisons
 * past the struct); the wifi_mgr stand-in at emm_mgr_buf. emm_found_index is
 * what the stubbed em_get_radio_index_from_mac returns.
 *
 * Cases: match (iface entry exists + lookup returns radio_index -> policy 0),
 * no_iface (radio_index has no interface-map entry -> RETURN_ERR),
 * no_policy_match (iface exists but lookup never equals radio_index -> ERR).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

alignas(16) char emm_mgr_buf[sizeof(wifi_mgr_t) + EMM_PAD];
alignas(16) char emm_pol_buf[sizeof(radio_metrics_policies_t) + EMM_PAD];
int  emm_found_index, emm_grifm_calls;

em_mri_test_case_t em_match_radio_index_to_policy_index_suite[] = {
    /* name              radio_index want_ret */
    { "match",             1,         0 },   /* iface entry for 1 exists, lookup->1 => policy index 0 */
    { "no_iface_map",      5,        -1 },   /* no interface-map entry for radio_index 5             */
    { "no_policy_match",   1,        -1 },   /* iface exists but lookup never == radio_index          */
    { NULL, 0, 0 }  /* sentinel */
};

void construct_em_match_radio_index_to_policy_index_input(const em_mri_test_case_t *tc)
{
    memset(emm_mgr_buf, 0, sizeof(emm_mgr_buf));
    memset(emm_pol_buf, 0, sizeof(emm_pol_buf));
    emm_grifm_calls = 0;

    wifi_mgr_t *m = (wifi_mgr_t *)emm_mgr_buf;
    wifi_platform_property_t *wp = &m->hal_cap.wifi_prop;
    for (int k = 0; k < 8; k++) wp->radio_interface_map[k].radio_index = -1;
    snprintf(wp->radio_interface_map[0].interface_name, 32, "wlan0"); wp->radio_interface_map[0].radio_index = 0;
    snprintf(wp->radio_interface_map[1].interface_name, 32, "wlan1"); wp->radio_interface_map[1].radio_index = 1;

    radio_metrics_policies_t *pol = (radio_metrics_policies_t *)emm_pol_buf;
    pol->radio_count = 2;

    /* the stubbed lookup returns radio_index for the match case, else a non-matching value */
    emm_found_index = (strcmp(tc->test_name, "no_policy_match") == 0) ? 99 : tc->radio_index;
}
