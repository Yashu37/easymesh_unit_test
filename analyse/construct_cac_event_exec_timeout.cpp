/*
 * TEST CASES / CONSTRUCTOR: construct_cac_event_exec_timeout
 *
 * apps (cet_apps_buf) has data.u.cac.assoc_req_map set (or NULL) and
 * sta_map = NULL (the heavy second loop is skipped). One cac_sta_info_t
 * (cet_elem) is the single assoc_map entry; when its seconds_alive hits 0
 * the handler strncpy's its mac_addr into mac_str and hash_map_remove's it.
 *
 * Cases: no assoc_map (nothing), one entry expiring (seconds_alive 1 -> 0,
 * removed), one entry not expiring (seconds_alive 5), and a hex-letter MAC.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

char  cet_mgr_buf[sizeof(wifi_mgr_t) + CET_PAD];
char  cet_slot_mac[CET_MAC_SZ + CET_PAD];
void *cet_first;
char  cet_removed_key[64];
int   cet_remove_calls;
alignas(16) char cet_apps_buf[sizeof(wifi_app_t) + CET_PAD];
static cac_sta_info_t cet_elem;

cac_event_exec_timeout_test_case_t cac_event_exec_timeout_suite[] = {
    /* name            has_assoc seconds_alive mac0  expect_remove */
    { "no_assoc_map",    0,       0,            0x10, 0 },
    { "entry_expires",   1,       1,            0x10, 1 },
    { "entry_alive",     1,       5,            0x10, 0 },
    { "mac_hex_letters", 1,       1,            0xaa, 1 },

    { NULL, 0, 0, 0, 0 }  /* sentinel */
};

void construct_cac_event_exec_timeout_input(const cac_event_exec_timeout_test_case_t *tc)
{
    memset(cet_mgr_buf, 0, sizeof(cet_mgr_buf));
    memset(cet_apps_buf, 0, sizeof(cet_apps_buf));
    memset(&cet_elem, 0, sizeof(cet_elem));

    snprintf(cet_elem.mac_addr, sizeof(cet_elem.mac_addr), "%02x:%02x:%02x:%02x:%02x:%02x",
             (unsigned char)tc->mac0, (unsigned char)(tc->mac0+1), (unsigned char)(tc->mac0+2),
             (unsigned char)(tc->mac0+3), (unsigned char)(tc->mac0+4), (unsigned char)(tc->mac0+5));
    cet_elem.seconds_alive = tc->seconds_alive;
    cet_elem.ap_index = 1;
    cet_first = &cet_elem;

    wifi_app_t *app = (wifi_app_t *)cet_apps_buf;
    app->data.u.cac.assoc_req_map = tc->has_assoc ? (void *)0x1 : NULL;
    app->data.u.cac.sta_map = NULL;   /* skip the heavy second loop */

    cet_removed_key[0] = 0;
    cet_remove_calls = 0;
}
