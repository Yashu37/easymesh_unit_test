/*
 * TEST CASES / CONSTRUCTOR: construct_handle_sta_client_info
 *
 * sta_info (input) lives at hsci_sta_buf; the runner poisons past the struct.
 * hsci_prepopulate pre-seeds the client-type map so the "refresh existing"
 * branch runs. The mac is a0:a1:..:a5 -> key "a0:a1:a2:a3:a4:a5".
 *
 * Cases: new_entry (map miss -> malloc + put), refresh (pre-populated ->
 * update existing), null_sta (-> RETURN_ERR).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

alignas(16) char hsci_sta_buf[sizeof(sta_client_info_t) + HSCI_PAD];

em_hsci_test_case_t handle_sta_client_info_suite[] = {
    /* name          sta_null prepopulate want_ret */
    { "new_entry",      0,     0,          0 },
    { "refresh",        0,     1,          0 },
    { "null_sta",       1,     0,         -1 },
    { NULL, 0, 0, 0 }  /* sentinel */
};

void construct_handle_sta_client_info_input(const em_hsci_test_case_t *tc)
{
    memset(hsci_sta_buf, 0, sizeof(hsci_sta_buf));
    sta_client_info_t *sta = (sta_client_info_t *)hsci_sta_buf;
    unsigned char mac[6] = {0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5};
    memcpy(sta->mac_addr, mac, 6);
    snprintf((char *)sta->client_type, sizeof(sta->client_type), "Smartphone");

    hsci_store_reset();
    if (tc->prepopulate)
        hsci_store_prepopulate("a0:a1:a2:a3:a4:a5");
}
