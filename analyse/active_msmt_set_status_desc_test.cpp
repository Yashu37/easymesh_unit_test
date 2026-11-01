/*
 * TEST RUNNER: active_msmt_set_status_desc_test
 *
 * Poisoned around the call:
 *   - the caller's dst_mac: bytes past MAC_ADDRESS_LENGTH (13);
 *   - the caller's plan_id / msg: bytes past their NULs (NULL is skipped);
 *   - the stand-in wifi_actvie_msmt_t: bytes past its size;
 *   - the write slots: asd_slot_mac past 13, asd_slot_desc past 512.
 * mac[13] is internal (auto-guarded by ASan).
 * PASS = status_desc holds the expected text and the mac slot stays < 13.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

void active_msmt_set_status_desc(const char *func, unsigned char *plan_id, unsigned int step_id,
    unsigned char *dst_mac, char *msg);

int test_active_msmt_set_status_desc(const active_msmt_set_status_desc_test_case_t *tc)
{
    unsigned char *plan = tc->plan_id ? (unsigned char *)asd_plan_buf : NULL;
    char          *msg  = tc->msg     ? asd_msg_buf : NULL;
    size_t plen = strlen(asd_plan_buf) + 1, mlen = strlen(asd_msg_buf) + 1;

    /* POISON */
    __asan_poison_memory_region(&asd_mac_buf[ASD_DSTMAC_SZ], ASD_PAD);                 /* dst_mac[13]  */
    if (plan) __asan_poison_memory_region(&asd_plan_buf[plen], 64 + ASD_PAD - plen);   /* plan_id      */
    if (msg)  __asan_poison_memory_region(&asd_msg_buf[mlen], 512 + ASD_PAD - mlen);   /* msg          */
    __asan_poison_memory_region(&asd_mgr_buf[sizeof(wifi_actvie_msmt_t)], ASD_PAD);    /* stand-in     */
    __asan_poison_memory_region(&asd_slot_mac[ASD_MAC_SZ], ASD_PAD);                   /* mac[13]      */
    __asan_poison_memory_region(&asd_slot_desc[ASD_DESC_SZ], ASD_PAD);                 /* status_desc  */

    active_msmt_set_status_desc("active_msmt_report_error", plan, 7, asd_mac_buf, msg);

    /* UNPOISON */
    __asan_unpoison_memory_region(&asd_slot_desc[ASD_DESC_SZ], ASD_PAD);
    __asan_unpoison_memory_region(&asd_slot_mac[ASD_MAC_SZ], ASD_PAD);
    __asan_unpoison_memory_region(&asd_mgr_buf[sizeof(wifi_actvie_msmt_t)], ASD_PAD);
    if (msg)  __asan_unpoison_memory_region(&asd_msg_buf[mlen], 512 + ASD_PAD - mlen);
    if (plan) __asan_unpoison_memory_region(&asd_plan_buf[plen], 64 + ASD_PAD - plen);
    __asan_unpoison_memory_region(&asd_mac_buf[ASD_DSTMAC_SZ], ASD_PAD);

    const char *desc = ((wifi_actvie_msmt_t *)asd_mgr_buf)->status_desc;
    int ok = strncmp(desc, tc->want_desc_prefix, strlen(tc->want_desc_prefix)) == 0;
    printf("    mac_len=%zu desc_len=%zu desc=\"%.90s\"\n", asd_mac_len, asd_desc_len, desc);
    return ok && asd_mac_len < ASD_MAC_SZ && asd_desc_len < ASD_DESC_SZ;
}

void run_all_tests_active_msmt_set_status_desc(void)
{
    for (int i = 0; active_msmt_set_status_desc_suite[i].test_name != NULL; i++) {
        active_msmt_set_status_desc_test_case_t *test = &active_msmt_set_status_desc_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_active_msmt_set_status_desc_input(test);
        int pass = test_active_msmt_set_status_desc(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m (want prefix \"%.60s\") =====\n", test->test_name, test->want_desc_prefix);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
