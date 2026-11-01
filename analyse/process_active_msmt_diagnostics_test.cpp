/*
 * TEST RUNNER: process_active_msmt_diagnostics_test
 *
 * Poisoned around the call:
 *   - the g_active_msmt stand-in: bytes past sizeof(wifi_actvie_msmt_t);
 *   - the source sample array pad_src_buf: bytes past samples*sizeof(entry)
 *     (catches the copy loop over-reading the source);
 *   - the sta_key write slot pad_slot_key past 18 (= STA_KEY_LEN).
 * sta_key is internal (auto-guarded by ASan).
 * PASS = a station is stored/updated under the lower-case 17-char key, and
 * its sta_active_msmt_data was allocated when expected.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

void process_active_msmt_diagnostics(int ap_index);

int test_process_active_msmt_diagnostics(const process_active_msmt_diagnostics_test_case_t *tc)
{
    size_t src_used = (size_t)tc->samples * sizeof(active_msmt_data_t);

    /* POISON */
    __asan_poison_memory_region(&pad_mgr_buf[sizeof(wifi_actvie_msmt_t)], PAD_PAD);           /* stand-in     */
    __asan_poison_memory_region(&pad_src_buf[src_used], sizeof(pad_src_buf) - src_used);      /* source array */
    __asan_poison_memory_region(&pad_slot_key[PAD_KEY_SZ], PAD_PAD);                          /* sta_key[18]  */

    process_active_msmt_diagnostics(tc->ap_index);

    /* UNPOISON */
    __asan_unpoison_memory_region(&pad_slot_key[PAD_KEY_SZ], PAD_PAD);
    __asan_unpoison_memory_region(&pad_src_buf[src_used], sizeof(pad_src_buf) - src_used);
    __asan_unpoison_memory_region(&pad_mgr_buf[sizeof(wifi_actvie_msmt_t)], PAD_PAD);

    blaster_hashmap_t *sta = (blaster_hashmap_t *)(pad_put_data ? pad_put_data : pad_existing);
    int key_lower = 1;
    for (const char *p = pad_key_seen; *p; p++) if (*p >= 'A' && *p <= 'F') key_lower = 0;

    int ok;
    if (tc->no_map) {
        ok = (pad_key_len == 0) && (pad_put_data == NULL);      /* early return, no key built */
    } else {
        int put_ok = (pad_put_data != NULL) == (tc->expect_put != 0);
        int alloc_ok = sta && (tc->samples == 0 || sta->sta_active_msmt_data != NULL);
        int mac_ok = sta && !memcmp(sta->sta_mac, ((wifi_actvie_msmt_t *)pad_mgr_buf)->curStepData.DestMac, 6);
        ok = put_ok && alloc_ok && mac_ok && key_lower && pad_key_len == 17;
    }
    printf("    ap_index=%d samples=%d -> put=%d key=\"%s\" key_len=%zu alloc=%p\n",
           tc->ap_index, tc->samples, pad_put_data != NULL, pad_key_seen, pad_key_len,
           (void *)(sta ? sta->sta_active_msmt_data : NULL));

    if (sta && sta->sta_active_msmt_data) { free(sta->sta_active_msmt_data); sta->sta_active_msmt_data = NULL; }
    if (pad_put_data) free(pad_put_data);
    return ok;
}

void run_all_tests_process_active_msmt_diagnostics(void)
{
    for (int i = 0; process_active_msmt_diagnostics_suite[i].test_name != NULL; i++) {
        process_active_msmt_diagnostics_test_case_t *test = &process_active_msmt_diagnostics_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_process_active_msmt_diagnostics_input(test);
        int pass = test_process_active_msmt_diagnostics(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m (expected put=%d) =====\n", test->test_name, test->expect_put);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
