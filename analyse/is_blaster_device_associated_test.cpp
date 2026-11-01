/*
 * TEST RUNNER: is_blaster_device_associated_test
 *
 * Poisoned around the call:
 *   - the caller's sta_mac: bytes past MAC_ADDR_LEN (6);
 *   - the caller's is_mlo: bytes past sizeof(bool);
 *   - the vap info (rdk_wifi_vap_info_t) and the station (assoc_dev_data_t):
 *     bytes past each struct;
 *   - the sta_key write slot bib_slot_key past 18 (= STA_KEY_LEN).
 * sta_key is internal (auto-guarded by ASan).
 * PASS = return value and *is_mlo match, and the key is lower-case
 * 17 chars when it is built.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

bool is_blaster_device_associated(int ap_index, mac_address_t sta_mac, bool *is_mlo);

int test_is_blaster_device_associated(const is_blaster_device_associated_test_case_t *tc)
{
    bool *is_mlo = tc->mlo_null ? NULL : (bool *)bib_mlo_buf;

    /* POISON */
    __asan_poison_memory_region(&bib_mac_buf[MAC_ADDR_LEN], BIB_PAD);                  /* sta_mac[6]     */
    __asan_poison_memory_region(&bib_mlo_buf[sizeof(bool)], BIB_PAD);                  /* is_mlo         */
    __asan_poison_memory_region(&bib_vap_buf[sizeof(rdk_wifi_vap_info_t)], BIB_PAD);   /* vap info       */
    __asan_poison_memory_region(&bib_sta_buf[sizeof(assoc_dev_data_t)], BIB_PAD);      /* station        */
    __asan_poison_memory_region(&bib_slot_key[BIB_KEY_SZ], BIB_PAD);                   /* sta_key[18]    */

    bool ret = is_blaster_device_associated(5, bib_mac_buf, is_mlo);

    /* UNPOISON */
    __asan_unpoison_memory_region(&bib_slot_key[BIB_KEY_SZ], BIB_PAD);
    __asan_unpoison_memory_region(&bib_sta_buf[sizeof(assoc_dev_data_t)], BIB_PAD);
    __asan_unpoison_memory_region(&bib_vap_buf[sizeof(rdk_wifi_vap_info_t)], BIB_PAD);
    __asan_unpoison_memory_region(&bib_mlo_buf[sizeof(bool)], BIB_PAD);
    __asan_unpoison_memory_region(&bib_mac_buf[MAC_ADDR_LEN], BIB_PAD);

    int mlo_out = *(bool *)bib_mlo_buf ? 1 : 0;
    int key_ok = 1;
    if (bib_key_len) {
        key_ok = (bib_key_len == 17) && !strcmp(bib_key_seen, bib_sta_key);
        for (const char *p = bib_key_seen; *p; p++) if (*p >= 'A' && *p <= 'F') key_ok = 0;
    }
    printf("    ret=%d is_mlo=%s -> %d key_len=%zu key=\"%s\" lookups=%d\n",
           ret, tc->mlo_null ? "NULL" : "set", mlo_out, bib_key_len, bib_key_seen, bib_vap_lookups);
    return ret == tc->expect_ret && mlo_out == tc->expect_mlo && key_ok && bib_vap_lookups == 1 && bib_lookup_index == 5;
}

void run_all_tests_is_blaster_device_associated(void)
{
    for (int i = 0; is_blaster_device_associated_suite[i].test_name != NULL; i++) {
        is_blaster_device_associated_test_case_t *test = &is_blaster_device_associated_suite[i];

        printf("--- Running Test: %s ---\n", test->test_name);

        construct_is_blaster_device_associated_input(test);

        int pass = test_is_blaster_device_associated(test);

        if (pass) {
            printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        } else {
            printf("===== %s: \033[31mFAIL\033[0m (expected ret=%d is_mlo=%d) =====\n",
                   test->test_name, test->expect_ret, test->expect_mlo);
        }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
