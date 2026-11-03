/*
 * TEST RUNNER: is_harvester_device_associated
 *
 * Poisoned around the call:
 *   - the caller's query MAC (ihd_mac_buf): bytes past the 6-byte mac;
 *   - the tail of the to_sta_key slot (ihd_slot_key) past STA_KEY_LEN -- so an
 *     over-long key format would trip.
 * sta_key (char[STA_KEY_LEN]) is an internal stack array (ASan redzones).
 *
 * PASS = the returned bool matches (true only when the vap + non-NULL map +
 * matching station are present).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

bool is_harvester_device_associated(int ap_index, mac_address_t sta_mac);

int test_is_harvester_device_associated(const harv_ihd_test_case_t *tc)
{
    /* POISON */
    __asan_poison_memory_region(&ihd_mac_buf[6], IHD_PAD);
    __asan_poison_memory_region(&ihd_slot_key[IHD_KEY_SZ], IHD_PAD);

    bool got = is_harvester_device_associated(1, (unsigned char *)ihd_mac_buf);

    /* UNPOISON */
    __asan_unpoison_memory_region(&ihd_slot_key[IHD_KEY_SZ], IHD_PAD);
    __asan_unpoison_memory_region(&ihd_mac_buf[6], IHD_PAD);

    printf("    got=%d key_len=%d key_seen=\"%s\" (want %d)\n", got, ihd_key_len, ihd_key_seen, tc->want);
    return got == tc->want;
}

void run_all_tests_is_harvester_device_associated(void)
{
    for (int i = 0; is_harvester_device_associated_suite[i].test_name != NULL; i++) {
        harv_ihd_test_case_t *test = &is_harvester_device_associated_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_is_harvester_device_associated_input(test);
        int pass = test_is_harvester_device_associated(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
