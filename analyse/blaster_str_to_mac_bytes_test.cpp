/*
 * TEST RUNNER: blaster_str_to_mac_bytes_test
 *
 * Poisoned around the call:
 *   - the caller's key: bytes past strlen(key)+1 (catches reading past NUL);
 *   - the caller's bmac: bytes past MAC_ADDR_LEN (6).
 * mac[6] is internal (auto-guarded by ASan).
 * PASS = bmac holds the expected 6 bytes.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

void blaster_str_to_mac_bytes(char *key, mac_addr_t bmac);

int test_blaster_str_to_mac_bytes(const blaster_str_to_mac_bytes_test_case_t *tc)
{
    size_t klen = strlen(bsm_key_buf) + 1;

    /* POISON */
    __asan_poison_memory_region(&bsm_key_buf[klen], BSM_KEY_MAX + BSM_PAD - klen);   /* key past NUL */
    __asan_poison_memory_region(&bsm_mac_buf[MAC_ADDR_LEN], BSM_PAD);                /* bmac[6]      */

    blaster_str_to_mac_bytes(bsm_key_buf, bsm_mac_buf);

    /* UNPOISON */
    __asan_unpoison_memory_region(&bsm_mac_buf[MAC_ADDR_LEN], BSM_PAD);
    __asan_unpoison_memory_region(&bsm_key_buf[klen], BSM_KEY_MAX + BSM_PAD - klen);

    printf("    key=\"%s\" -> bmac=%02x:%02x:%02x:%02x:%02x:%02x\n", tc->key,
           bsm_mac_buf[0], bsm_mac_buf[1], bsm_mac_buf[2], bsm_mac_buf[3], bsm_mac_buf[4], bsm_mac_buf[5]);
    return !memcmp(bsm_mac_buf, tc->expect, MAC_ADDR_LEN);
}

void run_all_tests_blaster_str_to_mac_bytes(void)
{
    for (int i = 0; blaster_str_to_mac_bytes_suite[i].test_name != NULL; i++) {
        blaster_str_to_mac_bytes_test_case_t *test = &blaster_str_to_mac_bytes_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_blaster_str_to_mac_bytes_input(test);
        int pass = test_blaster_str_to_mac_bytes(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
