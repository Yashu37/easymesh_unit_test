/*
 * TEST RUNNER: harvester_str_to_mac_bytes
 * Poisoned around the call:
 *   - the caller's key buffer: bytes past the key's NUL;
 *   - the caller's bmac: bytes past the 6-byte mac_addr_t.
 * mac[6] (unsigned int) is an internal stack array guarded by ASan redzones.
 * PASS = bmac holds the parsed bytes (or is untouched for the empty key).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

void harvester_str_to_mac_bytes(char *key, mac_addr_t bmac);

int test_harvester_str_to_mac_bytes(const harv_hsm_test_case_t *tc)
{
    size_t klen = strlen(hsm_key_buf);

    /* POISON */
    __asan_poison_memory_region(&hsm_key_buf[klen + 1], HSM_KEY_SZ - (klen + 1));
    __asan_poison_memory_region(&hsm_bmac_buf[6], HSM_PAD);

    harvester_str_to_mac_bytes(hsm_key_buf, (unsigned char *)hsm_bmac_buf);

    /* UNPOISON */
    __asan_unpoison_memory_region(&hsm_bmac_buf[6], HSM_PAD);
    __asan_unpoison_memory_region(&hsm_key_buf[klen + 1], HSM_KEY_SZ - (klen + 1));

    int ok = (memcmp(hsm_bmac_buf, tc->expect, 6) == 0);
    printf("    bmac=%02x:%02x:%02x:%02x:%02x:%02x\n", hsm_bmac_buf[0], hsm_bmac_buf[1],
           hsm_bmac_buf[2], hsm_bmac_buf[3], hsm_bmac_buf[4], hsm_bmac_buf[5]);
    return ok;
}

void run_all_tests_harvester_str_to_mac_bytes(void)
{
    for (int i = 0; harvester_str_to_mac_bytes_suite[i].test_name != NULL; i++) {
        harv_hsm_test_case_t *test = &harvester_str_to_mac_bytes_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_harvester_str_to_mac_bytes_input(test);
        int pass = test_harvester_str_to_mac_bytes(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
