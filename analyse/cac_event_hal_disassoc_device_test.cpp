/*
 * TEST RUNNER: cac_event_hal_disassoc_device_test
 * Poison: caller arg + apps past sizes; client_mac slot past 32; temp_str
 * slot past 64. Internal arrays ASan-stack guarded.
 * PASS = RETURN_OK, remove happens iff the station existed, key lower-case 17.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

int cac_event_hal_disassoc_device(wifi_app_t *apps, void *arg);

int test_cac_event_hal_disassoc_device(const cac_event_hal_disassoc_device_test_case_t *tc)
{
    __asan_poison_memory_region(&cdd_arg_buf[sizeof(assoc_dev_data_t)], CDD_PAD);
    __asan_poison_memory_region(&cdd_apps_buf[sizeof(wifi_app_t)], CDD_PAD);
    __asan_poison_memory_region(&cdd_slot_mac[CDD_MAC_SZ], CDD_PAD);
    __asan_poison_memory_region(&cdd_slot_tmp[CDD_TMP_SZ], CDD_PAD);

    int ret = cac_event_hal_disassoc_device((wifi_app_t *)cdd_apps_buf, cdd_arg_buf);

    __asan_unpoison_memory_region(&cdd_slot_tmp[CDD_TMP_SZ], CDD_PAD);
    __asan_unpoison_memory_region(&cdd_slot_mac[CDD_MAC_SZ], CDD_PAD);
    __asan_unpoison_memory_region(&cdd_apps_buf[sizeof(wifi_app_t)], CDD_PAD);
    __asan_unpoison_memory_region(&cdd_arg_buf[sizeof(assoc_dev_data_t)], CDD_PAD);

    int key_ok = strlen(cdd_key_seen) == 17;
    for (const char *p = cdd_key_seen; *p; p++) if (*p >= 'A' && *p <= 'F') key_ok = 0;
    printf("    ret=%d remove=%d key=\"%s\" tmp_len=%zu\n", ret, cdd_remove_calls, cdd_key_seen, cdd_tmp_len);
    return ret == 0 && cdd_remove_calls == tc->expect_remove && key_ok && cdd_tmp_len < CDD_TMP_SZ;
}

void run_all_tests_cac_event_hal_disassoc_device(void)
{
    for (int i = 0; cac_event_hal_disassoc_device_suite[i].test_name != NULL; i++) {
        cac_event_hal_disassoc_device_test_case_t *test = &cac_event_hal_disassoc_device_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_cac_event_hal_disassoc_device_input(test);
        int pass = test_cac_event_hal_disassoc_device(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m (expected remove=%d) =====\n", test->test_name, test->expect_remove);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
