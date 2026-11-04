/*
 * TEST RUNNER: process_levl_csi
 *
 * Poisoned around the call:
 *   - the levl wifi_app stand-in (lpc_app_buf) past sizeof(struct wifi_app);
 *   - the caller's wifi_csi_dev_t (lpc_csi_buf) past sizeof(wifi_csi_dev_t):
 *     the handler reads only the 6-byte sta_mac from it.
 * mac_addr (6 bytes) and mac_str (18 bytes) are internal stack arrays guarded
 * by ASan redzones; the sounding entry is a heap block (a use after free
 * would be reported, e.g. in the "entry gone" path).
 *
 * PASS = return value, publish count and whether last_time_publish was
 * updated match the case.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

int process_levl_csi(wifi_app_t *app, wifi_csi_dev_t *csi_data);

int test_process_levl_csi(const lv_lpc_test_case_t *tc)
{
    /* POISON */
    __asan_poison_memory_region(&lpc_app_buf[sizeof(struct wifi_app)], LPC_PAD);
    __asan_poison_memory_region(&lpc_csi_buf[sizeof(wifi_csi_dev_t)], LPC_PAD);

    int ret = process_levl_csi((wifi_app_t *)lpc_app_buf, (wifi_csi_dev_t *)lpc_csi_buf);

    /* UNPOISON */
    __asan_unpoison_memory_region(&lpc_csi_buf[sizeof(wifi_csi_dev_t)], LPC_PAD);
    __asan_unpoison_memory_region(&lpc_app_buf[sizeof(struct wifi_app)], LPC_PAD);

    int updated = lpc_slot_updated();
    lpc_free_slot();
    int ok = (ret == tc->want_ret) && (lpc_pub_calls == tc->want_pub) && (updated == tc->want_updated);
    printf("    ret=%d (want %d) publish=%d (want %d) updated=%d (want %d)\n", ret, tc->want_ret,
           lpc_pub_calls, tc->want_pub, updated, tc->want_updated);
    return ok;
}

void run_all_tests_process_levl_csi(void)
{
    for (int i = 0; process_levl_csi_suite[i].test_name != NULL; i++) {
        lv_lpc_test_case_t *test = &process_levl_csi_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_process_levl_csi_input(test);
        int pass = test_process_levl_csi(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
