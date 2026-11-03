/*
 * TEST RUNNER: levl_csi_status_publish
 *
 * Poisoned around the call:
 *   - the caller's mac buffer (lcsp_mac_buf): bytes past the 6-byte mac_addr_t.
 * eventName[200] / eventValue[50] / mac_str[18] are internal stack arrays guarded
 * by ASan redzones.
 *
 * PASS = return value matches and the published event value equals
 * "<mac>;<status>".
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

int levl_csi_status_publish(bus_handle_t *handle, mac_addr_t mac_addr, unsigned int status);

int test_levl_csi_status_publish(const lv_lcsp_test_case_t *tc)
{
    /* POISON */
    __asan_poison_memory_region(&lcsp_mac_buf[6], LCSP_PAD);

    int ret = levl_csi_status_publish(NULL, (unsigned char *)lcsp_mac_buf, tc->status);

    /* UNPOISON */
    __asan_unpoison_memory_region(&lcsp_mac_buf[6], LCSP_PAD);

    int ok = (ret == tc->want_ret) && (lcsp_publish_calls == 1) &&
             (strcmp(lcsp_pub_value, tc->want_value) == 0);
    printf("    ret=%d (want %d) calls=%d event=\"%s\" value=\"%s\"\n", ret, tc->want_ret,
           lcsp_publish_calls, lcsp_pub_name, lcsp_pub_value);
    return ok;
}

void run_all_tests_levl_csi_status_publish(void)
{
    for (int i = 0; levl_csi_status_publish_suite[i].test_name != NULL; i++) {
        lv_lcsp_test_case_t *test = &levl_csi_status_publish_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_levl_csi_status_publish_input(test);
        int pass = test_levl_csi_status_publish(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
