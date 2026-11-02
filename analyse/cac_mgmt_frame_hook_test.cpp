/*
 * TEST RUNNER: cac_mgmt_frame_hook_test
 * Poison: the vap_name write slot past 32, and the wifi_mgr stand-in past its
 * size. vap_name[32] is ASan-stack guarded.
 * PASS = the return matches the expected NL_OK(0)/NL_SKIP(1).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"
typedef enum { WIFI_MGMT_FRAME_TYPE_PROBE_REQ=0, WIFI_MGMT_FRAME_TYPE_ASSOC_REQ=1, WIFI_MGMT_FRAME_TYPE_REASSOC_REQ=2, WIFI_MGMT_FRAME_TYPE_OTHER=99 } wifi_mgmtFrameType_t;

int cac_mgmt_frame_hook(int ap_index, wifi_mgmtFrameType_t type);

int test_cac_mgmt_frame_hook(const cac_mgmt_frame_hook_test_case_t *tc)
{
    __asan_poison_memory_region(&cmh_slot_vap[CMH_VAP_SZ], CMH_PAD);
    __asan_poison_memory_region(&cmh_mgr_buf[sizeof(wifi_mgr_t)], CMH_PAD);

    int ret = cac_mgmt_frame_hook(4, (wifi_mgmtFrameType_t)tc->type);

    __asan_unpoison_memory_region(&cmh_mgr_buf[sizeof(wifi_mgr_t)], CMH_PAD);
    __asan_unpoison_memory_region(&cmh_slot_vap[CMH_VAP_SZ], CMH_PAD);

    printf("    type=%d -> ret=%d\n", tc->type, ret);
    return ret == tc->expect_ret;
}

void run_all_tests_cac_mgmt_frame_hook(void)
{
    for (int i = 0; cac_mgmt_frame_hook_suite[i].test_name != NULL; i++) {
        cac_mgmt_frame_hook_test_case_t *test = &cac_mgmt_frame_hook_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_cac_mgmt_frame_hook_input(test);
        int pass = test_cac_mgmt_frame_hook(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m (expected ret=%d) =====\n", test->test_name, test->expect_ret);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
