/*
 * TEST RUNNER: sample_blaster_test
 *
 * Poisoned around the call:
 *   - provider_response and the ctrl/mgr/blaster/app stand-ins past sizes;
 *   - the frameCountSample and active_msmt_data arrays past SB_SAMPLES;
 *   - the sta_data provider array past its entries;
 *   - the msg slot past 256 and the Operating_* slot past OPER_BUFFER_LEN.
 * bmac[6] / msg[256] are internal (auto-guarded by ASan).
 * PASS = the expected branch ran (msg substring for ext-disconnected, empty
 * otherwise) and msg_len < 256.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

void sample_blaster(wifi_provider_response_t *provider_response);

int test_sample_blaster(const sample_blaster_test_case_t *tc)
{
    /* POISON */
    __asan_poison_memory_region(&sb_resp_buf[sizeof(wifi_provider_response_t)], SB_PAD);
    __asan_poison_memory_region(&sb_wctrl_buf[sizeof(wifi_ctrl_t)], SB_PAD);
    __asan_poison_memory_region(&sb_wmgr_buf[sizeof(wifi_mgr_t)], SB_PAD);
    __asan_poison_memory_region(&sb_mgr_buf[sizeof(wifi_actvie_msmt_t)], SB_PAD);
    __asan_poison_memory_region(&sb_app_buf[sizeof(wifi_app_t)], SB_PAD);
    __asan_poison_memory_region(&sb_fcs_buf[SB_SAMPLES * sizeof(pktGenFrameCountSamples)], SB_PAD);
    __asan_poison_memory_region(&sb_amd_buf[SB_SAMPLES * sizeof(active_msmt_data_t)], SB_PAD);
    __asan_poison_memory_region(&sb_slot_msg[SB_MSG_SZ], SB_PAD);
    __asan_poison_memory_region(&sb_slot_oper[SB_OPER_SZ], SB_PAD);

    sample_blaster((wifi_provider_response_t *)sb_resp_buf);

    /* UNPOISON */
    __asan_unpoison_memory_region(&sb_slot_oper[SB_OPER_SZ], SB_PAD);
    __asan_unpoison_memory_region(&sb_slot_msg[SB_MSG_SZ], SB_PAD);
    __asan_unpoison_memory_region(&sb_amd_buf[SB_SAMPLES * sizeof(active_msmt_data_t)], SB_PAD);
    __asan_unpoison_memory_region(&sb_fcs_buf[SB_SAMPLES * sizeof(pktGenFrameCountSamples)], SB_PAD);
    __asan_unpoison_memory_region(&sb_app_buf[sizeof(wifi_app_t)], SB_PAD);
    __asan_unpoison_memory_region(&sb_mgr_buf[sizeof(wifi_actvie_msmt_t)], SB_PAD);
    __asan_unpoison_memory_region(&sb_wmgr_buf[sizeof(wifi_mgr_t)], SB_PAD);
    __asan_unpoison_memory_region(&sb_wctrl_buf[sizeof(wifi_ctrl_t)], SB_PAD);
    __asan_unpoison_memory_region(&sb_resp_buf[sizeof(wifi_provider_response_t)], SB_PAD);

    int msg_ok = tc->want_msg_sub[0] == 0 ? 1 : (strstr(sb_slot_msg, tc->want_msg_sub) != NULL);
    printf("    done_notify=%d statusdesc=%d msg_len=%zu msg=\"%.40s\"\n",
           sb_done_notify, sb_statusdesc_calls, sb_msg_len, sb_slot_msg);
    return msg_ok && sb_msg_len < SB_MSG_SZ && sb_done_notify >= 1;
}

void run_all_tests_sample_blaster(void)
{
    for (int i = 0; sample_blaster_suite[i].test_name != NULL; i++) {
        sample_blaster_test_case_t *test = &sample_blaster_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_sample_blaster_input(test);
        int pass = test_sample_blaster(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m (want msg~\"%s\") =====\n", test->test_name, test->want_msg_sub);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
