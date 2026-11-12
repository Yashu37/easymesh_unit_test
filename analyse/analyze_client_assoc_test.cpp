/*
 * TEST RUNNER: analyze_client_assoc_test
 *
 * Poisoned around the call:
 *   - the caller's subdoc.buff: bytes past strlen+1 (catches cJSON_Parse /
 *     strchr / sscanf reading past the NUL);
 *   - the caller's pcmd[]: slots from EM_MAX_CMD onward (catches a write past
 *     the caller's array).
 * mac[6] and assoc_param are internal (auto-guarded by ASan redzones).
 * PASS = return value matches expect_num and, when accepted, the parsed
 * bssid / AssocControl / ValidityPeriod / sta_count / first STA match.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

int test_analyze_client_assoc(const ac_test_case_t *tc)
{
    em_bus_event_t *evt = (em_bus_event_t *)ac_evt_buf;
    char *buff = evt->u.subdoc.buff;
    size_t blen = strlen(buff) + 1;
    char *poison_from = buff + blen;
    size_t poison_len = (size_t)((ac_evt_buf + AC_EVT_SZ) - poison_from);

    /* POISON */
    __asan_poison_memory_region(poison_from, poison_len);                       /* buff past NUL   */
    __asan_poison_memory_region(&ac_pcmd_buf[EM_MAX_CMD], 8 * sizeof(void *));  /* pcmd[16..]      */

    int ret = ac_invoke(evt, ac_pcmd_buf);

    /* UNPOISON */
    __asan_unpoison_memory_region(&ac_pcmd_buf[EM_MAX_CMD], 8 * sizeof(void *));
    __asan_unpoison_memory_region(poison_from, poison_len);

    printf("    ret=%d (expect %d) cmds=%d", ret, tc->expect_num, ac_cmd_created);
    int ok = (ret == tc->expect_num);
    if (ok && ret == 1) {
        printf(" bssid=%02x:%02x:%02x:%02x:%02x:%02x assoc=%u vp=%u cnt=%u sta0=%02x:%02x:%02x:%02x:%02x:%02x",
               ac_last_params.bssid[0], ac_last_params.bssid[1], ac_last_params.bssid[2],
               ac_last_params.bssid[3], ac_last_params.bssid[4], ac_last_params.bssid[5],
               ac_last_params.assoc_control, ac_last_params.validity_period, ac_last_params.sta_count,
               ac_last_params.sta_list[0][0], ac_last_params.sta_list[0][1], ac_last_params.sta_list[0][2],
               ac_last_params.sta_list[0][3], ac_last_params.sta_list[0][4], ac_last_params.sta_list[0][5]);
        ok = ok && ac_cmd_created == 1
              && !memcmp(ac_last_params.bssid, tc->bssid, 6)
              && ac_last_params.assoc_control == tc->assoc
              && ac_last_params.validity_period == tc->vp
              && ac_last_params.sta_count == tc->sta_count;
        if (tc->sta_count == 1 || tc->gen == 0)
            ok = ok && !memcmp(ac_last_params.sta_list[0], tc->sta0, 6);
    } else if (ret != 1) {
        ok = ok && ac_cmd_created == 0;   /* no command may be built on reject */
    }
    printf("\n");
    return ok;
}

void run_all_tests_analyze_client_assoc(void)
{
    int pass = 0, fail = 0;
    for (int i = 0; analyze_client_assoc_suite[i].test_name != NULL; i++) {
        ac_test_case_t *test = &analyze_client_assoc_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_analyze_client_assoc_input(test);
        int ok = test_analyze_client_assoc(test);
        if (ok) { pass++; printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name); }
        else    { fail++; printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name); }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
    printf("analyze_client_assoc: %d pass, %d fail\n", pass, fail);
}
