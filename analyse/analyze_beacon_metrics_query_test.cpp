/*
 * TEST RUNNER: analyze_beacon_metrics_query_test
 *
 * Poisoned around the call:
 *   - the caller's subdoc.buff: bytes past strlen+1 (cJSON_Parse / strchr /
 *     sscanf / string_to_macbytes reading past the NUL);
 *   - the caller's pcmd[]: slots from EM_MAX_CMD onward;
 *   - evt->guard: the bytes right after the caller's params struct, so a write
 *     past the end of ap_channel_rprt[16] / element_list[32] / ssid[32] aborts.
 * bssid_mac[6] and the cJSON objects are internal (ASan redzones / heap).
 * PASS = return value matches expect_num and, when accepted, the parsed
 * sta_mac / op_class / channel / bssid / rprt_detail / ssid_len /
 * num_ap_channel_rprt / num_element_id match.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

namespace abq {

int test_one(const test_case_t *tc)
{
    em_bus_event_t *evt = (em_bus_event_t *)evt_buf;
    char *buff = evt->u.subdoc.buff;
    size_t blen = strlen(buff) + 1;
    char *poison_from = buff + blen;
    size_t poison_len = (size_t)((evt_buf + ABQ_EVT_SZ) - poison_from);

    /* POISON */
    __asan_poison_memory_region(poison_from, poison_len);                       /* buff past NUL   */
    __asan_poison_memory_region(&pcmd_buf[EM_MAX_CMD], 8 * sizeof(void *));     /* pcmd[16..]      */
    __asan_poison_memory_region(evt->guard, sizeof(evt->guard));                /* past params     */

    int ret = invoke(evt, pcmd_buf);

    /* UNPOISON */
    __asan_unpoison_memory_region(evt->guard, sizeof(evt->guard));
    __asan_unpoison_memory_region(&pcmd_buf[EM_MAX_CMD], 8 * sizeof(void *));
    __asan_unpoison_memory_region(poison_from, poison_len);

    printf("    ret=%d (expect %d) cmds=%d", ret, tc->expect_num, cmd_created);
    int ok = (ret == tc->expect_num);
    if (ok && ret == 1) {
        const em_cmd_beacon_metrics_param_t *p = &last_params;
        printf(" sta=%02x:%02x:%02x:%02x:%02x:%02x opc=%u ch=%u bssid=%02x:%02x:%02x:%02x:%02x:%02x rd=%u slen=%u apc=%u nel=%u",
               p->sta_mac_addr[0], p->sta_mac_addr[1], p->sta_mac_addr[2], p->sta_mac_addr[3], p->sta_mac_addr[4], p->sta_mac_addr[5],
               p->op_class, p->channel_num,
               p->bssid[0], p->bssid[1], p->bssid[2], p->bssid[3], p->bssid[4], p->bssid[5],
               p->rprt_detail, p->ssid_len, p->num_ap_channel_rprt, p->element_list.num_element_id);
        ok = cmd_created == 1
          && !memcmp(p->sta_mac_addr, tc->sta_mac, 6)
          && p->op_class == tc->op_class && p->channel_num == tc->channel
          && !memcmp(p->bssid, tc->bssid, 6)
          && p->rprt_detail == tc->rd && p->ssid_len == tc->ssid_len
          && p->num_ap_channel_rprt == tc->num_apc
          && p->element_list.num_element_id == tc->num_el;
    } else if (ret != 1) {
        ok = ok && cmd_created == 0;   /* no command may be built on reject */
    }
    printf("\n");
    return ok;
}

} /* namespace abq */

void run_all_tests_analyze_beacon_metrics_query(void)
{
    int pass = 0, fail = 0;
    for (int i = 0; abq::suite[i].test_name != NULL; i++) {
        abq::test_case_t *test = &abq::suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        abq::construct_input(test);
        int ok = abq::test_one(test);
        if (ok) { pass++; printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name); }
        else    { fail++; printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name); }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
    printf("analyze_beacon_metrics_query: %d pass, %d fail\n", pass, fail);
}
