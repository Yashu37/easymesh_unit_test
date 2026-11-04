/*
 * TEST RUNNER: levl_csi_publish
 *
 * Poisoned around the call:
 *   - the caller's mac_address buffer (lcp_mac_buf) past the 6-byte mac;
 *   - the caller's wifi_csi_dev_t (lcp_csi_buf) past sizeof(wifi_csi_dev_t):
 *     the header is built in place and then CSI_HEADER_SIZE +
 *     sizeof(wifi_csi_data_t) bytes are read from it, so any longer write/read
 *     would trip;
 *   - the wifi_ctrl_t and levl wifi_app stand-ins past their sizes.
 * eventName[200] is an internal stack array guarded by ASan redzones.
 *
 * PASS = publish / open / write counts match, and (when a frame was sent) the
 * header starts with "CSI", the length field equals the published size and
 * the CSI payload follows unchanged.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

void levl_csi_publish(mac_address_t mac_address, wifi_csi_dev_t *csi_dev_data);

int test_levl_csi_publish(const lv_lcp_test_case_t *tc)
{
    /* POISON */
    __asan_poison_memory_region(&lcp_mac_buf[6], LCP_PAD);
    __asan_poison_memory_region(&lcp_csi_buf[sizeof(wifi_csi_dev_t)], LCP_PAD);
    __asan_poison_memory_region(&lcp_ctrl_buf[sizeof(wifi_ctrl_t)], LCP_PAD);
    __asan_poison_memory_region(&lcp_app_buf[sizeof(struct wifi_app)], LCP_PAD);

    levl_csi_publish((unsigned char *)lcp_mac_buf, (wifi_csi_dev_t *)lcp_csi_buf);

    /* UNPOISON */
    __asan_unpoison_memory_region(&lcp_app_buf[sizeof(struct wifi_app)], LCP_PAD);
    __asan_unpoison_memory_region(&lcp_ctrl_buf[sizeof(wifi_ctrl_t)], LCP_PAD);
    __asan_unpoison_memory_region(&lcp_csi_buf[sizeof(wifi_csi_dev_t)], LCP_PAD);
    __asan_unpoison_memory_region(&lcp_mac_buf[6], LCP_PAD);

    unsigned int want_len = CSI_HEADER_SIZE + sizeof(wifi_csi_data_t);
    int ok = (lcp_pub_calls == tc->want_pub) && (lcp_open_calls == tc->want_open) &&
             (lcp_write_calls == tc->want_write);
    if (tc->want_hdr) {
        unsigned int got_len = lcp_pub_calls ? lcp_pub_len : lcp_write_len;
        unsigned int total = 0;
        memcpy(&total, lcp_sink + 4, sizeof(total));
        ok = ok && memcmp(lcp_sink, "CSI", 4) == 0 && got_len == want_len &&
             total == (unsigned int)(sizeof(time_t) + sizeof(unsigned int) + 6 + sizeof(unsigned int) + sizeof(wifi_csi_data_t)) &&
             lcp_sink[CSI_HEADER_SIZE] == 0x5A && lcp_sink[want_len - 1] == 0x5A;
    }
    printf("    publish=%d open=%d write=%d len=%u sink=\"%.3s\" event=\"%s\"\n", lcp_pub_calls,
           lcp_open_calls, lcp_write_calls, lcp_pub_calls ? lcp_pub_len : lcp_write_len, lcp_sink, lcp_pub_name);
    return ok;
}

void run_all_tests_levl_csi_publish(void)
{
    for (int i = 0; levl_csi_publish_suite[i].test_name != NULL; i++) {
        lv_lcp_test_case_t *test = &levl_csi_publish_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_levl_csi_publish_input(test);
        int pass = test_levl_csi_publish(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
