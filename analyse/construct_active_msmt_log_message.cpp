/*
 * TEST CASES / CONSTRUCTOR: construct_active_msmt_log_message
 *
 * Every case calls the function the way wifi_blaster.c:873 does:
 *   active_msmt_log_message(level,
 *       "%s:%d no need to start pktgen for offline client: %s\n",
 *       "SetActiveMsmtStepSrcMac", 873, DstMac);
 * with DstMac copied into aml_arg_buf (runner poisons past its NUL).
 *
 * Cases: info level, debug level, unknown level (no trace hook), a 2000-char
 * argument (msg truncated to 1023), and a DstMac that itself contains a "%s"
 * (passed as a normal %s arg, so it lands in msg as literal text).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

char   aml_slot[AML_SLOT_SZ + AML_PAD];
size_t aml_msg_len;
char   aml_dbg_out[4096];
char   aml_trace_out[2048];
int    aml_trace_calls;
alignas(16) char aml_arg_buf[AML_ARG_MAX + AML_PAD];
alignas(16) char aml_mgr_buf[sizeof(wifi_mgr_t) + AML_PAD];

static void aml_trace_info(char *m)  { aml_trace_calls++; snprintf(aml_trace_out, sizeof(aml_trace_out), "INFO:%s", m); }
static void aml_trace_debug(char *m) { aml_trace_calls++; snprintf(aml_trace_out, sizeof(aml_trace_out), "DBG:%s", m); }

blaster_log_level_t aml_levels[] = { BLASTER_INFO_LOG, BLASTER_DEBUG_LOG, (blaster_log_level_t)9, BLASTER_DEBUG_LOG, BLASTER_DEBUG_LOG };

active_msmt_log_message_test_case_t active_msmt_log_message_suite[] = {
    /* name            level_idx dst_mac               big  expect_trace expect_contains                 */
    { "info_level",      0,      "aa:bb:cc:dd:ee:ff",  0,   1,  "INFO:SetActiveMsmtStepSrcMac:873 no need to start pktgen for offline client: aa:bb:cc:dd:ee:ff" },
    { "debug_level",     1,      "10:11:12:13:14:15",  0,   1,  "DBG:SetActiveMsmtStepSrcMac:873 no need to start pktgen for offline client: 10:11:12:13:14:15"  },
    { "unknown_level",   2,      "01:02:03:04:05:06",  0,   0,  ""                                                                                              },
    { "big_truncated",   3,      NULL,                 1,   1,  "DBG:"                                                                                          },
    { "percent_in_arg",  4,      "%s%s%n",             0,   1,  "DBG:SetActiveMsmtStepSrcMac:873 no need to start pktgen for offline client: %s%s%n"             },

    { NULL, 0, NULL, 0, 0, NULL }  /* sentinel */
};

void construct_active_msmt_log_message_input(const active_msmt_log_message_test_case_t *tc)
{
    memset(aml_arg_buf, 0, sizeof(aml_arg_buf));
    if (tc->big) {
        memset(aml_arg_buf, 'y', 2000);
        aml_arg_buf[2000] = 0;
    } else {
        snprintf(aml_arg_buf, AML_ARG_MAX, "%s", tc->dst_mac);
    }

    memset(aml_mgr_buf, 0, sizeof(aml_mgr_buf));
    wifi_mgr_t *m = (wifi_mgr_t *)aml_mgr_buf;
    m->wifi_ccsp.desc.CcspTraceInfoRdkb_fn  = aml_trace_info;
    m->wifi_ccsp.desc.CcspTraceDebugRdkb_fn = aml_trace_debug;

    aml_msg_len = 0;
    aml_trace_calls = 0;
    aml_dbg_out[0] = 0;
    aml_trace_out[0] = 0;
}
