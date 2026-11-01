/*
 * TEST CASES / CONSTRUCTOR: construct_analytics_event_hal_channel_change
 *
 * arg is a packed wifi_channel_change_event_t at the start of acc_arg_buf
 * (bytes past its size poisoned by the runner).
 *
 * Cases: plain channel change, every DFS sub_event 0..5 (dfs_states[0..5]),
 * sub_event 6 (one past the table), sub_event 0xFFFFFFFF (a "negative"
 * value), and the longest line ("PRE-CAC expired" + UINT_MAX channel /
 * INT_MIN bw / UINT_MAX radio, printed with %d).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "common.h"

char   acc_slot[ACC_SLOT_SZ + ACC_PAD];
size_t acc_len;
int    acc_calls;
alignas(16) char acc_arg_buf[sizeof(wifi_channel_change_event_t) + ACC_PAD];

analytics_event_hal_channel_change_test_case_t analytics_event_hal_channel_change_suite[] = {
    /* name                event                          sub_event     channel    bw        radio     prefix              */
    { "channel_change",    WIFI_EVENT_CHANNELS_CHANGED,   0,            36,        2,        1,        "ch:36"            },
    { "radar_detected",    WIFI_EVENT_DFS_RADAR_DETECTED, 0,            52,        1,        1,        "Radar detected"   },
    { "cac_finished",      WIFI_EVENT_DFS_RADAR_DETECTED, 1,            52,        1,        1,        "CAC finished"     },
    { "cac_aborted",       WIFI_EVENT_DFS_RADAR_DETECTED, 2,            52,        1,        1,        "CAC aborted"      },
    { "nop_finished",      WIFI_EVENT_DFS_RADAR_DETECTED, 3,            52,        1,        1,        "NOP finished"     },
    { "pre_cac_expired",   WIFI_EVENT_DFS_RADAR_DETECTED, 4,            52,        1,        1,        "PRE-CAC expired"  },
    { "cac_started",       WIFI_EVENT_DFS_RADAR_DETECTED, 5,            52,        1,        1,        "CAC started"      },
    { "sub_event_6",       WIFI_EVENT_DFS_RADAR_DETECTED, 6,            52,        1,        1,        "Unknown"          },
    { "sub_event_neg",     WIFI_EVENT_DFS_RADAR_DETECTED, 0xFFFFFFFFu,  52,        1,        1,        "Unknown"          },
    { "longest_line",      WIFI_EVENT_DFS_RADAR_DETECTED, 4,            UINT_MAX,  INT_MIN,  UINT_MAX, "PRE-CAC expired"  },

    { NULL, 0, 0, 0, 0, 0, NULL }  /* sentinel */
};

void construct_analytics_event_hal_channel_change_input(const analytics_event_hal_channel_change_test_case_t *tc)
{
    memset(acc_arg_buf, 0, sizeof(acc_arg_buf));
    wifi_channel_change_event_t *c = (wifi_channel_change_event_t *)acc_arg_buf;
    c->radioIndex = tc->radio;
    c->event = (wifi_chan_eventType_t)tc->event;
    c->sub_event = (wifi_radar_eventType_t)tc->sub_event;
    c->channel = tc->channel;
    c->channelWidth = tc->bw;
    c->op_class = 115;
    acc_len = 0;
    acc_calls = 0;
}
