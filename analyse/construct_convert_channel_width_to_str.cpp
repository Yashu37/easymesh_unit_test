/*
 * TEST CASES / CONSTRUCTOR: construct_convert_channel_width_to_str
 *
 * str is the caller's output buffer at ccw_str_buf (runner poisons past the
 * declared len). The buffer is pre-filled with 'Z' so a no-match case leaves
 * it unchanged (nothing is written when cw matches no enum).
 *
 * Cases: each known bandwidth (20/40/80/160), an unknown value (no write),
 * and a tiny len=2 that truncates "160" -> "1".
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

alignas(16) char ccw_str_buf[CCW_STR_SZ + CCW_PAD];

convert_channel_width_to_str_test_case_t convert_channel_width_to_str_suite[] = {
    /* name          cw     len          expect   */
    { "bw_20",       0x1,   CCW_STR_SZ,  "20"     },
    { "bw_40",       0x2,   CCW_STR_SZ,  "40"     },
    { "bw_80",       0x4,   CCW_STR_SZ,  "80"     },
    { "bw_160",      0x8,   CCW_STR_SZ,  "160"    },
    { "bw_unknown",  0x400, CCW_STR_SZ,  "ZZZ"    },   /* no match -> buffer unchanged */
    { "len_trunc",   0x8,   2,           "1"      },   /* "160" truncated into len 2 */

    { NULL, 0, 0, NULL }  /* sentinel */
};

void construct_convert_channel_width_to_str_input(const convert_channel_width_to_str_test_case_t *tc)
{
    memset(ccw_str_buf, 0, sizeof(ccw_str_buf));
    memset(ccw_str_buf, 'Z', 3);   /* sentinel content for the no-match case */
    ccw_str_buf[3] = 0;
}
