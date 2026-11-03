/*
 * TEST CASES / CONSTRUCTOR: construct_get_max_probe_ttl_cnt
 * The "file" is gmt_file_buf (GMT_FILE_SZ + GMT_PAD); its content is
 * tc->content repeated tc->repeat times (capped at GMT_FILE_SZ). The runner
 * poisons everything past the content, so a read past the end would trip.
 * Cases: no_file, normal_nl, zero_nl, no_newline, long_alpha_line (400 chars,
 * longer than buff[64]), long_digit_line (400 digits).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

char   gmt_file_buf[GMT_FILE_SZ + GMT_PAD];
size_t gmt_file_len;
int    gmt_have_file;

lv_gmt_test_case_t get_max_probe_ttl_cnt_suite[] = {
    /* name              content   repeat have  want */
    { "no_file",         "",         0,   0,   500 },
    { "normal_nl",       "10\n",     1,   1,    10 },
    { "zero_nl",         "0\n",      1,   1,   500 },
    { "no_newline",      "25",       1,   1,    25 },
    { "long_alpha_line", "A",      400,   1,   500 },
    { "long_digit_line", "7",      400,   1,   0xFFFFFFFFu },  /* value not checked (atoi overflow) */
    { NULL, NULL, 0, 0, 0 }  /* sentinel */
};

void construct_get_max_probe_ttl_cnt_input(const lv_gmt_test_case_t *tc)
{
    memset(gmt_file_buf, 0, sizeof(gmt_file_buf));
    gmt_have_file = tc->have_file;
    gmt_file_len = 0;
    size_t clen = strlen(tc->content);
    for (int i = 0; i < tc->repeat && gmt_file_len + clen <= GMT_FILE_SZ; i++) {
        memcpy(gmt_file_buf + gmt_file_len, tc->content, clen);
        gmt_file_len += clen;
    }
}
