/*
 * TEST CASES / CONSTRUCTOR: construct_ovsdb_tran_comment
 *
 * The global ovsdb_comment points at otc_comment_buf (2048 bytes, filled
 * per case; tail past the NUL poisoned by the runner) or is NULL.
 * where is a 2-D JSON array of strings; long cases overflow the 128-byte
 * comment many times over (all appends must truncate at 127).
 *
 * Cases: comment NULL, each op (insert/update/mutate/delete), an
 * unsupported op (select -> no comment), where NULL, a where row that is
 * not an array, a non-string element, a 127/128/500-char ovsdb_comment,
 * and 30 where pairs of 100-char strings.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jansson.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

char  otc_comment_buf[OTC_BUF_SZ];
char *ovsdb_comment;

ovsdb_tran_comment_test_case_t ovsdb_tran_comment_suite[] = {
    /* name                 cnull clen oper where_kind  ret appended */
    { "comment_null",         1,    2,  0,   1,          1,   0 },
    { "insert",               0,    2,  0,   1,          1,   1 },
    { "update",               0,    2,  2,   1,          1,   1 },
    { "mutate",               0,    2,  3,   1,          1,   1 },
    { "delete",               0,    2,  4,   1,          1,   1 },
    { "select_unsupported",   0,    2,  1,   1,          1,   0 },
    { "where_null",           0,    2,  2,   0,          1,   1 },
    { "where_row_not_array",  0,    2,  2,   2,          1,   1 },
    { "where_non_string",     0,    2,  2,   3,          1,   1 },
    { "comment_127",          0,  127,  2,   1,          1,   1 },
    { "comment_128",          0,  128,  2,   1,          1,   1 },
    { "comment_500",          0,  500,  2,   1,          1,   1 },
    { "where_30x100",         0,    2,  2,   4,          1,   1 },

    { NULL, 0, 0, 0, 0, 0, 0 }  /* sentinel */
};

void *construct_ovsdb_tran_comment_where(const ovsdb_tran_comment_test_case_t *tc)
{
    switch (tc->where_kind) {
    case 1: return json_pack("[[s,s,s]]", "if_name", "==", "wl0");
    case 2: return json_pack("[s,[s,s,s]]", "bogus", "if_name", "==", "wl0");
    case 3: return json_pack("[[s,i,n]]", "if_name", 5);
    case 4: {
        json_t *w = json_array();
        char s[101]; memset(s, 'w', 100); s[100] = 0;
        for (int i = 0; i < 30; i++) json_array_append_new(w, json_pack("[s,s,s]", s, "==", s));
        return w;
    }
    default: return NULL;
    }
}

void construct_ovsdb_tran_comment_input(const ovsdb_tran_comment_test_case_t *tc)
{
    memset(otc_comment_buf, 0, sizeof(otc_comment_buf));
    if (tc->comment_len == 2) snprintf(otc_comment_buf, sizeof(otc_comment_buf), "em");
    else memset(otc_comment_buf, 'c', (size_t)tc->comment_len);
    ovsdb_comment = tc->comment_null ? NULL : otc_comment_buf;
}
