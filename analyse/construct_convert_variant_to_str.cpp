/*
 * TEST CASES / CONSTRUCTOR: construct_convert_variant_to_str
 *
 * str points INTO cvs_str_buf at offset CVS_GUARD, so the runner can poison
 * the bytes BEFORE str (to catch the str[-1] underflow) as well as past len.
 * str starts empty (as the caller's zeroed Operating_standard field).
 *
 * Cases: single valid variants (-> "a" / "ax"), then the bug trigger: a
 * variant whose bits match NO arr_enum entry (WIFI_80211_VARIANT_H 0x10)
 * with an empty str, which makes str[strlen(str)-1] write to str[-1].
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

alignas(16) char cvs_str_buf[CVS_GUARD + CVS_STR_SZ + CVS_PAD];

convert_variant_to_str_test_case_t convert_variant_to_str_suite[] = {
    /* name            variant  expect   underflow */
    { "variant_a",     0x01,    "a",      0 },
    { "variant_ax",    0x80,    "ax",     0 },
    { "no_match_empty",0x10,    "",       0 },   /* after fix: str stays empty, no underflow */

    { NULL, 0, NULL, 0 }  /* sentinel */
};

void construct_convert_variant_to_str_input(const convert_variant_to_str_test_case_t *tc)
{
    memset(cvs_str_buf, 0, sizeof(cvs_str_buf));   /* str starts empty */
    (void)tc;
}
