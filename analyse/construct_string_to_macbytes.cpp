/*
 * TEST CASES / CONSTRUCTOR: construct_string_to_macbytes
 *
 * key lives in key_store at offset STM_LEFT (runner poisons the bytes in front of it and past its NUL); bmac sits in
 * bmac_store between STM_GUARD poisoned bytes on each side and is pre-filled with 0x5a. expect_mac is compared with bmac
 * afterwards; "5a:5a:5a:5a:5a:5a" means bmac must be left unchanged.
 * The handler picks the format by length only (> 12 chars = colon format, else 12 hex digits) and copies its
 * UNINITIALISED mac[6] into bmac when sscanf matches fewer than 6 fields: those cases (marked [spec]) write stack garbage
 * (whatever is on the stack: 0x00 / partial values here) into bmac and fail, there is no abort.
 * The rej_key_null / rej_bmac_null / rej_key_and_bmac_null cases ABORTED on the original handler (NULL key -> strlen, NULL bmac
 * -> store); fix 1 makes the function return.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "string_to_macbytes.h"

namespace stm {
alignas(16) char key_store[STM_LEFT + STM_KEY_SZ + STM_PAD];
alignas(16) unsigned char bmac_store[STM_GUARD + 6 + STM_GUARD];

#define UNCH "5a:5a:5a:5a:5a:5a"
/* {name, key, key_null, bmac_null, expect_mac, crash} */
test_case_t suite[] = {
 {"ok_colon_lower",                    "02:00:00:00:00:aa", false, false, "02:00:00:00:00:aa", false},
 {"ok_colon_upper",                    "02:00:00:00:00:AA", false, false, "02:00:00:00:00:aa", false},
 {"ok_colon_all_ff",                   "ff:ff:ff:ff:ff:ff", false, false, "ff:ff:ff:ff:ff:ff", false},
 {"ok_colon_all_zero",                 "00:00:00:00:00:00", false, false, "00:00:00:00:00:00", false},
 {"ok_colon_mixed_bytes",              "01:23:45:67:89:ab", false, false, "01:23:45:67:89:ab", false},
 {"ok_compact_12_lower",               "0200000000aa", false, false, "02:00:00:00:00:aa", false},
 {"ok_compact_12_upper",               "0200000000AA", false, false, "02:00:00:00:00:aa", false},
 {"ok_compact_all_zero",               "000000000000", false, false, "00:00:00:00:00:00", false},
 {"ok_compact_all_ff",                 "ffffffffffff", false, false, "ff:ff:ff:ff:ff:ff", false},
 {"ok_colon_with_al_suffix",           "02:00:00:00:00:aa_al", false, false, "02:00:00:00:00:aa", false},
 {"ok_colon_with_trailing_text",       "aa:bb:cc:dd:ee:ff extra", false, false, "aa:bb:cc:dd:ee:ff", false},
 {"ok_colon_one_digit_fields_13_chars","02:0:0:0:0:aa", false, false, "02:00:00:00:00:aa", false},
 /* ---- [spec]: malformed input, bmac must stay unchanged, the handler copies uninitialised stack bytes ---- */
 {"spec_empty_key [spec]",             "", false, false, UNCH, false},
 {"spec_not_hex_short [spec]",         "zz", false, false, UNCH, false},
 {"spec_not_hex_13_chars [spec]",      "not-a-mac-str", false, false, UNCH, false},
 {"spec_compact_11_digits [spec]",     "0200000000a", false, false, UNCH, false},
 {"spec_compact_with_al_suffix_15 [spec]", "0200000000aa_al", false, false, UNCH, false},
 {"spec_colon_short_3_fields [spec]",  "02:00:00", false, false, UNCH, false},
 {"spec_dash_separated [spec]",        "02-00-00-00-00-aa", false, false, UNCH, false},
 {"spec_colon_one_digit_11_chars [spec]", "a:b:c:d:e:f", false, false, UNCH, false},
 {"spec_colon_5_fields [spec]",        "02:00:00:00:00", false, false, UNCH, false},
 {"spec_colon_last_field_missing [spec]", "02:00:00:00:00:", false, false, UNCH, false},
 {"ok_leading_space_skipped_by_sscanf", " 02:00:00:00:00:aa", false, false, "02:00:00:00:00:aa", false},
 /* ---- were CRASH cases on the original handler (now return without touching bmac) ---- */
 {"rej_key_null",                      NULL, true,  false, UNCH, false},
 {"rej_bmac_null",                   "02:00:00:00:00:aa", false, true, NULL, false},
 {"rej_key_and_bmac_null",           NULL, true,  true,  NULL, false},
 {NULL, NULL, false, false, NULL, false}
};

void construct_input(const test_case_t *tc)
{
    memset(key_store, 0, sizeof(key_store));
    if (tc->key) snprintf(key_store + STM_LEFT, STM_KEY_SZ, "%s", tc->key);
    memset(bmac_store, 0, sizeof(bmac_store));
    memset(bmac_store + STM_GUARD, STM_SENTINEL, 6);
}
void teardown(void) {}
} /* namespace stm */
