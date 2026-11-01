/*
 * TEST RUNNER: convert_variant_to_str_test
 *
 * str = &cvs_str_buf[CVS_GUARD]. Poisoned around the call:
 *   - the guard bytes BEFORE str  [0, CVS_GUARD)  -> catches the str[-1]
 *     out-of-bounds underflow write;
 *   - the bytes past str+len.
 * arr_str / arr_enum are internal static globals (auto-guarded by ASan).
 *
 * The "no_match_empty" case reproduces the bug: variant matches no arr_enum
 * entry, str is empty, so str[strlen(str)-1] == str[-1] writes into the
 * poisoned guard region and ASan aborts.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

void convert_variant_to_str(wifi_ieee80211Variant_t variant, char *str, size_t len);

int test_convert_variant_to_str(const convert_variant_to_str_test_case_t *tc)
{
    char  *str = &cvs_str_buf[CVS_GUARD];
    size_t len = CVS_STR_SZ;

    /* POISON: guard BEFORE str (catches str[-1]) and the tail after str+len */
    __asan_poison_memory_region(&cvs_str_buf[0], CVS_GUARD);
    __asan_poison_memory_region(&str[len], CVS_PAD);
    printf("    (calling with variant=0x%x, str empty)\n", tc->variant);
    fflush(stdout);

    convert_variant_to_str((wifi_ieee80211Variant_t)tc->variant, str, len);

    /* UNPOISON */
    __asan_unpoison_memory_region(&str[len], CVS_PAD);
    __asan_unpoison_memory_region(&cvs_str_buf[0], CVS_GUARD);

    printf("    variant=0x%x -> str=\"%s\"\n", tc->variant, str);
    return strcmp(str, tc->expect) == 0;
}

void run_all_tests_convert_variant_to_str(void)
{
    for (int i = 0; convert_variant_to_str_suite[i].test_name != NULL; i++) {
        convert_variant_to_str_test_case_t *test = &convert_variant_to_str_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_convert_variant_to_str_input(test);
        int pass = test_convert_variant_to_str(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m (expected \"%s\") =====\n", test->test_name, test->expect);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
