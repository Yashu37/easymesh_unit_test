/*
 * TEST RUNNER: radio_get_name_from_cfg_test
 *
 * The caller-owned input is radio_cfg (in rgn_backing). We poison:
 *   - the phy_name tail past its terminator (over-read guard on %s), and
 *   - the memory past the radio_entry_t struct.
 * The returned string is an internal static array (auto-guarded by ASan).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

char *radio_get_name_from_cfg(radio_entry_t *radio_cfg);

int test_radio_name(const radio_name_test_case_t *tc)
{
    radio_entry_t *cfg = (radio_entry_t *)rgn_backing;

    /* poison phy_name tail past the terminator (over-read guard) */
    size_t off = (size_t)((char *)cfg->phy_name - (char *)rgn_backing) + rgn_phy_len + 1;
    __asan_poison_memory_region(&rgn_backing[off], sizeof(rgn_backing) - off);
    /* poison memory past the struct */
    __asan_poison_memory_region(&rgn_backing[sizeof(radio_entry_t)],
                                sizeof(rgn_backing) - sizeof(radio_entry_t));

    char *out = radio_get_name_from_cfg(rgn_null_cfg ? NULL : cfg);

    __asan_unpoison_memory_region(&rgn_backing[sizeof(radio_entry_t)],
                                  sizeof(rgn_backing) - sizeof(radio_entry_t));
    __asan_unpoison_memory_region(&rgn_backing[off], sizeof(rgn_backing) - off);

    int nonnull = (out != NULL) ? 1 : 0;
    printf("    out=%s\n", out ? out : "(NULL)");
    return nonnull;
}

void run_all_tests_radio_name(void)
{
    for (int i = 0; radio_name_suite[i].test_name != NULL; i++) {
        radio_name_test_case_t *test = &radio_name_suite[i];

        printf("--- Running Test: %s ---\n", test->test_name);

        construct_radio_name_input(test);

        int got = test_radio_name(test);

        if (got == test->expect_nonnull) {
            printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        } else {
            printf("===== %s: \033[31mFAIL\033[0m (expected nonnull=%d, got=%d) =====\n",
                   test->test_name, test->expect_nonnull, got);
        }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
