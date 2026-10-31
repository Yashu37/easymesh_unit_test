/*
 * TEST RUNNER: log_severity_parse_sink_test
 *
 * The caller-owned input is sevstr. We poison its tail past the terminator
 * so any over-read is flagged. The internal psevstr[256] is auto-guarded by
 * ASan (and the too_long/fill_255 cases stress the length guard + copy).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

extern "C" bool log_severity_parse_sink(int sink, char *sevstr);  /* sink is int at the ABI */

int test_log_sev(const log_sev_test_case_t *tc)
{
    char *in = lsp_null ? NULL : lsp_in;

    if (!lsp_null)
        __asan_poison_memory_region(&lsp_in[lsp_in_len + 1],
                                    sizeof(lsp_in) - (lsp_in_len + 1));

    bool ret = log_severity_parse_sink(0 /* LOG_SINK_LOCAL */, in);

    if (!lsp_null)
        __asan_unpoison_memory_region(&lsp_in[lsp_in_len + 1],
                                      sizeof(lsp_in) - (lsp_in_len + 1));

    printf("    ret=%d (default_set=%d sev_set=%d mod_sev_set=%d)\n",
           ret, lsp_default_set, lsp_sev_set, lsp_mod_sev_set);
    return ret ? 1 : 0;
}

void run_all_tests_log_sev(void)
{
    for (int i = 0; log_sev_suite[i].test_name != NULL; i++) {
        log_sev_test_case_t *test = &log_sev_suite[i];

        printf("--- Running Test: %s ---\n", test->test_name);

        lsp_default_set = lsp_sev_set = lsp_mod_sev_set = 0;
        construct_log_sev_input(test);

        int got = test_log_sev(test);

        if (got == test->expect_ret) {
            printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        } else {
            printf("===== %s: \033[31mFAIL\033[0m (expected=%d, got=%d) =====\n",
                   test->test_name, test->expect_ret, got);
        }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
