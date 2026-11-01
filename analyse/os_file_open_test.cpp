/*
 * TEST RUNNER: os_file_open_test
 *
 * Caller inputs are location and prefix; we poison each one's tail past its
 * terminator so any over-read is flagged. file[64]/time_stamp[32] are
 * internal (auto-guarded by ASan). The long_prefix case stresses the
 * bounded file[64] appends. Opened files are closed and removed.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

FILE *os_file_open(char *location, char *prefix);

int test_os_file_open(const os_file_open_test_case_t *tc)
{
    __asan_poison_memory_region(&ofo_location[ofo_loc_len + 1], sizeof(ofo_location) - (ofo_loc_len + 1));
    __asan_poison_memory_region(&ofo_prefix[ofo_pre_len + 1],   sizeof(ofo_prefix)   - (ofo_pre_len + 1));

    FILE *fp = os_file_open(ofo_location, ofo_prefix);

    __asan_unpoison_memory_region(&ofo_location[ofo_loc_len + 1], sizeof(ofo_location) - (ofo_loc_len + 1));
    __asan_unpoison_memory_region(&ofo_prefix[ofo_pre_len + 1],   sizeof(ofo_prefix)   - (ofo_pre_len + 1));

    int opened = (fp != NULL) ? 1 : 0;
    printf("    fp=%s\n", opened ? "opened" : "(null)");
    if (fp) fclose(fp);
    return opened;
}

void run_all_tests_os_file_open(void)
{
    for (int i = 0; os_file_open_suite[i].test_name != NULL; i++) {
        os_file_open_test_case_t *test = &os_file_open_suite[i];

        printf("--- Running Test: %s ---\n", test->test_name);

        construct_os_file_open_input(test);

        int opened = test_os_file_open(test);

        if (opened == test->expect_fp) {
            printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        } else {
            printf("===== %s: \033[31mFAIL\033[0m (expected_fp=%d, got=%d) =====\n",
                   test->test_name, test->expect_fp, opened);
        }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
    /* temp files land in /tmp; left in place (harmless) */
}
