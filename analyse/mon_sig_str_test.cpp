/*
 * TEST RUNNER: mon_sig_str_test
 *
 * mon_sig_str takes a caller-owned buffer, so this is a DIRECT
 * poison/unpoison case (base64_encode style): we own mss_buf[256], poison
 * every byte at/above the sigstr_sz we pass in, then call mon_sig_str with
 * that smaller size. If it writes past the size it was told, ASan aborts.
 * The local sig_default[16] inside the function is auto-guarded by ASan.
 *
 * PASS invariant: with sigstr_sz > 0, snprintf must NUL-terminate within
 * the buffer, i.e. strlen(result) < sigstr_sz.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

void mon_sig_str(int signum, char *sigstr, size_t sigstr_sz);

static char mss_buf[256];

int test_mon_sig_str(void)
{
    size_t sz = mss_size;

    /* poison everything the function is NOT allowed to touch */
    __asan_poison_memory_region(&mss_buf[sz], sizeof(mss_buf) - sz);

    mon_sig_str(mss_signum, mss_buf, sz);

    /* read the result length while still inside the allowed region */
    int ok;
    size_t n = 0;
    if (sz == 0) {
        ok = 1;                         /* nothing may be written */
    } else {
        n = strnlen(mss_buf, sz);
        ok = (n < sz) ? 1 : 0;          /* must be NUL-terminated within sz */
        printf("    signum=%d size=%zu -> \"%.*s\" (len=%zu)\n",
               mss_signum, sz, (int)n, mss_buf, n);
    }

    __asan_unpoison_memory_region(&mss_buf[sz], sizeof(mss_buf) - sz);
    return ok;
}

void run_all_tests_mon_sig_str(void)
{
    for (int i = 0; mon_sig_str_suite[i].test_name != NULL; i++) {
        mon_sig_str_test_case_t *test = &mon_sig_str_suite[i];

        printf("--- Running Test: %s ---\n", test->test_name);

        construct_mon_sig_str_input(test);

        int ok = test_mon_sig_str();

        if (ok) {
            printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        } else {
            printf("===== %s: \033[31mFAIL\033[0m (result not terminated within size) =====\n",
                   test->test_name);
        }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
