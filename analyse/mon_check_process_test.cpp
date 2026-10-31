/*
 * TEST RUNNER: mon_check_process_test
 *
 * The arrays under test (sigstr[64], sig_default[16]) are local stack
 * arrays that ASan brackets with red-zones, so nothing is poisoned here:
 * an out-of-bounds write by mon_sig_str aborts on its own. The runner
 * drives each forked child and checks mon_check_process's return value and
 * the *exit_status it reports.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

bool mon_check_process(pid_t child, int *exit_status);
void mon_sig_str(int signum, char *sigstr, size_t sigstr_sz);

#define MON_SIGSTR_SZ 64   /* same as monitor.c:58 */

/*
 * base64_encode-style explicit poison check for the array mon_check_process
 * actually fills (via mon_sig_str). We own a buffer LARGER than the size we
 * hand to mon_sig_str, poison everything at/above that size, and call it: if
 * mon_sig_str writes past the MON_SIGSTR_SZ it was told, ASan aborts here.
 * (mon_check_process itself takes no caller buffer, so this is where an
 * explicit poison/unpoison is meaningful.)
 */
static char moncp_sigbuf[256];

static void poisoned_mon_sig_str_check(int sig)
{
    __asan_poison_memory_region(&moncp_sigbuf[MON_SIGSTR_SZ],
                                sizeof(moncp_sigbuf) - MON_SIGSTR_SZ);

    mon_sig_str(sig, moncp_sigbuf, MON_SIGSTR_SZ);

    __asan_unpoison_memory_region(&moncp_sigbuf[MON_SIGSTR_SZ],
                                  sizeof(moncp_sigbuf) - MON_SIGSTR_SZ);

    printf("    mon_sig_str(%d) -> \"%s\"\n", sig, moncp_sigbuf);
}

/* returns 1 if the observed (ret,status) matched the expectation */
int test_mon_check_process(const mon_cp_test_case_t *tc)
{
    /* explicit poisoned-buffer check of the signal->string array path */
    if (tc->kind == MONCP_SIGNAL) {
        int sig = (tc->param < 0) ? (SIGRTMIN + 3) : tc->param;
        poisoned_mon_sig_str_check(sig);
    }

    int exit_status = -999;
    bool ret = mon_check_process(moncp_child, &exit_status);

    printf("ret=%s exit_status=%d\n", ret ? "true(alive)" : "false(dead)", exit_status);

    /* ALIVE case: child still running -> kill and reap it now */
    if (tc->kind == MONCP_ALIVE) {
        kill(moncp_child, SIGKILL);
        int st;
        waitpid(moncp_child, &st, 0);
    }

    int ret_i = ret ? 1 : 0;
    return (ret_i == tc->expected_ret && exit_status == tc->expected_status) ? 1 : 0;
}

void run_all_tests_mon_check_process(void)
{
    for (int i = 0; mon_check_process_suite[i].test_name != NULL; i++) {
        mon_cp_test_case_t *test = &mon_check_process_suite[i];

        printf("--- Running Test: %s ---\n", test->test_name);

        construct_mon_check_process_input(test);

        int ok = test_mon_check_process(test);

        if (ok) {
            printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        } else {
            printf("===== %s: \033[31mFAIL\033[0m (expected ret=%d status=%d) =====\n",
                   test->test_name, test->expected_ret, test->expected_status);
        }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
