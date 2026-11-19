/*
 * TEST RUNNER: apmld_tget_params_test
 *
 * Poisoned around the call:
 *   - the bytes in front of root (APT_ROOT_LEFT) and past its NUL - catches a read outside the root string;
 *   - dm->before[] / dm->after[], the members in front of and after dm->m_ap_mld[64] - catches the loop
 *     running to the raw m_num_ap_mld when it is above 64;
 *   - every m_ap_mld[] entry that is not in use (index >= min(count, 64)) - the handler must not read entries
 *     past the count;
 *   - every used entry's rest_of_struct[] (members the handler never reads).
 * path[512] is a local array guarded by an ASan redzone (root of 600 characters is truncated by snprintf).
 * PASS = return code, row count and recorded lines match. Cases named crash_* ABORT on the original
 * function: they run last and UNFORKED so a plain `make` stops with the ASan report; FORK_CRASH=1 forks each.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sanitizer/asan_interface.h>
#include "apmld_tget_params.h"

namespace apt {

static void poison_region(void *p, size_t n, bool on)
{
    if (on) __asan_poison_memory_region(p, n); else __asan_unpoison_memory_region(p, n);
}

static void poison(const test_case_t *tc, bool on)
{
    size_t used = strlen(root_store + APT_ROOT_LEFT) + 1;
    poison_region(root_store, APT_ROOT_LEFT, on);                                                    /* in front of root */
    poison_region(root_store + APT_ROOT_LEFT + used, sizeof(root_store) - APT_ROOT_LEFT - used, on);  /* past its NUL */
    if (g_dm) {
        poison_region(g_dm->before, sizeof(g_dm->before), on);                                       /* members before m_ap_mld[] */
        poison_region(g_dm->after, sizeof(g_dm->after), on);                                         /* members after m_ap_mld[] */
        int used_n = tc->nmld < APT_MAXMLD ? tc->nmld : APT_MAXMLD;
        for (int i = 0; i < APT_MAXMLD; i++) {
            if (i >= used_n) poison_region(&g_dm->m_ap_mld[i], sizeof(g_dm->m_ap_mld[i]), on);       /* entries not in use */
            else poison_region(g_dm->m_ap_mld[i].info.rest_of_struct, sizeof(g_dm->m_ap_mld[i].info.rest_of_struct), on);
        }
    }
}

static int call_once(const test_case_t *tc)
{
    poison(tc, true);                                                    /* POISON */
    g_rc = invoke(root_store + APT_ROOT_LEFT, tc->no_dm, tc->no_prop);
    poison(tc, false);                                                   /* UNPOISON */
    return 0;
}

int test_one(const test_case_t *tc)
{
    call_once(tc);
    int ok = (g_rc == tc->expect_rc);
    if (tc->expect_rows >= 0) ok = ok && g_rows == tc->expect_rows;
    if (tc->has) ok = ok && strstr(g_rec, tc->has) != NULL;
    if (tc->not_has) ok = ok && strstr(g_rec, tc->not_has) == NULL;
    if (tc->expect_rc != 0) ok = ok && g_rec[0] == '\0';
    ok = ok && strlen(g_aff_path) < 512;
    printf("    rc=%d (expect %d) rows=%d (expect %d)\n", g_rc, tc->expect_rc, g_rows, tc->expect_rows);
    if (!ok) printf("    record:\n%.500s\n", g_rec);
    return ok;
}

static int test_crash_fork(const test_case_t *tc)
{
    fflush(stdout); fflush(stderr);
    pid_t pid = fork();
    if (pid == 0) { call_once(tc); _exit(0); }
    int st = 0;
    waitpid(pid, &st, 0);
    int aborted = !(WIFEXITED(st) && WEXITSTATUS(st) == 0);
    printf("    child %s (status 0x%x)\n", aborted ? "ABORTED (ASan/SEGV above)" : "survived", st);
    return aborted;
}

} /* namespace apt */

int apt::g_rc = 0;

void run_all_tests_apmld_tget_params(void)
{
    int pass = 0, fail = 0, crashes = 0;
    bool fork_crash = getenv("FORK_CRASH") != NULL;
    for (int i = 0; apt::suite[i].test_name != NULL; i++) {
        apt::test_case_t *test = &apt::suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        apt::construct_input(test);
        int ok;
        if (test->crash && fork_crash) { ok = apt::test_crash_fork(test); if (ok) crashes++; }
        else                           ok = apt::test_one(test);      /* a crash case aborts the whole run here */
        apt::teardown();
        if (ok) { pass++; printf("================== %s: \033[32m%s\033[0m ==============\n", test->test_name, test->crash ? "CRASH CONFIRMED" : "PASS"); }
        else    { fail++; printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name); }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
    printf("apmld_tget_params: %d pass, %d fail (%d crash cases confirmed)\n", pass, fail, crashes);
}
