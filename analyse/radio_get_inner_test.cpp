/*
 * TEST RUNNER: radio_get_inner_test
 *
 * Poisoned around the call:
 *   - the bytes in front of event_name (RGI_LEFT) and past its NUL - catches strrchr / strstr /
 *     name += sizeof(DATAELEMS_NETWORK) reading outside the name;
 *   - dm->before[] / dm->between[], the members in front of and after dm->m_radio[EM_MAX_BANDS] -
 *     catches dm->m_radio[radio_instance - 1] with radio_instance 0, > 3, negative or huge;
 *   - dm->after[], the members after dm->m_op_class[EM_MAX_OPCLASS] - catches the op class loop
 *     running past the array when m_num_opclass > 64;
 *   - every radio's after_chip[], the members that follow chip_vendor[128] - catches
 *     raw_data_set(ri->chip_vendor) (strlen) on a chip_vendor without NUL.
 * The local arrays (instance[32], id_str[16]) are guarded by ASan redzones, the dm objects are heap
 * allocated one by one. PASS = return code matches and the value recorded by raw_data_set matches.
 * Cases named crash_* are expected to abort: they run last and UNFORKED so a plain `make` stops with
 * the ASan report; FORK_CRASH=1 forks each one.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sanitizer/asan_interface.h>
#include "radio_get_inner.h"

namespace rgi {

static void poison_region(void *p, size_t n, bool on)
{
    if (on) __asan_poison_memory_region(p, n); else __asan_unpoison_memory_region(p, n);
}

static void poison(const test_case_t *tc, bool on)
{
    if (tc->event) {
        size_t used = strlen(name_store + RGI_LEFT) + 1;
        poison_region(name_store, RGI_LEFT, on);                                                   /* in front of event_name */
        poison_region(name_store + RGI_LEFT + used, sizeof(name_store) - RGI_LEFT - used, on);     /* past its NUL */
    }
    if (g_dm) {
        poison_region(g_dm->before, sizeof(g_dm->before), on);                                     /* members before m_radio[] */
        poison_region(g_dm->between, sizeof(g_dm->between), on);                                   /* members after m_radio[] */
        poison_region(g_dm->after, sizeof(g_dm->after), on);                                       /* members after m_op_class[] */
        for (int r = 0; r < EM_MAX_BANDS; r++)
            poison_region(g_dm->m_radio[r].info.after_chip, sizeof(g_dm->m_radio[r].info.after_chip), on); /* after chip_vendor[] */
    }
}

static int call_once(const test_case_t *tc)
{
    poison(tc, true);                                                    /* POISON */
    g_rc = invoke(tc->event ? name_store + RGI_LEFT : NULL, tc->no_pdata);
    poison(tc, false);                                                   /* UNPOISON */
    return 0;
}

int test_one(const test_case_t *tc)
{
    call_once(tc);
    int ok = (g_rc == tc->expect_rc);
    if (tc->expect_val) ok = ok && g_nset >= 1 && !strcmp(g_val, tc->expect_val);
    if (tc->expect_rc != 0) ok = ok && g_nset == 0;
    printf("    rc=%d (expect %d) value=%.40s%s%s sets=%d\n", g_rc, tc->expect_rc, g_nset ? g_val : "-",
           tc->expect_val ? " expect " : "", tc->expect_val ? tc->expect_val : "", g_nset);
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

} /* namespace rgi */

int rgi::g_rc = 0;

void run_all_tests_radio_get_inner(void)
{
    int pass = 0, fail = 0, crashes = 0;
    bool fork_crash = getenv("FORK_CRASH") != NULL;
    for (int i = 0; rgi::suite[i].test_name != NULL; i++) {
        rgi::test_case_t *test = &rgi::suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        rgi::construct_input(test);
        int ok;
        if (test->crash && fork_crash) { ok = rgi::test_crash_fork(test); if (ok) crashes++; }
        else                           ok = rgi::test_one(test);      /* a crash case aborts the whole run here */
        rgi::teardown();
        if (ok) { pass++; printf("================== %s: \033[32m%s\033[0m ==============\n", test->test_name, test->crash ? "CRASH CONFIRMED" : "PASS"); }
        else    { fail++; printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name); }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
    printf("radio_get_inner: %d pass, %d fail (%d crash cases confirmed)\n", pass, fail, crashes);
}
