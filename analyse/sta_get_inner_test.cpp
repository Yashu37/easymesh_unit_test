/*
 * TEST RUNNER: sta_get_inner_test
 *
 * Poisoned around the call:
 *   - the bytes in front of event_name (SGI_LEFT) and past its NUL - catches strrchr / strstr /
 *     name += sizeof(DATAELEMS_NETWORK) reading outside the name;
 *   - dm->before[] / dm->between[], the members in front of and after dm->m_radio[EM_MAX_BANDS] -
 *     catches dm->m_radio[radio_instance - 1] with radio_instance 0, > 3, negative or huge;
 *   - dm->after[], the members after dm->m_bss[EM_MAX_BSSS] - catches the BSS loop running past the array
 *     when m_num_bss > 24;
 *   - every radio's / BSS's rest_of_struct[] and every STA's rest_of_struct[] (members after frame_body[512]),
 *     the bytes of frame_body[] past frame_body_len are NOT poisoned (the handler may read the whole array).
 * The local arrays (instance[32], caps_str[32]) are guarded by ASan redzones, the dm and STA objects are heap
 * allocated one by one. PASS = return code matches and the value recorded by raw_data_set matches. Cases named
 * crash_* ABORT on the original handler: they run last and UNFORKED so a plain `make` stops with the ASan
 * report; FORK_CRASH=1 forks each one.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sanitizer/asan_interface.h>
#include "sta_get_inner.h"

namespace sgi {

static void poison_region(void *p, size_t n, bool on)
{
    if (on) __asan_poison_memory_region(p, n); else __asan_unpoison_memory_region(p, n);
}

static void poison(const test_case_t *tc, bool on)
{
    if (tc->event) {
        size_t used = strlen(name_store + SGI_LEFT) + 1;
        poison_region(name_store, SGI_LEFT, on);                                                   /* in front of event_name */
        poison_region(name_store + SGI_LEFT + used, sizeof(name_store) - SGI_LEFT - used, on);     /* past its NUL */
    }
    if (g_dm) {
        poison_region(g_dm->before, sizeof(g_dm->before), on);                                     /* members before m_radio[] */
        poison_region(g_dm->between, sizeof(g_dm->between), on);                                   /* members after m_radio[] */
        poison_region(g_dm->after, sizeof(g_dm->after), on);                                       /* members after m_bss[] */
        for (int r = 0; r < EM_MAX_BANDS; r++)
            poison_region(g_dm->m_radio[r].info.rest_of_struct, sizeof(g_dm->m_radio[r].info.rest_of_struct), on);
        for (int b = 0; b < EM_MAX_BSSS; b++)
            poison_region(g_dm->m_bss[b].info.rest_of_struct, sizeof(g_dm->m_bss[b].info.rest_of_struct), on);
        for (int i = 0; i < g_dm->m_sta_map->n; i++) {
            dm_sta_t *st = g_dm->m_sta_map->p[i];
            poison_region(st->info.rest_of_struct, sizeof(st->info.rest_of_struct), on);           /* after frame_body[512] */
        }
    }
}

static int call_once(const test_case_t *tc)
{
    poison(tc, true);                                                    /* POISON */
    g_rc = invoke(tc->event ? name_store + SGI_LEFT : NULL, tc->no_pdata);
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

} /* namespace sgi */

int sgi::g_rc = 0;

void run_all_tests_sta_get_inner(void)
{
    int pass = 0, fail = 0, crashes = 0;
    bool fork_crash = getenv("FORK_CRASH") != NULL;
    for (int i = 0; sgi::suite[i].test_name != NULL; i++) {
        sgi::test_case_t *test = &sgi::suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        sgi::construct_input(test);
        int ok;
        if (test->crash && fork_crash) { ok = sgi::test_crash_fork(test); if (ok) crashes++; }
        else                           ok = sgi::test_one(test);      /* a crash case aborts the whole run here */
        sgi::teardown();
        if (ok) { pass++; printf("================== %s: \033[32m%s\033[0m ==============\n", test->test_name, test->crash ? "CRASH CONFIRMED" : "PASS"); }
        else    { fail++; printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name); }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
    printf("sta_get_inner: %d pass, %d fail (%d crash cases confirmed)\n", pass, fail, crashes);
}
