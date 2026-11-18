/*
 * TEST RUNNER: dev_test_decode_test
 *
 * Poisoned around the call:
 *   - the event's subdoc.buff past its NUL (the JSON text) and the members after the event's params
 *     (guard) - catches reads past the subdoc;
 *   - the bytes after each em_t entry of the hash map (the neighbours of the objects the handler walks
 *     with hash_map_get_first / get_next).
 * The local array str_type[32] is guarded by an ASan stack redzone; the em_dev_test_info arrays are
 * indexed only with 0 / 1 (em_dev_test_type_max = 2). PASS = the summary of the decoded em_dev_test_info and
 * of the em entries matches. The case crash_* is expected to abort: it runs last and UNFORKED so a plain
 * `make` stops with the ASan report; FORK_CRASH=1 forks it.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sanitizer/asan_interface.h>
#include "dev_test_decode.h"

namespace dtd {

static void poison_region(void *p, size_t n, bool on)
{
    if (on) __asan_poison_memory_region(p, n); else __asan_unpoison_memory_region(p, n);
}

static void poison(const test_case_t *tc, bool on)
{
    em_bus_event_t *evt = (em_bus_event_t *)evt_buf;
    char *buff = evt->u.subdoc.buff;
    char *from = buff + strlen(buff) + 1;
    poison_region(from, (size_t)((evt_buf + DTD_EVT_SZ) - from), on);                              /* subdoc.buff past its NUL */
    poison_region(evt->guard, sizeof(evt->guard), on);                                             /* members after params */
    (void)tc;
}

static int call_once(const test_case_t *tc)
{
    poison(tc, true);                                                    /* POISON */
    invoke();
    poison(tc, false);                                                   /* UNPOISON */
    return 0;
}

int test_one(const test_case_t *tc)
{
    call_once(tc);
    const char *want = tc->expect[0] ? tc->expect : g_default;
    int ok = strcmp(g_sum, want) == 0;
    printf("    got  %s\n    want %s\n", g_sum, want);
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

} /* namespace dtd */

void run_all_tests_dev_test_decode(void)
{
    int pass = 0, fail = 0, crashes = 0;
    bool fork_crash = getenv("FORK_CRASH") != NULL;
    for (int i = 0; dtd::suite[i].test_name != NULL; i++) {
        dtd::test_case_t *test = &dtd::suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        dtd::construct_input(test);
        int ok;
        if (test->crash && fork_crash) { ok = dtd::test_crash_fork(test); if (ok) crashes++; }
        else                           ok = dtd::test_one(test);      /* a crash case aborts the whole run here */
        dtd::teardown();
        if (ok) { pass++; printf("================== %s: \033[32m%s\033[0m ==============\n", test->test_name, test->crash ? "CRASH CONFIRMED" : "PASS"); }
        else    { fail++; printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name); }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
    printf("dev_test_decode: %d pass, %d fail (%d crash cases confirmed)\n", pass, fail, crashes);
}
