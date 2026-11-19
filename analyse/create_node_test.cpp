/*
 * TEST RUNNER: create_node_test
 *
 * Poisoned around the call: the CND_GUARD bytes in front of and behind the em_interface_t that is passed as ruid
 * (the handler writes ruid->name and reads ruid->mac; any access outside the struct is reported). mac_str[32] is a stack
 * array covered by an ASan redzone. PASS = the returned node, the map size and the newest key match. The case crash_*
 * ABORTS on the original handler (uncaught std::runtime_error from the em_t constructor): it runs last and UNFORKED;
 * FORK_CRASH=1 forks it.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sanitizer/asan_interface.h>
#include "create_node.h"

namespace cnd {
static void poison(bool on)
{
    void *a = ruid_store, *b = ruid_store + CND_GUARD + sizeof(em_interface_t);
    if (on) { __asan_poison_memory_region(a, CND_GUARD); __asan_poison_memory_region(b, CND_GUARD); }
    else    { __asan_unpoison_memory_region(a, CND_GUARD); __asan_unpoison_memory_region(b, CND_GUARD); }
}
static void call_once(const test_case_t *tc) { poison(true); invoke(tc); poison(false); }

static int test_one(const test_case_t *tc)
{
    em_t *existing = g_mgr->m_map.empty() ? NULL : g_mgr->m_map[0].em;
    call_once(tc);
    int got = g_ret == NULL ? 0 : (g_ret == existing && existing ? 2 : 1);
    int ok = got == tc->expect && (int)g_mgr->m_map.size() == tc->expect_map;
    if (tc->expect_key && !g_mgr->m_map.empty()) ok = ok && !strcmp(g_mgr->m_map.back().key, tc->expect_key);
    fflush(stdout);
    printf("    result=%d (expect %d) map=%zu (expect %d) key=%s\n", got, tc->expect, g_mgr->m_map.size(), tc->expect_map,
           g_mgr->m_map.empty() ? "-" : g_mgr->m_map.back().key);
    fflush(stdout);
    return ok;
}
static int test_crash_fork(const test_case_t *tc)
{
    fflush(stdout); fflush(stderr);
    pid_t pid = fork();
    if (pid == 0) { call_once(tc); _exit(0); }
    int st = 0; waitpid(pid, &st, 0);
    int aborted = !(WIFEXITED(st) && WEXITSTATUS(st) == 0);
    printf("    child %s (status 0x%x)\n", aborted ? "ABORTED (terminate above)" : "survived", st);
    return aborted;
}
} /* namespace cnd */

void run_all_tests_create_node(void)
{
    int pass = 0, fail = 0, crashes = 0;
    bool fork_crash = getenv("FORK_CRASH") != NULL;
    for (int i = 0; cnd::suite[i].test_name != NULL; i++) {
        cnd::test_case_t *test = &cnd::suite[i];
        printf("--- Running Test: %s ---\n", test->test_name); fflush(stdout);
        cnd::construct_input(test);
        int ok;
        if (test->crash && fork_crash) { ok = cnd::test_crash_fork(test); if (ok) crashes++; }
        else                           ok = cnd::test_one(test);
        cnd::teardown();
        if (ok) { pass++; printf("================== %s: \033[32m%s\033[0m ==============\n", test->test_name, test->crash ? "CRASH CONFIRMED" : "PASS"); }
        else    { fail++; printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name); }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
    printf("create_node: %d pass, %d fail (%d crash cases confirmed)\n", pass, fail, crashes);
}
