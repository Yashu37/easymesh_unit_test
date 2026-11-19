/*
 * TEST RUNNER: config_reset_test
 *
 * Poisoned around the call: ECR_GUARD bytes in front of and behind the dm_easy_mesh_t object and the sub-document, the
 * after_interfaces guard right behind m_interfaces[8] and the after_ssids guard right behind m_network_ssid[5] (they stand for the
 * members that follow the arrays in the real class), so a read of m_network_ssid[i] with i >= 5 or a string read that runs off the
 * interface array is reported. The handler's locals (mac_str[18], interface_str[128]) are covered by ASan redzones. PASS = return
 * value, Interfaces.List / NetworkSSIDList entry counts, first interface string and complete JSON in subdoc->buff.
 * crash_* cases ABORT on the original code: they run last and UNFORKED so a plain `make` stops with the report; FORK_CRASH=1 forks each.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sanitizer/asan_interface.h>
#include "config_reset.h"

namespace ecr {
static void poison(bool on)
{
    void *r[5] = { g_box->before, g_box->after, g_box->dm.after_interfaces, g_box->dm.after_ssids, g_box->after_subdoc };
    for (int i = 0; i < 5; i++) { if (on) __asan_poison_memory_region(r[i], ECR_GUARD); else __asan_unpoison_memory_region(r[i], ECR_GUARD); }
}
static int test_one(const test_case_t *tc)
{
    poison(true); int rc = invoke(tc); poison(false);
    int ok = rc == tc->expect_ret;
    int nif = -1, nss = -1; char first[160] = "-"; int parsed = 0;
    cJSON *root = (rc == 0) ? cJSON_Parse(g_box->subdoc.buff) : NULL;
    if (root) {
        parsed = 1;
        cJSON *net = root->child;
        cJSON *list = cJSON_GetObjectItem(cJSON_GetObjectItem(net, "Interfaces"), "List");
        cJSON *ssids = cJSON_GetObjectItem(net, "NetworkSSIDList");
        nif = list ? cJSON_GetArraySize(list) : -1; nss = ssids ? cJSON_GetArraySize(ssids) : -1;
        cJSON *i0 = list ? cJSON_GetArrayItem(list, 0) : NULL;
        if (i0 && i0->child && i0->child->valuestring) snprintf(first, sizeof(first), "%s", i0->child->valuestring);
        cJSON_Delete(root);
    }
    if (tc->expect_parse) ok = ok && parsed;
    if (tc->expect_ifaces >= 0) ok = ok && nif == tc->expect_ifaces;
    if (tc->expect_ssids >= 0) ok = ok && nss == tc->expect_ssids;
    if (tc->expect_iface0) ok = ok && !strcmp(first, tc->expect_iface0);
    printf("    ret=%d (expect %d) parsed=%d interfaces=%d (expect %d) ssids=%d (expect %d) iface0=%.70s\n", rc, tc->expect_ret, parsed, nif, tc->expect_ifaces, nss, tc->expect_ssids, first);
    fflush(stdout);
    return ok;
}
static int test_crash_fork(const test_case_t *tc)
{
    fflush(stdout); fflush(stderr);
    pid_t pid = fork();
    if (pid == 0) { poison(true); invoke(tc); _exit(0); }
    int st = 0; waitpid(pid, &st, 0);
    int aborted = !(WIFEXITED(st) && WEXITSTATUS(st) == 0);
    printf("    child %s (status 0x%x)\n", aborted ? "ABORTED (ASan above)" : "survived", st);
    return aborted;
}
} /* namespace ecr */

void run_all_tests_config_reset(void)
{
    int pass = 0, fail = 0, crashes = 0;
    bool fork_crash = getenv("FORK_CRASH") != NULL;
    for (int i = 0; ecr::suite[i].test_name != NULL; i++) {
        ecr::test_case_t *test = &ecr::suite[i];
        printf("--- Running Test: %s ---\n", test->test_name); fflush(stdout);
        ecr::construct_input(test);
        int ok;
        if (test->crash && fork_crash) { ok = ecr::test_crash_fork(test); if (ok) crashes++; }
        else                           ok = ecr::test_one(test);
        ecr::teardown();
        if (ok) { pass++; printf("================== %s: \033[32m%s\033[0m ==============\n", test->test_name, test->crash && fork_crash ? "CRASH CONFIRMED" : "PASS"); }
        else    { fail++; printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name); }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
    printf("config_reset: %d pass, %d fail (%d crash cases confirmed)\n", pass, fail, crashes);
}
