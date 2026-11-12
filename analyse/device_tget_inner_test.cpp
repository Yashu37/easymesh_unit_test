/*
 * TEST RUNNER: device_tget_inner_test
 *
 * Poisoned around the call:
 *   - the bytes in front of event_name (DTI_LEFT) - catches event_name[strlen-1] on an empty name;
 *   - the bytes of event_name past its NUL - catches strlen / snprintf("%s") reading past it;
 *   - every device's rest_of_struct (the fields that follow backhaul_down_mac[16] in the real
 *     em_device_info_t) - catches num_backhaul_down_mac > 16 reading past the array.
 * The internal arrays (path[512], val_str[1024], maclist_str[256], maclist[14], tmp[]) are guarded
 * by ASan redzones, the dm objects are heap allocated one by one.
 * PASS = return code matches, the number of device IDs reported matches, the recorded
 * properties contain `has` and not `not_has`. Cases named crash_* are expected to abort: they run
 * last and UNFORKED so a plain `make` stops with the ASan report; FORK_CRASH=1 forks each one.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sanitizer/asan_interface.h>
#include "device_tget_inner.h"

namespace dti {
extern int g_rc;

static void poison(const test_case_t *tc, bool on)
{
    size_t used = strlen(name_store + DTI_LEFT) + 1;
    void *left = name_store, *tail = name_store + DTI_LEFT + used;
    size_t tail_len = sizeof(name_store) - DTI_LEFT - used;
    if (tc->event) {
        if (on) { __asan_poison_memory_region(left, DTI_LEFT); __asan_poison_memory_region(tail, tail_len); }
        else    { __asan_unpoison_memory_region(left, DTI_LEFT); __asan_unpoison_memory_region(tail, tail_len); }
    }
    for (int i = 0; i < g_ndm; i++) {
        void *rest = ((dm_easy_mesh_t *)g_dm[i])->dev.info.rest_of_struct;
        if (on) __asan_poison_memory_region(rest, sizeof(((em_device_info_t *)0)->rest_of_struct));
        else    __asan_unpoison_memory_region(rest, sizeof(((em_device_info_t *)0)->rest_of_struct));
    }
}

static int call_once(const test_case_t *tc)
{
    poison(tc, true);                                                   /* POISON */
    g_rc = invoke(tc->event ? name_store + DTI_LEFT : NULL, tc->no_pdata);
    poison(tc, false);                                                  /* UNPOISON */
    return 0;
}

int test_one(const test_case_t *tc)
{
    call_once(tc);
    int ok = (g_rc == tc->expect_rc);
    if (tc->expect_devices >= 0) ok = ok && (g_ndev == tc->expect_devices);
    if (tc->has) ok = ok && strstr(g_rec, tc->has);
    if (tc->not_has) ok = ok && !strstr(g_rec, tc->not_has);
    printf("    rc=%d (expect %d) devices=%d (expect %d) raw_set=%d\n", g_rc, tc->expect_rc, g_ndev, tc->expect_devices, g_raw_set);
    if (!ok) printf("    recorded: %.300s\n", g_rec);
    return ok;
}

/* run one expected-abort case in a forked child; return 1 if it aborted */
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



} /* namespace dti */

void run_all_tests_device_tget_inner(void)
{
    int pass = 0, fail = 0, crashes = 0;
    bool fork_crash = getenv("FORK_CRASH") != NULL;
    for (int i = 0; dti::suite[i].test_name != NULL; i++) {
        dti::test_case_t *test = &dti::suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        dti::construct_input(test);
        int ok;
        if (test->crash && fork_crash) { ok = dti::test_crash_fork(test); if (ok) crashes++; }
        else                           ok = dti::test_one(test);      /* a crash case aborts the whole run here */
        dti::teardown();
        if (ok) { pass++; printf("================== %s: \033[32m%s\033[0m ==============\n", test->test_name, test->crash ? "CRASH CONFIRMED" : "PASS"); }
        else    { fail++; printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name); }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
    printf("device_tget_inner: %d pass, %d fail (%d crash cases confirmed)\n", pass, fail, crashes);
}
int dti::g_rc = 0;
