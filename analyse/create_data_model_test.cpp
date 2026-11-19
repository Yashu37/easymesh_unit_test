/*
 * TEST RUNNER: create_data_model_test
 *
 * Poisoned around the call:
 *   - the bytes in front of net_id (CDM_LEFT) and past its NUL - catches strlen / snprintf / strncpy reading outside it;
 *   - CDM_GUARD bytes before and after the al_intf (em_interface_t) argument;
 *   - on_dm_created(): every dm the handler creates gets the guard behind device id (the members that follow net_id[128],
 *     dev_mac, media in em_device_info_t) poisoned - strncpy(net_id, ..., strlen(net_id) + 1) past 128 + 10 bytes is reported.
 * The local arrays (mac_str[18], key[64], em_policy[8], op_class[6], policy[8]) are covered by ASan redzones.
 * PASS = returned dm, list size, flags, copied SSIDs, findability, 8 policies / 6 channels / net_id / profile match.
 * Cases named crash_* ABORT on the original handler: they run last and UNFORKED so a plain `make` stops with the ASan
 * report / assertion; FORK_CRASH=1 forks each one.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sanitizer/asan_interface.h>
#include "create_data_model.h"

namespace cdm {
static bool g_poison_on = false;
static void poison_region(void *p, size_t n, bool on)
{ if (on) __asan_poison_memory_region(p, n); else __asan_unpoison_memory_region(p, n); }

void on_dm_created(dm_easy_mesh_t *dm)          /* called by the dm stand-in's init() while the handler runs */
{
    g_dms.push_back(dm);
    if (g_poison_on) poison_region(dm->m_device.m_device_info.after_id, sizeof(dm->m_device.m_device_info.after_id), true);
}
static void poison(const test_case_t *tc, bool on)
{
    g_poison_on = on;
    if (tc->net_id || tc->long_len > 0) {
        size_t used = strlen(name_store + CDM_LEFT) + 1;
        poison_region(name_store, CDM_LEFT, on);                                                   /* in front of net_id */
        poison_region(name_store + CDM_LEFT + used, sizeof(name_store) - CDM_LEFT - used, on);     /* past its NUL */
    }
    poison_region(al_store, CDM_GUARD, on);                                                        /* before al_intf */
    poison_region(al_store + CDM_GUARD + sizeof(em_interface_t), CDM_GUARD, on);                   /* after al_intf */
    if (!on) for (dm_easy_mesh_t *d : g_dms) poison_region(d->m_device.m_device_info.after_id, sizeof(d->m_device.m_device_info.after_id), false);
}
static void call_once(const test_case_t *tc) { poison(tc, true); invoke(tc); poison(tc, false); }

static int test_one(const test_case_t *tc)
{
    call_once(tc);
    int got = g_ret != NULL;
    int ok = got == tc->expect && (int)g_list->m_list->v.size() == tc->expect_list;
    if (g_ret) {
        char net[CDM_NAME_SZ + 1]; snprintf(net, sizeof(net), "%s", name_store + CDM_LEFT);
        em_device_info_t *di = &g_ret->m_device.m_device_info;
        int flags = (g_ret->controller ? 1 : 0) | (g_ret->colocated ? 2 : 0) | (g_ret->id == 7 ? 4 : 0);
        if (tc->expect_flags >= 0) ok = ok && flags == tc->expect_flags;
        if (tc->expect_ssids >= 0) ok = ok && (int)g_ret->num_ssid == tc->expect_ssids;
        ok = ok && g_ret->num_policy == 8 && g_ret->num_channels == EM_MAX_PRE_SET_CHANNELS && di->profile == 3 && !strcmp(di->id.net_id, net)
             && !memcmp(di->intf.mac, g_al->mac, 6);
        if (tc->expect_findable >= 0) ok = ok && ((g_list->get_data_model(net, g_al->mac) == g_ret) == (tc->expect_findable == 1));
    }
    printf("    returned=%d (expect %d) list=%zu (expect %d) findable=%s\n", got, tc->expect, g_list->m_list->v.size(), tc->expect_list,
           g_ret ? (g_list->get_data_model(name_store + CDM_LEFT, g_al->mac) == g_ret ? "yes" : "no") : "-");
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
    printf("    child %s (status 0x%x)\n", aborted ? "ABORTED (ASan/SEGV/assert above)" : "survived", st);
    return aborted;
}
} /* namespace cdm */

void run_all_tests_create_data_model(void)
{
    int pass = 0, fail = 0, crashes = 0;
    bool fork_crash = getenv("FORK_CRASH") != NULL;
    for (int i = 0; cdm::suite[i].test_name != NULL; i++) {
        cdm::test_case_t *test = &cdm::suite[i];
        printf("--- Running Test: %s ---\n", test->test_name); fflush(stdout);
        cdm::construct_input(test);
        int ok;
        if (test->crash && fork_crash) { ok = cdm::test_crash_fork(test); if (ok) crashes++; }
        else                           ok = cdm::test_one(test);
        cdm::teardown();
        if (ok) { pass++; printf("================== %s: \033[32m%s\033[0m ==============\n", test->test_name, test->crash ? "CRASH CONFIRMED" : "PASS"); }
        else    { fail++; printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name); }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
    printf("create_data_model: %d pass, %d fail (%d crash cases confirmed)\n", pass, fail, crashes);
}
