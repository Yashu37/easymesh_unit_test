/*
 * TEST RUNNER: print_config_test
 *
 * Poisoned around the call: PCF_GUARD bytes in front of and behind the dm_easy_mesh_t object, the after_ssids / after_bss / after_radio
 * guards right behind m_network_ssid[5], m_bss[24] and m_radio[3], and the after_ch_scan guard behind ch_scan of each radio cap (they
 * stand for the members that follow the arrays in the real class), so a read past any of those arrays - including the channel list
 * of the last op class - is reported. The handler's ch_buf[256] local is covered by an ASan redzone. PASS = number of printed lines
 * and, when requested, the channel list of the first op class. crash_* cases ABORT on the original code: they run last and UNFORKED
 * so a plain `make` stops with the report; FORK_CRASH=1 forks each one.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sanitizer/asan_interface.h>
#include "print_config.h"

namespace pcf {
static void poison(bool on)
{
    void *r[5 + EM_MAX_BANDS]; int n = 0;
    r[n++] = g_box->before; r[n++] = g_box->after; r[n++] = g_box->dm.after_ssids; r[n++] = g_box->dm.after_bss; r[n++] = g_box->dm.after_radio;
    for (int i = 0; i < EM_MAX_BANDS; i++) r[n++] = g_box->dm.m_radio_cap[i].info.after_ch_scan;
    for (int i = 0; i < n; i++) { if (on) __asan_poison_memory_region(r[i], PCF_GUARD); else __asan_unpoison_memory_region(r[i], PCF_GUARD); }
}
static int test_one(const test_case_t *tc)
{
    poison(true); invoke(); poison(false);
    size_t expect = 4 + tc->num_ssids + tc->num_bss + tc->num_radios * 6 + (tc->num_radios > 0 ? tc->op_classes_num : 0);
    int ok = g_lines.size() == expect;
    const char *chl = NULL; std::string first;
    for (auto &l : g_lines) if (l.find("ch_scan op_class[0]") != std::string::npos) { first = l; chl = first.c_str(); break; }
    if (tc->expect_ch_line) ok = ok && chl && strstr(chl, tc->expect_ch_line);
    printf("    lines=%zu (expect %zu) ch_line=%.110s\n", g_lines.size(), expect, chl ? chl : "-");
    fflush(stdout);
    return ok;
}
static int test_crash_fork(void)
{
    fflush(stdout); fflush(stderr);
    pid_t pid = fork();
    if (pid == 0) { poison(true); invoke(); _exit(0); }
    int st = 0; waitpid(pid, &st, 0);
    int aborted = !(WIFEXITED(st) && WEXITSTATUS(st) == 0);
    printf("    child %s (status 0x%x)\n", aborted ? "ABORTED (ASan above)" : "survived", st);
    return aborted;
}
} /* namespace pcf */

void run_all_tests_print_config(void)
{
    int pass = 0, fail = 0, crashes = 0;
    bool fork_crash = getenv("FORK_CRASH") != NULL;
    for (int i = 0; pcf::suite[i].test_name != NULL; i++) {
        pcf::test_case_t *test = &pcf::suite[i];
        printf("--- Running Test: %s ---\n", test->test_name); fflush(stdout);
        pcf::construct_input(test);
        int ok;
        if (test->crash && fork_crash) { ok = pcf::test_crash_fork(); if (ok) crashes++; }
        else                           ok = pcf::test_one(test);
        pcf::teardown();
        if (ok) { pass++; printf("================== %s: \033[32m%s\033[0m ==============\n", test->test_name, test->crash && fork_crash ? "CRASH CONFIRMED" : "PASS"); }
        else    { fail++; printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name); }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
    printf("print_config: %d pass, %d fail (%d crash cases confirmed)\n", pass, fail, crashes);
}
