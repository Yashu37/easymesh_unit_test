/*
 * TEST RUNNER: dm_bss_encode_test
 *
 * Poisoned around the call: DBE_GUARD bytes before and after m_bss_info inside dm_bss_t (the members next to the BSS info).
 * vendor_elements[2310] is the last array of em_bss_info_t, so vendor_elements[i] with i >= 2310 + 8 (size_t len) + 1 reaches
 * the guard; fronthaul_akm[] / backhaul_akm[] (10 entries of 64 bytes) are followed by the other members, the 255 counts run
 * through them into the guard. The stack array vendor_ies and the locals mac_str[18] / haul_type_str[64] are covered by ASan
 * redzones; the stack is dirtied with 'A' first so an unassigned haul_type_str is not a NUL. PASS = the keys of the produced
 * JSON object match the expectations. Cases named crash_* ABORT on the original handler: they run last and UNFORKED so a plain
 * `make` stops with the ASan report; FORK_CRASH=1 forks each one.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sanitizer/asan_interface.h>
#include "dm_bss_encode.h"

namespace dbe {
static void poison_region(void *p, size_t n, bool on)
{ if (on) __asan_poison_memory_region(p, n); else __asan_unpoison_memory_region(p, n); }
static void poison(bool on)
{
    poison_region(g_bss->before_info, sizeof(g_bss->before_info), on);    /* members before m_bss_info */
    poison_region(g_bss->after_info, sizeof(g_bss->after_info), on);      /* members after m_bss_info */
}
static void call_once(const test_case_t *tc) { poison(true); invoke(tc); poison(false); }

static const char *str_of(const char *k) { cJSON *i = cJSON_GetObjectItem(g_obj, k); return i && cJSON_IsString(i) ? i->valuestring : NULL; }
static int test_one(const test_case_t *tc)
{
    call_once(tc);
    int ok = 1;
    if (tc->summary) ok = ok && cJSON_GetObjectItem(g_obj, "LastChange") == NULL && cJSON_GetObjectItem(g_obj, "ExtraVendorIEs") == NULL && str_of("BSSID") != NULL;
    else             ok = ok && cJSON_GetObjectItem(g_obj, "LastChange") != NULL && str_of("BSSID") && !strcmp(str_of("BSSID"), "02:00:00:00:10:01");
    if (tc->expect_haul) ok = ok && str_of("HaulType") && !strcmp(str_of("HaulType"), tc->expect_haul);
    if (tc->expect_ssid) ok = ok && str_of("SSID") && !strcmp(str_of("SSID"), tc->expect_ssid);
    cJSON *fh = cJSON_GetObjectItem(g_obj, "FronthaulAKMsAllowed"), *bh = cJSON_GetObjectItem(g_obj, "BackhaulAKMsAllowed");
    if (tc->expect_fh >= 0) ok = ok && fh && cJSON_GetArraySize(fh) == tc->expect_fh;
    if (tc->expect_bh >= 0) ok = ok && bh && cJSON_GetArraySize(bh) == tc->expect_bh;
    if (tc->expect_vendor_len >= 0 && !tc->summary) ok = ok && str_of("ExtraVendorIEs") && (int)strlen(str_of("ExtraVendorIEs")) == tc->expect_vendor_len;
    if (tc->expect_mld >= 0) ok = ok && ((cJSON_GetObjectItem(g_obj, "MLDAddr") != NULL) == (tc->expect_mld == 1));
    printf("    HaulType=%s SSID=%s fh=%d bh=%d vendor_chars=%zu mld=%d\n", str_of("HaulType") ? str_of("HaulType") : "-", str_of("SSID") ? str_of("SSID") : "-",
           fh ? cJSON_GetArraySize(fh) : -1, bh ? cJSON_GetArraySize(bh) : -1, str_of("ExtraVendorIEs") ? strlen(str_of("ExtraVendorIEs")) : (size_t)0,
           cJSON_GetObjectItem(g_obj, "MLDAddr") != NULL);
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
    printf("    child %s (status 0x%x)\n", aborted ? "ABORTED (ASan/SEGV above)" : "survived", st);
    return aborted;
}
} /* namespace dbe */

void run_all_tests_dm_bss_encode(void)
{
    int pass = 0, fail = 0, crashes = 0;
    bool fork_crash = getenv("FORK_CRASH") != NULL;
    for (int i = 0; dbe::suite[i].test_name != NULL; i++) {
        dbe::test_case_t *test = &dbe::suite[i];
        printf("--- Running Test: %s ---\n", test->test_name); fflush(stdout);
        dbe::construct_input(test);
        int ok;
        if (test->crash && fork_crash) { ok = dbe::test_crash_fork(test); if (ok) crashes++; }
        else                           ok = dbe::test_one(test);
        dbe::teardown();
        if (ok) { pass++; printf("================== %s: \033[32m%s\033[0m ==============\n", test->test_name, test->crash ? "CRASH CONFIRMED" : "PASS"); }
        else    { fail++; printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name); }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
    printf("dm_bss_encode: %d pass, %d fail (%d crash cases confirmed)\n", pass, fail, crashes);
}
