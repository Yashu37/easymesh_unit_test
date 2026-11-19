/*
 * TEST RUNNER: network_init_test
 *
 * Poisoned around the call: NIT_GUARD bytes in front of and behind the dm_network_t object, so a write outside m_net_info (for
 * example a timestamp copy that is too long) is reported. The handler's date_time[64] local is covered by an ASan redzone. PASS =
 * the check of the case holds (return value / timestamp format / media / cleared members / UTC time / repeatability).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sanitizer/asan_interface.h>
#include "network_init.h"

namespace nit {
static void poison(bool on)
{
    if (on) { __asan_poison_memory_region(g_box->before, NIT_GUARD); __asan_poison_memory_region(g_box->after, NIT_GUARD); }
    else    { __asan_unpoison_memory_region(g_box->before, NIT_GUARD); __asan_unpoison_memory_region(g_box->after, NIT_GUARD); }
}
static int format_ok(const char *t)
{
    if (strlen(t) != 20) return 0;
    for (int i = 0; i < 20; i++) {
        char c = t[i];
        if (i == 4 || i == 7) { if (c != '-') return 0; }
        else if (i == 10) { if (c != 'T') return 0; }
        else if (i == 13 || i == 16) { if (c != ':') return 0; }
        else if (i == 19) { if (c != 'Z') return 0; }
        else if (c < '0' || c > '9') return 0;
    }
    return 1;
}
static void utc_now(char *o) { time_t n = time(NULL); struct tm *g = gmtime(&n); strftime(o, 32, "%Y-%m-%dT%H:%M:%SZ", g); }
static int test_one(const test_case_t *tc)
{
    char before[32], after[32];
    utc_now(before);
    poison(true); int rc = invoke(); poison(false);
    utc_now(after);
    em_network_info_t *n = &g_box->obj.m_net_info;
    int ok = 0;
    switch (tc->check) {
    case 0: ok = rc == 0 && format_ok(n->timestamp); break;
    case 1: ok = rc == 0 && n->media == em_media_type_ieee8023ab; break;
    case 2: {
        em_network_info_t z; memset(&z, 0, sizeof(z)); strcpy(z.timestamp, n->timestamp); z.media = n->media;
        ok = rc == 0 && !memcmp(&z, n, sizeof(z)) && format_ok(n->timestamp); break; }
    case 3: ok = rc == 0 && (!strcmp(n->timestamp, before) || !strcmp(n->timestamp, after)); break;
    case 4: { em_network_info_t a = *n; poison(true); invoke(); poison(false); ok = rc == 0 && format_ok(n->timestamp) && n->media == a.media; break; }
    }
    printf("    rc=%d timestamp=%s utc_now=%s media=%d\n", rc, n->timestamp, after, n->media);
    fflush(stdout);
    return ok;
}
} /* namespace nit */

void run_all_tests_network_init(void)
{
    int pass = 0, fail = 0;
    for (int i = 0; nit::suite[i].test_name != NULL; i++) {
        nit::test_case_t *test = &nit::suite[i];
        printf("--- Running Test: %s ---\n", test->test_name); fflush(stdout);
        nit::construct_input(test);
        int ok = nit::test_one(test);
        nit::teardown();
        if (ok) { pass++; printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name); }
        else    { fail++; printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name); }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
    printf("network_init: %d pass, %d fail (0 crash cases confirmed)\n", pass, fail);
}
