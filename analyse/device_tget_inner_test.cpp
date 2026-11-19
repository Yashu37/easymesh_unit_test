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




/* ---- direct checks of the size-limited helpers (fill_comma_sep / fill_backhaul_down_macs) ----
 * The destination is a heap buffer of dest_sz + 32 bytes; the 32 bytes past dest_sz are poisoned, so a
 * write past the capacity aborts with an ASan report. Each check returns 1 on pass. */
static char *fcs_dest(size_t dest_sz, size_t fill)
{
    char *d = static_cast<char *>(malloc(dest_sz + 32));
    memset(d, 'X', dest_sz + 32);
    d[0] = '\0';
    if (fill) { memset(d, 'Q', fill); d[fill] = '\0'; }
    __asan_poison_memory_region(d + dest_sz, 32);
    return d;
}
static void fcs_free(char *d, size_t dest_sz) { __asan_unpoison_memory_region(d + dest_sz, 32); free(d); }

static int fcs_run(const char *name, size_t dest_sz, size_t pre, em_short_string_t *list, size_t n, const char *expect)
{
    dm_easy_mesh_ctrl_t c;
    char *d = fcs_dest(dest_sz, pre);
    c.fill_comma_sep(list, n, d, dest_sz);
    int ok = (strcmp(d, expect) == 0);
    printf("--- Running Test: %s ---\n    out=\"%.60s\" expect=\"%.60s\"\n", name, d, expect);
    fcs_free(d, dest_sz);
    return ok;
}

static int fcs_all(int *failp)
{
    int pass = 0;
    int fail = 0;
    #define CHK(x) do { if (x) { pass++; printf("================== direct: \033[32mPASS\033[0m ==============\n"); } else { fail++; printf("===== direct: \033[31mFAIL\033[0m =====\n"); } } while (0)
    { em_short_string_t l[1] = { "" };                         CHK(fcs_run("fcs_empty_list", 16, 0, l, 1, "")); }
    { em_short_string_t l[2] = { "a", "b" };                   CHK(fcs_run("fcs_join_two", 16, 0, l, 2, "a,b")); }
    { em_short_string_t l[3] = { "a", "", "c" };               CHK(fcs_run("fcs_stops_at_empty_entry", 16, 0, l, 3, "a")); }
    { em_short_string_t l[2] = { "aaaaaaa", "bbbbbbb" };       CHK(fcs_run("fcs_exact_fit_16", 16, 0, l, 2, "aaaaaaa,bbbbbbb")); }
    { em_short_string_t l[3] = { "aaaaaaa", "bbbbbbb", "ccccccc" }; CHK(fcs_run("fcs_entry_too_long_dropped_15", 15, 0, l, 3, "aaaaaaa")); }
    { em_short_string_t l[1] = { "a" };                        CHK(fcs_run("fcs_size_1_empty_result", 1, 0, l, 1, "")); }
    { em_short_string_t l[1] = { "a" };                        CHK(fcs_run("fcs_appends_to_existing", 16, 1, l, 1, "Q,a")); }
    { em_short_string_t l[1] = { "a" };                        CHK(fcs_run("fcs_existing_content_fills_buffer", 4, 3, l, 1, "QQQ")); }
    { dm_easy_mesh_ctrl_t c; em_short_string_t l[1] = { "a" }; c.fill_comma_sep(l, 1, NULL, 16); char *z = fcs_dest(4, 0); c.fill_comma_sep(l, 1, z, 0); fcs_free(z, 4);
      printf("--- Running Test: fcs_null_or_zero_size ---\n"); CHK(1); }
    /* fill_backhaul_down_macs: count cap and per-device result */
    {
        dm_easy_mesh_ctrl_t c; em_device_info_t di; memset(&di, 0, sizeof(di));
        for (int i = 0; i < EM_BACKHAUL_DOWNMAC_ADDR; i++) snprintf(di.backhaul_down_mac[i], sizeof(di.backhaul_down_mac[i]), "02:00:00:00:00:%02x", i + 1);
        const unsigned char counts[] = { 0, 1, 15, 16, 17, 255 };
        for (unsigned ci = 0; ci < sizeof(counts); ci++) {
            size_t n = counts[ci] > EM_BACKHAUL_DOWNMAC_ADDR ? EM_BACKHAUL_DOWNMAC_ADDR : counts[ci];
            di.num_backhaul_down_mac = counts[ci];
            char *d = fcs_dest(1024, 0); memset(d, 'Z', 1024); d[1023] = '\0';
            c.fill_backhaul_down_macs(&di, d, 1024);
            size_t want = n ? n * 17 + (n - 1) : 0;
            printf("--- Running Test: fbd_count_%u ---\n    len=%zu expect=%zu\n", (unsigned)counts[ci], strlen(d), want);
            CHK(strlen(d) == want && (n == 0 || strncmp(d, "02:00:00:00:00:01", 17) == 0));
            fcs_free(d, 1024);
        }
        /* reused buffer: 15 entries, then 2, then none, then 15 again - each result holds only the current device */
        char *d = fcs_dest(1024, 0); size_t lens[4]; const unsigned char seq[] = { 15, 2, 0, 15 };
        for (int k = 0; k < 4; k++) { di.num_backhaul_down_mac = seq[k]; c.fill_backhaul_down_macs(&di, d, 1024); lens[k] = strlen(d); }
        printf("--- Running Test: fbd_reused_buffer ---\n    lens=%zu,%zu,%zu,%zu\n", lens[0], lens[1], lens[2], lens[3]);
        CHK(lens[0] == 15 * 17 + 14 && lens[1] == 2 * 17 + 1 && lens[2] == 0 && lens[3] == lens[0]);
        fcs_free(d, 1024);
        /* small destination: 40 bytes holds two entries (17 + 1 + 17 = 35), a third needs 53 */
        di.num_backhaul_down_mac = 16;
        d = fcs_dest(40, 0); c.fill_backhaul_down_macs(&di, d, 40);
        printf("--- Running Test: fbd_small_destination ---\n    out=\"%s\"\n", d);
        CHK(strlen(d) == 35);
        fcs_free(d, 40);
    }
    #undef CHK
    *failp += fail;
    return pass;
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
    pass += dti::fcs_all(&fail);
    printf("device_tget_inner: %d pass, %d fail (%d crash cases confirmed)\n", pass, fail, crashes);
}
int dti::g_rc = 0;
