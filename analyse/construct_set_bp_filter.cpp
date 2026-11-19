/*
 * TEST CASES / CONSTRUCTOR: construct_set_bp_filter
 *
 * em_t has before_ruid[] / after_ruid[] guards (poisoned by the runner) around m_ruid = {name[32], mac, media}. name = NULL
 * fills name[32] with 'A' and no NUL; its mac and media bytes are non-zero too, so a %s read walks through the whole
 * em_interface_t into the poisoned guard. setsockopt results sso[0] (SO_ATTACH_FILTER) and sso[1] (PACKET_ADD_MEMBERSHIP),
 * ifindex = what if_nametoindex() returns (0 = unknown interface). check_filter compares the attached program with the expected
 * ldh [12] / jeq #0x893a / ret #0xffffffff / ret #0 and checks the membership type (PACKET_MR_PROMISC).
 * [spec] cases: after close() on an error path m_fd still holds the closed descriptor, expected -1; no abort.
 * Cases named crash_* ABORT on the original handler: they run last and UNFORKED so a plain `make` stops with the ASan report;
 * FORK_CRASH=1 forks each one.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "set_bp_filter.h"

namespace sbf {
/* {name, name, fd, sso[2], ifindex, expect_ret, calls, close, expect_ifindex, expect_fd_after, check_filter, crash} */
test_case_t suite[] = {
 {"ok_both_succeed",                      "wlan0", 7,  {0, 0},   3, 0,  2, 0, 3, -2, true, false},
 {"ok_ifindex_large",                     "wlan0", 7,  {0, 0},   0x7fffffff, 0, 2, 0, 0x7fffffff, -2, true, false},
 {"ok_fd_passed_to_both_calls",           "wlan0", 11, {0, 0},   2, 0,  2, 0, 2, -2, false, false},
 {"ok_name_15_chars",                     "abcdefghijklmno", 7, {0, 0}, 5, 0, 2, 0, 5, -2, false, false},
 {"ok_name_31_chars",                     "abcdefghijklmnopqrstuvwxyz01234", 7, {0, 0}, 5, 0, 2, 0, 5, -2, false, false},
 {"ok_name_empty_unknown_interface",      "",      7,  {0, 0},   0, -1, 2, 1, 0, -2, false, false},
 {"ok_name_unterminated_success_path",    NULL,    7,  {0, 0},   4, 0,  2, 0, 4, -2, false, false},
 {"ok_unknown_interface_ifindex_0",       "nope0", 7,  {0, 0},   0, -1, 2, 1, 0, -2, false, false},
 {"rej_attach_fails",                     "wlan0", 7,  {-1, 0},  3, -1, 1, 1, -1, -2, false, false},
 {"rej_attach_fails_no_membership",       "wlan0", 7,  {-1, 0},  3, -1, 1, 1, -1, -2, false, false},
 {"rej_attach_fails_closes_the_fd",       "wlan0", 9,  {-1, 0},  3, -1, 1, 1, -1, -2, false, false},
 {"rej_membership_fails",                 "wlan0", 7,  {0, -1},  3, -1, 2, 1, 3, -2, false, false},
 {"rej_membership_fails_closes_the_fd",   "wlan0", 9,  {0, -1},  3, -1, 2, 1, 3, -2, false, false},
 {"rej_both_fail_only_first_call",        "wlan0", 7,  {-1, -1}, 3, -1, 1, 1, -1, -2, false, false},
 {"ok_attach_fail_unterminated_name_no_print", NULL, 7, {-1, 0}, 3, -1, 1, 1, -1, -2, false, false},
 /* ---- [spec]: wrong behaviour, no abort ---- */
 {"spec_fd_reset_after_attach_failure [spec]",     "wlan0", 7, {-1, 0}, 3, -1, 1, 1, -1, -1, false, false},
 {"spec_fd_reset_after_membership_failure [spec]", "wlan0", 7, {0, -1}, 3, -1, 2, 1, 3, -1, false, false},
 /* ---- CRASH cases on the original handler: run last, unforked ---- */
 {"crash_name_not_terminated_membership_fails",   NULL, 7, {0, -1}, 3, -1, 2, 1, 3, -2, false, true},
 {"crash_name_not_terminated_unknown_interface",  NULL, 7, {0, 0},  0, -1, 2, 1, 0, -2, false, true},
 {NULL, NULL, 0, {0, 0}, 0, 0, 0, 0, 0, 0, false, false}
};

extern int g_sso[2]; extern unsigned int g_ifindex;
void construct_input(const test_case_t *tc)
{
    g_em = new em_t; memset((void *)g_em, 0, sizeof(*g_em));
    g_em->m_fd = tc->fd;
    if (tc->name) snprintf(g_em->m_ruid.name, sizeof(g_em->m_ruid.name), "%s", tc->name);
    else { memset(g_em->m_ruid.name, 'A', sizeof(g_em->m_ruid.name)); memset(g_em->m_ruid.mac, 0xAA, 6); g_em->m_ruid.media = 0x41414141; }
    g_sso[0] = tc->sso[0]; g_sso[1] = tc->sso[1]; g_ifindex = (unsigned int)tc->ifindex;
    g_ncalls = 0; g_nclose = 0; g_close_fd = -1; g_ret = 0; memset(g_rec, 0, sizeof(g_rec));
}
void teardown(void) { delete g_em; g_em = NULL; }
} /* namespace sbf */
