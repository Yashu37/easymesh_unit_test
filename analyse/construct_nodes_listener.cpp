/*
 * TEST CASES / CONSTRUCTOR: construct_nodes_listener
 *
 * The listener loops until select() returns a negative value, so every script ends when its select() results run out
 * (the stand-in then returns -1 / EBADF). sel[]: >0 ready, 0 timeout, -2 = -1 with EINTR, 3 = ready but no fd flagged;
 * rd[]: read() results in order (-1 = error, 0 = EOF); ems[]: {fd, is_al}. m_timeout = 1. Checks: number of proto_process()
 * calls, the length of the first one and the nfds of the first select() (highest fd + 1).
 * Cases named crash_* ABORT on the original handler: they run last and UNFORKED so a plain `make` stops with the ASan report;
 * FORK_CRASH=1 forks each one. The [spec] case is wrong behaviour (no abort).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "nodes_listener.h"

namespace nls {
extern int g_sel[], g_nsel, g_sel_i, g_nrd, g_rd_i; extern long g_rd[];

/* {name, sel[], nsel, rd[], nrd, ems[], nems, expect_calls, expect_len0, expect_nfds, crash} */
test_case_t suite[] = {
 {"ok_ready_one_read_100",        {1}, 1,    {100}, 1,        {{5, true}}, 1, 1, 100, 6, false},
 {"ok_timeout_then_ready",        {0, 1}, 2, {64}, 1,         {{5, true}}, 1, 1, 64, 6, false},
 {"ok_two_ready_rounds",          {1, 1}, 2, {10, 20}, 2,     {{5, true}}, 1, 2, 10, 6, false},
 {"ok_two_al_ems_both_read",      {1}, 1,    {10, 20}, 2,     {{5, true}, {6, true}}, 2, 2, 10, 7, false},
 {"ok_non_al_em_ignored",         {1}, 1,    {10}, 1,         {{5, false}}, 1, 0, -1, 1, false},
 {"ok_non_al_and_al_mixed",       {1}, 1,    {33}, 1,         {{4, false}, {8, true}}, 2, 1, 33, 9, false},
 {"ok_read_eof_zero_not_processed", {1}, 1,  {0}, 1,          {{5, true}}, 1, 0, -1, 6, false},
 {"ok_full_buffer_3072",          {1}, 1,    {3072}, 1,       {{5, true}}, 1, 1, 3072, 6, false},
 {"ok_one_byte",                  {1}, 1,    {1}, 1,          {{5, true}}, 1, 1, 1, 6, false},
 {"ok_select_error_ends_loop",    {}, 0,     {}, 0,           {{5, true}}, 1, 0, -1, 6, false},
 {"ok_ready_but_fd_not_flagged",  {3}, 1,    {50}, 1,         {{5, true}}, 1, 0, -1, 6, false},
 {"ok_highest_fd_is_largest",     {1}, 1,    {5, 5, 5}, 3,    {{9, true}, {3, true}, {7, true}}, 3, 3, 5, 10, false},
 {"ok_no_ems_only_select",        {0, 0}, 2, {}, 0,           {}, 0, 0, -1, 1, false},
 {"ok_fd_1023_last_valid_fd",     {1}, 1,    {7}, 1,          {{1023, true}}, 1, 1, 7, 1024, false},
 /* ---- [spec]: wrong behaviour, no abort ---- */
 {"spec_eintr_must_not_end_listener [spec]", {-2, 1}, 2, {50}, 1, {{5, true}}, 1, 1, 50, 6, false},
 /* ---- CRASH cases on the original handler: run last, unforked ---- */
 {"crash_read_error_len_minus_1", {1}, 1,    {-1}, 1,         {{5, true}}, 1, 0, -1, 6, true},
 {"crash_read_error_second_em",   {1}, 1,    {10, -1}, 2,     {{5, true}, {6, true}}, 2, 1, 10, 7, true},
 {"crash_fd_1024_fd_set_overflow", {1}, 1,   {10}, 1,         {{1024, true}}, 1, 0, -1, -1, true},
 {"crash_fd_5000_fd_set_overflow", {1}, 1,   {10}, 1,         {{5000, true}}, 1, 0, -1, -1, true},
 {NULL, {0}, 0, {0}, 0, {{0, false}}, 0, 0, 0, 0, false}
};

void construct_input(const test_case_t *tc)
{
    g_mgr = new em_mgr_t; memset((void *)g_mgr, 0, sizeof(*g_mgr));
    g_mgr->m_timeout = 1; pthread_mutex_init(&g_mgr->m_mutex, NULL);
    g_mgr->m_em_map = new hash_map_t;
    for (int i = 0; i < tc->nems; i++) { em_t *e = new em_t; e->m_fd = tc->ems[i].fd; e->m_al = tc->ems[i].al; g_ems.push_back(e); g_mgr->m_em_map->v.push_back(e); }
    g_nsel = tc->nsel; g_sel_i = 0; for (int i = 0; i < tc->nsel; i++) g_sel[i] = tc->sel[i];
    g_nrd = tc->nrd; g_rd_i = 0; for (int i = 0; i < tc->nrd; i++) g_rd[i] = tc->rd[i];
    g_calls = 0; g_len0 = -1; g_nfds0 = -1; g_sel_calls = 0;
}
void teardown(void)
{
    for (em_t *e : g_ems) delete e; g_ems.clear();
    delete g_mgr->m_em_map; delete g_mgr; g_mgr = NULL;
}
} /* namespace nls */
