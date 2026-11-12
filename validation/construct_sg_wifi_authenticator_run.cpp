/*
 * UNIT TEST (input constructor): construct_sg_wifi_authenticator_run
 *
 * wifi_authenticator_run() takes no argument: it calls eloop_run() once and returns when the loop returns.  Inputs crossed: number of consecutive calls (1, 2, 5) and the number of iterations the
 * stub event loop runs per call (0, 1, 1000).
 * Expected (CORRECT behaviour): exactly one eloop_run per call (so calls in total), each call returns only after its loop returned (never while the loop is still running), and nothing outside the event
 * loop is touched.  Rows with last = 1 break the original: they run LAST.
 */
#include "hwr_war.h"

/* name, calls, iterations, last */
hwr_war_case_t sg_wifi_authenticator_run_suite[] = {
	{ "single_call_loop_returns_at_once",     1, 0, 0 },
	{ "single_call_one_iteration",            1, 1, 0 },
	{ "single_call_1000_iterations",          1, 1000, 0 },
	{ "two_consecutive_calls",                2, 1, 0 },
	{ "five_consecutive_calls",               5, 0, 0 },
	{ NULL }
};
