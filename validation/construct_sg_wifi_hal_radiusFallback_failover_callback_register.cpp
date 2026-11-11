/*
 * UNIT TEST (input constructor): construct_sg_wifi_hal_radiusFallback_failover_callback_register
 *
 * wifi_hal_radiusFallback_failover_callback_register(func).  Inputs crossed: callbacks already registered (num_radius_fallback_failover_cbs) 0 / 1 / 2 / 3 / 4 (full) / 5 / 100 / UINT_MAX and 1 / 2 / 4 / 5 / 8 consecutive
 * registrations (alternating callbacks B, A, ...); a NULL callback; the callbacks table not available.  Expected (CORRECT behaviour): while num_radius_fallback_failover_cbs < 4 the callback is stored in the next slot and
 * num_radius_fallback_failover_cbs is incremented (a NULL callback is stored like any other), earlier slots are kept; with a full table (or an impossible count above 4) or no table nothing is stored, nothing else in the
 * table (other_cb / num_other_cbs) is written and num_radius_fallback_failover_cbs does not change.  No crash case is expected.
 */
#include "hwr_wff.h"
#include <limits.h>

/* name, start_n, calls, no_table, null_cb, last */
hwr_wff_case_t sg_wifi_hal_radiusFallback_failover_callback_register_suite[] = {
	{ "first_callback",            0, 1, 0, 0, 0 },
	{ "two_callbacks",             0, 2, 0, 0, 0 },
	{ "fill_the_table",            0, 4, 0, 0, 0 },
	{ "start_1_one_more",          1, 1, 0, 0, 0 },
	{ "start_2_two_more",          2, 2, 0, 0, 0 },
	{ "start_3_last_free_slot",    3, 1, 0, 0, 0 },
	{ "start_3_two_more_second_dropped", 3, 2, 0, 0, 0 },
	{ "table_full_one_more",       4, 1, 0, 0, 0 },
	{ "table_full_three_more",     4, 3, 0, 0, 0 },
	{ "five_registrations_from_empty", 0, 5, 0, 0, 0 },
	{ "eight_registrations_from_empty", 0, 8, 0, 0, 0 },
	{ "count_5_impossible_state",  5, 1, 0, 0, 0 },
	{ "count_100_impossible_state",100, 1, 0, 0, 0 },
	{ "count_uint_max_impossible_state", UINT_MAX, 1, 0, 0, 0 },
	{ "null_callback_registered",  0, 1, 0, 1, 0 },
	{ "null_callback_when_full",   4, 1, 0, 1, 0 },
	{ "table_not_available",       0, 1, 1, 0, 0 },
	{ "table_not_available_repeated", 2, 3, 1, 0, 0 },
	{ NULL }
};
