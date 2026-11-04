/*
 * UNIT TEST (input constructor): construct_hal_ipc_server_get_radio_channel_stats_callback
 *
 * The getter has NO parameters: it logs a debug line and returns the global
 * callback pointer.  The input space is therefore the STATE of that global
 * (NULL / valid / bogus / odd / data / stack / heap / foreign), what was
 * done to it before (setter sequences), the state of the neighbouring
 * globals, the call count, and the thread context.  Each suite entry is a
 * scenario returning 1 when the observed behaviour is what is expected.
 * The log sink wifi_hal_print() lives in the set_ap_assoc construct file and
 * writes into the shared runner-owned, tail-poisoned hipc_log_buf[].
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include "common.h"

static const char *FN = "hal_ipc_server_get_radio_channel_stats_callback";
static int cb_calls;

static int cb_a(int, hipc_chstats_t *, int *) { cb_calls++; return 11; }
static int cb_b(int, hipc_chstats_t *, int *) { cb_calls++; return 22; }
static int cb_c(int, hipc_chstats_t *, int *) { cb_calls++; return 33; }
static int assoc_like(int, hipc_chstats_t *, int *) { return 44; }
static int neigh_like(int, void *, int *) { return 55; }

static void reset(void)
{
	hal_ipc_server_callback_get_radio_channel_stats = NULL;
	hal_ipc_server_callback_get_ap_assoc_dev_diag_res3 = NULL;
	hal_ipc_server_callback_get_neighbor_ap2 = NULL;
	hipc_log_calls = 0;
	hipc_log_level = -1;
	cb_calls = 0;
	memset(hipc_log_buf, 0, HIPC_LOG_USE);
}

/* store p directly into the global, then read it back through the getter */
static int get_returns(hipc_rs_cb_t p)
{
	reset();
	hal_ipc_server_callback_get_radio_channel_stats = p;
	return hal_ipc_server_get_radio_channel_stats_callback() == p;
}

static void *thr_get(void *arg)
{
	hipc_rs_cb_t want = (hipc_rs_cb_t)arg;
	int bad = 0;

	for (int i = 0; i < 200; i++)
		if (hal_ipc_server_get_radio_channel_stats_callback() != want)
			bad++;
	return (void *)(intptr_t)bad;
}

hipc_grcs_test_case_t hal_ipc_server_get_radio_channel_stats_callback_suite[] = {
	/* ---- returned value == stored value ---- */
	{ "get_returns_null_when_unset",    [](void)->int { return get_returns(NULL); }, 1 },
	{ "get_returns_cb_a",               [](void)->int { return get_returns(cb_a); }, 1 },
	{ "get_returns_cb_b",               [](void)->int { return get_returns(cb_b); }, 1 },
	{ "get_returns_cb_c",               [](void)->int { return get_returns(cb_c); }, 1 },
	{ "get_returns_pointer_0x1",        [](void)->int { return get_returns((hipc_rs_cb_t)(uintptr_t)0x1); }, 1 },
	{ "get_returns_pointer_all_ones",   [](void)->int { return get_returns((hipc_rs_cb_t)(uintptr_t)~(uintptr_t)0); }, 1 },
	{ "get_returns_odd_address",        [](void)->int { return get_returns((hipc_rs_cb_t)((uintptr_t)cb_a + 1)); }, 1 },
	{ "get_returns_data_address",       [](void)->int { static int d; return get_returns((hipc_rs_cb_t)(void *)&d); }, 1 },
	{ "get_returns_stack_address",      [](void)->int { int s = 0; return get_returns((hipc_rs_cb_t)(void *)&s); }, 1 },
	{ "get_returns_heap_address",       [](void)->int { void *h = malloc(16); int ok = get_returns((hipc_rs_cb_t)h); free(h); return ok; }, 1 },
	{ "get_returns_libc_function",      [](void)->int { return get_returns((hipc_rs_cb_t)(void *)&puts); }, 1 },
	{ "get_returns_foreign_type_assoc", [](void)->int { return get_returns((hipc_rs_cb_t)(void *)assoc_like); }, 1 },
	{ "get_returns_foreign_type_neigh", [](void)->int { return get_returns((hipc_rs_cb_t)(void *)neigh_like); }, 1 },

	/* ---- round trip with the setter and sequences ---- */
	{ "set_then_get_roundtrip_a",       [](void)->int { reset(); hal_ipc_server_set_radio_channel_stats_callback(cb_a);
		return hal_ipc_server_get_radio_channel_stats_callback() == cb_a; }, 1 },
	{ "set_a_then_b_get_returns_b",     [](void)->int { reset(); hal_ipc_server_set_radio_channel_stats_callback(cb_a);
		hal_ipc_server_set_radio_channel_stats_callback(cb_b); return hal_ipc_server_get_radio_channel_stats_callback() == cb_b; }, 1 },
	{ "set_then_unregister_get_null",   [](void)->int { reset(); hal_ipc_server_set_radio_channel_stats_callback(cb_a);
		hal_ipc_server_set_radio_channel_stats_callback(NULL); return hal_ipc_server_get_radio_channel_stats_callback() == NULL; }, 1 },
	{ "get_then_set_then_get_changes",  [](void)->int { reset(); hal_ipc_server_set_radio_channel_stats_callback(cb_a);
		hipc_rs_cb_t g1 = hal_ipc_server_get_radio_channel_stats_callback();
		hal_ipc_server_set_radio_channel_stats_callback(cb_b);
		hipc_rs_cb_t g2 = hal_ipc_server_get_radio_channel_stats_callback(); return g1 == cb_a && g2 == cb_b && g1 != g2; }, 1 },
	{ "get_result_feeds_back_to_setter",[](void)->int { reset(); hal_ipc_server_callback_get_radio_channel_stats = cb_c;
		hal_ipc_server_set_radio_channel_stats_callback(hal_ipc_server_get_radio_channel_stats_callback());
		return hal_ipc_server_callback_get_radio_channel_stats == cb_c; }, 1 },

	/* ---- getter is read-only ---- */
	{ "get_does_not_modify_global",     [](void)->int { reset(); hal_ipc_server_callback_get_radio_channel_stats = cb_a;
		hal_ipc_server_get_radio_channel_stats_callback(); return hal_ipc_server_callback_get_radio_channel_stats == cb_a; }, 1 },
	{ "get_does_not_modify_null_global",[](void)->int { reset(); hal_ipc_server_get_radio_channel_stats_callback();
		return hal_ipc_server_callback_get_radio_channel_stats == NULL; }, 1 },
	{ "ap_assoc_dev_diag_res3_global_unchanged",  [](void)->int { reset(); hal_ipc_server_callback_get_ap_assoc_dev_diag_res3 = (hipc_cb_t)(void *)assoc_like;
		hal_ipc_server_get_radio_channel_stats_callback(); return hal_ipc_server_callback_get_ap_assoc_dev_diag_res3 == (hipc_cb_t)(void *)assoc_like; }, 1 },
	{ "neighbor_ap2_global_unchanged",  [](void)->int { reset(); hal_ipc_server_callback_get_neighbor_ap2 = (hipc_nb_cb_t)(void *)neigh_like;
		hal_ipc_server_get_radio_channel_stats_callback(); return hal_ipc_server_callback_get_neighbor_ap2 == (hipc_nb_cb_t)(void *)neigh_like; }, 1 },
	{ "getter_does_not_invoke_callback",[](void)->int { reset(); hal_ipc_server_callback_get_radio_channel_stats = cb_a;
		hal_ipc_server_get_radio_channel_stats_callback(); return cb_calls == 0; }, 1 },
	{ "returned_cb_a_callable_11",      [](void)->int { reset(); hal_ipc_server_callback_get_radio_channel_stats = cb_a;
		return hal_ipc_server_get_radio_channel_stats_callback()(0, NULL, NULL) == 11; }, 1 },
	{ "returned_cb_b_callable_22",      [](void)->int { reset(); hal_ipc_server_callback_get_radio_channel_stats = cb_b;
		return hal_ipc_server_get_radio_channel_stats_callback()(0, NULL, NULL) == 22; }, 1 },

	/* ---- repeated reads ---- */
	{ "two_gets_return_same_value",     [](void)->int { reset(); hal_ipc_server_callback_get_radio_channel_stats = cb_a;
		return hal_ipc_server_get_radio_channel_stats_callback() == hal_ipc_server_get_radio_channel_stats_callback(); }, 1 },
	{ "deterministic_1000_gets",        [](void)->int { reset(); hal_ipc_server_callback_get_radio_channel_stats = cb_b;
		for (int i = 0; i < 1000; i++) if (hal_ipc_server_get_radio_channel_stats_callback() != cb_b) return 0;
		return hipc_log_calls == 1000; }, 1 },

	/* ---- debug log line ---- */
	{ "log_message_exact",              [](void)->int { reset(); hal_ipc_server_get_radio_channel_stats_callback();
		char want[160]; snprintf(want, sizeof(want), "%s: Enter.\n", FN); return !strcmp(hipc_log_buf, want); }, 1 },
	{ "log_contains_function_name",     [](void)->int { reset(); hal_ipc_server_get_radio_channel_stats_callback(); return strstr(hipc_log_buf, FN) != NULL; }, 1 },
	{ "log_ends_with_newline",          [](void)->int { reset(); hal_ipc_server_get_radio_channel_stats_callback();
		size_t n = strlen(hipc_log_buf); return n > 0 && hipc_log_buf[n - 1] == '\n'; }, 1 },
	{ "log_level_is_debug",             [](void)->int { reset(); hal_ipc_server_get_radio_channel_stats_callback(); return hipc_log_level == 0; }, 1 },
	{ "log_emitted_once_per_call",      [](void)->int { reset(); hal_ipc_server_get_radio_channel_stats_callback(); return hipc_log_calls == 1; }, 1 },
	{ "log_emitted_10_times_for_10",    [](void)->int { reset(); for (int i = 0; i < 10; i++) hal_ipc_server_get_radio_channel_stats_callback(); return hipc_log_calls == 10; }, 1 },
	{ "log_same_message_when_null",     [](void)->int { reset(); hal_ipc_server_get_radio_channel_stats_callback();
		char want[160]; snprintf(want, sizeof(want), "%s: Enter.\n", FN); return !strcmp(hipc_log_buf, want) && hipc_log_calls == 1; }, 1 },
	{ "log_fits_in_slot_use_size",      [](void)->int { reset(); hal_ipc_server_get_radio_channel_stats_callback(); return strlen(hipc_log_buf) < HIPC_LOG_USE; }, 1 },

	/* ---- side effects / context ---- */
	{ "errno_unchanged",                [](void)->int { reset(); errno = 0; hal_ipc_server_get_radio_channel_stats_callback(); return errno == 0; }, 1 },
	{ "call_via_function_pointer",      [](void)->int { hipc_rs_cb_t (*fp)(void) = hal_ipc_server_get_radio_channel_stats_callback;
		reset(); hal_ipc_server_callback_get_radio_channel_stats = cb_c; return fp() == cb_c; }, 1 },
	{ "get_from_thread_sees_value",     [](void)->int { pthread_t t; void *r; reset(); hal_ipc_server_callback_get_radio_channel_stats = cb_a;
		pthread_create(&t, NULL, thr_get, (void *)cb_a); pthread_join(t, &r); return (intptr_t)r == 0; }, 1 },
	{ "four_threads_all_read_same",     [](void)->int { pthread_t t[4]; void *r; int bad = 0; reset(); hal_ipc_server_callback_get_radio_channel_stats = cb_b;
		for (int i = 0; i < 4; i++) pthread_create(&t[i], NULL, thr_get, (void *)cb_b);
		for (int i = 0; i < 4; i++) { pthread_join(t[i], &r); bad += (int)(intptr_t)r; } return bad == 0; }, 1 },
	{ NULL, NULL, 0 }
};

static const hipc_grcs_test_case_t *cur_tc;

void construct_hal_ipc_server_get_radio_channel_stats_callback_input(const hipc_grcs_test_case_t *tc)
{
	cur_tc = tc;
	memset(hipc_log_buf, 0, HIPC_LOG_SZ);
}

int hal_ipc_server_get_radio_channel_stats_callback_run_current(void)
{
	return cur_tc->scenario();
}
