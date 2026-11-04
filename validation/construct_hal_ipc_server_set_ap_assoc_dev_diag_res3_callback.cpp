/*
 * UNIT TEST (input constructor): construct_hal_ipc_server_set_ap_assoc_dev_diag_res3_callback
 *
 * The handler takes ONE parameter (a callback function pointer) and stores
 * it in a global, after emitting a debug log line.  The input space is the
 * pointer VALUE (NULL / valid / bogus / odd / data / stack / heap / foreign
 * type), the PRIOR state of the global, the call sequence, the call count,
 * and the thread context.  Each suite entry is a scenario returning 1 when
 * the observed behaviour is what is expected.
 *
 * wifi_hal_print() below is the log sink: it vsnprintf()s into the runner's
 * hipc_log_buf[], handing over only HIPC_LOG_USE bytes of the HIPC_LOG_SZ
 * slot, whose tail the runner poisons.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include "common.h"

char hipc_log_buf[HIPC_LOG_SZ];
int  hipc_log_calls, hipc_log_level;

void wifi_hal_print(wifi_hal_log_level_t level, const char *format, ...)
{
	va_list ap;

	hipc_log_calls++;
	hipc_log_level = (int)level;
	va_start(ap, format);
	vsnprintf(hipc_log_buf, HIPC_LOG_USE, format, ap);
	va_end(ap);
}

static const char *FN = "hal_ipc_server_set_ap_assoc_dev_diag_res3_callback";
static int cb_calls;

static int cb_a(int, hipc_dev3_t *, unsigned int *) { cb_calls++; return 11; }
static int cb_b(int, hipc_dev3_t *, unsigned int *) { cb_calls++; return 22; }
static int cb_c(int, hipc_dev3_t *, unsigned int *) { cb_calls++; return 33; }
static int neigh_like(int, void *, unsigned int *) { return 44; }
static int radio_like(int, void *, unsigned int *) { return 55; }

static void reset(void)
{
	hal_ipc_server_callback_get_ap_assoc_dev_diag_res3 = NULL;
	hal_ipc_server_callback_get_neighbor_ap2 = NULL;
	hal_ipc_server_callback_get_radio_channel_stats = NULL;
	hipc_log_calls = 0;
	hipc_log_level = -1;
	cb_calls = 0;
	memset(hipc_log_buf, 0, HIPC_LOG_USE);
}

static int stored_is(hipc_cb_t want)
{
	return hal_ipc_server_callback_get_ap_assoc_dev_diag_res3 == want;
}

static int set_and_check(hipc_cb_t p)
{
	reset();
	hal_ipc_server_set_ap_assoc_dev_diag_res3_callback(p);
	return stored_is(p);
}


static void *thr_set(void *arg)
{
	hipc_cb_t p = (hipc_cb_t)arg;

	for (int i = 0; i < 200; i++)
		hal_ipc_server_set_ap_assoc_dev_diag_res3_callback(p);
	return NULL;
}

hipc_sadr3_test_case_t hal_ipc_server_set_ap_assoc_dev_diag_res3_callback_suite[] = {
	/* ---- initial state ---- */
	{ "global_initially_null_before_any_set", [](void)->int { return hal_ipc_server_callback_get_ap_assoc_dev_diag_res3 == NULL; }, 1 },

	/* ---- valid / NULL values ---- */
	{ "set_valid_cb_a_stores",          [](void)->int { return set_and_check(cb_a); }, 1 },
	{ "set_valid_cb_b_stores",          [](void)->int { return set_and_check(cb_b); }, 1 },
	{ "set_valid_cb_c_stores",          [](void)->int { return set_and_check(cb_c); }, 1 },
	{ "set_NULL_stores_null",           [](void)->int { return set_and_check(NULL); }, 1 },

	/* ---- sequences (prior state x new value) ---- */
	{ "null_then_valid",                [](void)->int { reset(); hal_ipc_server_set_ap_assoc_dev_diag_res3_callback(NULL);
		hal_ipc_server_set_ap_assoc_dev_diag_res3_callback(cb_a); return stored_is(cb_a); }, 1 },
	{ "valid_then_null_unregisters",    [](void)->int { reset(); hal_ipc_server_set_ap_assoc_dev_diag_res3_callback(cb_a);
		hal_ipc_server_set_ap_assoc_dev_diag_res3_callback(NULL); return stored_is(NULL); }, 1 },
	{ "a_then_b_overwrites",            [](void)->int { reset(); hal_ipc_server_set_ap_assoc_dev_diag_res3_callback(cb_a);
		hal_ipc_server_set_ap_assoc_dev_diag_res3_callback(cb_b); return stored_is(cb_b); }, 1 },
	{ "a_b_c_last_wins",                [](void)->int { reset(); hal_ipc_server_set_ap_assoc_dev_diag_res3_callback(cb_a);
		hal_ipc_server_set_ap_assoc_dev_diag_res3_callback(cb_b); hal_ipc_server_set_ap_assoc_dev_diag_res3_callback(cb_c);
		return stored_is(cb_c); }, 1 },
	{ "set_same_value_twice_idempotent",[](void)->int { reset(); hal_ipc_server_set_ap_assoc_dev_diag_res3_callback(cb_a);
		hal_ipc_server_set_ap_assoc_dev_diag_res3_callback(cb_a); return stored_is(cb_a); }, 1 },
	{ "set_null_twice_idempotent",      [](void)->int { reset(); hal_ipc_server_set_ap_assoc_dev_diag_res3_callback(NULL);
		hal_ipc_server_set_ap_assoc_dev_diag_res3_callback(NULL); return stored_is(NULL); }, 1 },
	{ "alternate_a_b_100_times",        [](void)->int { reset();
		for (int i = 0; i < 100; i++) hal_ipc_server_set_ap_assoc_dev_diag_res3_callback((i & 1) ? cb_b : cb_a);
		return stored_is(cb_b); }, 1 },

	/* ---- bogus / unusual pointer values (stored verbatim, never called) ---- */
	{ "set_pointer_0x1",                [](void)->int { return set_and_check((hipc_cb_t)(uintptr_t)0x1); }, 1 },
	{ "set_pointer_all_ones",           [](void)->int { return set_and_check((hipc_cb_t)(uintptr_t)~(uintptr_t)0); }, 1 },
	{ "set_pointer_odd_address",        [](void)->int { return set_and_check((hipc_cb_t)((uintptr_t)cb_a + 1)); }, 1 },
	{ "set_pointer_data_address",       [](void)->int { static int d; return set_and_check((hipc_cb_t)(void *)&d); }, 1 },
	{ "set_pointer_stack_address",      [](void)->int { int s = 0; return set_and_check((hipc_cb_t)(void *)&s); }, 1 },
	{ "set_pointer_heap_address",       [](void)->int { void *h = malloc(16); int ok = set_and_check((hipc_cb_t)h); free(h); return ok; }, 1 },
	{ "set_pointer_libc_function",      [](void)->int { return set_and_check((hipc_cb_t)(void *)&puts); }, 1 },
	{ "set_pointer_foreign_type_neigh", [](void)->int { return set_and_check((hipc_cb_t)(void *)neigh_like); }, 1 },
	{ "set_pointer_foreign_type_radio", [](void)->int { return set_and_check((hipc_cb_t)(void *)radio_like); }, 1 },

	/* ---- stored pointer is the real callable, and setter never calls it ---- */
	{ "stored_cb_a_callable_returns_11",[](void)->int { set_and_check(cb_a); return hal_ipc_server_callback_get_ap_assoc_dev_diag_res3(0, NULL, NULL) == 11; }, 1 },
	{ "stored_cb_b_callable_returns_22",[](void)->int { set_and_check(cb_b); return hal_ipc_server_callback_get_ap_assoc_dev_diag_res3(0, NULL, NULL) == 22; }, 1 },
	{ "setter_does_not_invoke_callback",[](void)->int { reset(); hal_ipc_server_set_ap_assoc_dev_diag_res3_callback(cb_a); return cb_calls == 0; }, 1 },

	/* ---- the other two callback globals are untouched ---- */
	{ "neighbor_ap2_global_unchanged",  [](void)->int { reset(); hal_ipc_server_callback_get_neighbor_ap2 = (void *)neigh_like;
		hal_ipc_server_set_ap_assoc_dev_diag_res3_callback(cb_a); return hal_ipc_server_callback_get_neighbor_ap2 == (void *)neigh_like; }, 1 },
	{ "radio_stats_global_unchanged",   [](void)->int { reset(); hal_ipc_server_callback_get_radio_channel_stats = (void *)radio_like;
		hal_ipc_server_set_ap_assoc_dev_diag_res3_callback(cb_b); return hal_ipc_server_callback_get_radio_channel_stats == (void *)radio_like; }, 1 },
	{ "other_globals_unchanged_on_null",[](void)->int { reset(); hal_ipc_server_callback_get_neighbor_ap2 = (void *)neigh_like;
		hal_ipc_server_callback_get_radio_channel_stats = (void *)radio_like;
		hal_ipc_server_set_ap_assoc_dev_diag_res3_callback(NULL);
		return hal_ipc_server_callback_get_neighbor_ap2 == (void *)neigh_like && hal_ipc_server_callback_get_radio_channel_stats == (void *)radio_like; }, 1 },

	/* ---- debug log line ---- */
	{ "log_message_exact",              [](void)->int { reset(); hal_ipc_server_set_ap_assoc_dev_diag_res3_callback(cb_a);
		char want[160]; snprintf(want, sizeof(want), "%s: Enter.\n", FN); return !strcmp(hipc_log_buf, want); }, 1 },
	{ "log_contains_function_name",     [](void)->int { reset(); hal_ipc_server_set_ap_assoc_dev_diag_res3_callback(cb_a); return strstr(hipc_log_buf, FN) != NULL; }, 1 },
	{ "log_ends_with_newline",          [](void)->int { reset(); hal_ipc_server_set_ap_assoc_dev_diag_res3_callback(cb_a);
		size_t n = strlen(hipc_log_buf); return n > 0 && hipc_log_buf[n - 1] == '\n'; }, 1 },
	{ "log_level_is_debug",             [](void)->int { reset(); hal_ipc_server_set_ap_assoc_dev_diag_res3_callback(cb_a); return hipc_log_level == 0; }, 1 },
	{ "log_emitted_once_per_call",      [](void)->int { reset(); hal_ipc_server_set_ap_assoc_dev_diag_res3_callback(cb_a); return hipc_log_calls == 1; }, 1 },
	{ "log_emitted_10_times_for_10",    [](void)->int { reset(); for (int i = 0; i < 10; i++) hal_ipc_server_set_ap_assoc_dev_diag_res3_callback(cb_a); return hipc_log_calls == 10; }, 1 },
	{ "log_same_message_for_null_arg",  [](void)->int { reset(); hal_ipc_server_set_ap_assoc_dev_diag_res3_callback(NULL);
		char want[160]; snprintf(want, sizeof(want), "%s: Enter.\n", FN); return !strcmp(hipc_log_buf, want) && hipc_log_calls == 1; }, 1 },
	{ "log_fits_in_slot_use_size",      [](void)->int { reset(); hal_ipc_server_set_ap_assoc_dev_diag_res3_callback(cb_a); return strlen(hipc_log_buf) < HIPC_LOG_USE; }, 1 },

	/* ---- side effects / context ---- */
	{ "errno_unchanged",                [](void)->int { reset(); errno = 0; hal_ipc_server_set_ap_assoc_dev_diag_res3_callback(cb_a); return errno == 0; }, 1 },
	{ "deterministic_1000_calls",       [](void)->int { reset(); for (int i = 0; i < 1000; i++) hal_ipc_server_set_ap_assoc_dev_diag_res3_callback(cb_b);
		return stored_is(cb_b) && hipc_log_calls == 1000; }, 1 },
	{ "call_via_function_pointer",      [](void)->int { void (*fp)(hipc_cb_t) = hal_ipc_server_set_ap_assoc_dev_diag_res3_callback;
		reset(); fp(cb_c); return stored_is(cb_c); }, 1 },
	{ "set_from_thread_visible_after_join", [](void)->int { pthread_t t; reset(); pthread_create(&t, NULL, thr_set, (void *)cb_a);
		pthread_join(t, NULL); return stored_is(cb_a); }, 1 },
	{ "two_threads_final_is_one_of_them",   [](void)->int { pthread_t t1, t2; reset();
		pthread_create(&t1, NULL, thr_set, (void *)cb_a); pthread_create(&t2, NULL, thr_set, (void *)cb_b);
		pthread_join(t1, NULL); pthread_join(t2, NULL); return stored_is(cb_a) || stored_is(cb_b); }, 1 },
	{ NULL, NULL, 0 }
};

static const hipc_sadr3_test_case_t *cur_tc;

void construct_hal_ipc_server_set_ap_assoc_dev_diag_res3_callback_input(const hipc_sadr3_test_case_t *tc)
{
	cur_tc = tc;
	memset(hipc_log_buf, 0, HIPC_LOG_SZ);
}

int hal_ipc_server_set_ap_assoc_dev_diag_res3_callback_run_current(void)
{
	return cur_tc->scenario();
}
