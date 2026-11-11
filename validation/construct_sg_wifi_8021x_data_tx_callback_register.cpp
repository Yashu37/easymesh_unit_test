/*
 * UNIT TEST (input constructor): construct_sg_wifi_8021x_data_tx_callback_register
 *
 * wifi_8021x_data_tx_callback_register(func).  Inputs crossed: func NULL / callback A / callback B; the tx callback registered before none / A / B; an rx callback registered or not (it must stay);
 * one and two consecutive registrations (the second passes the other callback).  Expected (CORRECT behaviour): the EAPOL frame tx slot holds exactly the last callback passed (NULL clears it, a later one
 * replaces an earlier one), the neighbouring table members including the rx callback are untouched, and the accessor is used once per call.  A NULL callbacks table cannot occur: the real accessor returns
 * the address of a global (design note, not modelled).  No crash case is expected.
 */
#include "hwr_wtx.h"

/* name, old_tx, old_rx, new_cb, calls, last */
hwr_wtx_case_t sg_wifi_8021x_data_tx_callback_register_suite[] = {
	{ "register_a_first_time",        0, 0, 1, 1, 0 },
	{ "register_b_first_time",        0, 0, 2, 1, 0 },
	{ "register_null_when_empty",     0, 0, 0, 1, 0 },
	{ "replace_a_with_b",             1, 0, 2, 1, 0 },
	{ "replace_b_with_a",             2, 0, 1, 1, 0 },
	{ "same_callback_again",          1, 0, 1, 1, 0 },
	{ "null_clears_registered",       1, 0, 0, 1, 0 },
	{ "rx_callback_kept_a",           0, 1, 1, 1, 0 },
	{ "rx_callback_kept_null",        1, 1, 0, 1, 0 },
	{ "two_registrations_a_then_b",   0, 0, 1, 2, 0 },
	{ "two_registrations_null_then_a",0, 1, 0, 2, 0 },
	{ "two_registrations_b_then_a",   0, 0, 2, 2, 0 },
	{ NULL }
};
