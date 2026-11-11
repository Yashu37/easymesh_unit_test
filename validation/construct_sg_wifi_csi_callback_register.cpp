/*
 * UNIT TEST (input constructor): construct_sg_wifi_csi_callback_register
 *
 * wifi_csi_callback_register(func).  Inputs crossed: func NULL / callback A / callback B; the callback registered before none / A / B; one and two consecutive registrations (the second passes the
 * other callback); the callbacks table available / not available (get_hal_device_callbacks() returns NULL).  Expected (CORRECT behaviour): table available -> the CSI slot holds
 * exactly the last callback passed (NULL clears it, a later one replaces an earlier one) with the neighbouring table members untouched; table not available -> nothing written (the function returns void).
 * No crash case is expected.
 */
#include "hwr_wci.h"

/* name, old_cb, new_cb, no_cbs, calls, last */
hwr_wci_case_t sg_wifi_csi_callback_register_suite[] = {
	{ "register_a_first_time",      0, 1, 0, 1, 0 },
	{ "register_b_first_time",      0, 2, 0, 1, 0 },
	{ "register_null_when_empty",   0, 0, 0, 1, 0 },
	{ "replace_a_with_b",           1, 2, 0, 1, 0 },
	{ "replace_b_with_a",           2, 1, 0, 1, 0 },
	{ "same_callback_again",        1, 1, 0, 1, 0 },
	{ "null_clears_registered",     1, 0, 0, 1, 0 },
	{ "two_registrations_a_then_b", 0, 1, 0, 2, 0 },
	{ "two_registrations_null_then_a", 0, 0, 0, 2, 0 },
	{ "table_not_available_a",      0, 1, 1, 1, 0 },
	{ "table_not_available_null",   1, 0, 1, 1, 0 },
	{ "table_not_available_keeps_old", 2, 1, 1, 2, 0 },
	{ NULL }
};
