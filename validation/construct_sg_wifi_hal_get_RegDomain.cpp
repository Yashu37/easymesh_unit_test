/*
 * UNIT TEST (input constructor): construct_sg_wifi_hal_get_RegDomain
 *
 * wifi_hal_get_RegDomain(radioIndex, reg_domain).  Inputs crossed: radioIndex 0 / 1 / 2 / 255 / UINT_MAX (forwarded to the platform); reg_domain an exact 4-byte heap block / NULL; the platform function
 * present / absent; the platform function returning 0 / 1 / -1 / INT_MIN and writing or not writing the domain (0 / 0x10 / UINT_MAX).  Expected (CORRECT behaviour): no platform function -> RETURN_ERR; otherwise
 * the platform result is returned unchanged, with radioIndex and the pointer forwarded unchanged and the output exactly as the platform left it (the wrapper only forwards, it never reads or writes it); a
 * NULL reg_domain is the platform's concern and is forwarded as is.  No crash case is expected.
 */
#include "hwr_wgr.h"
#include <limits.h>

/* name, radio_index, out_null, no_fn, fn_ret, write_dom, dom_value, last */
hwr_wgr_case_t sg_wifi_hal_get_RegDomain_suite[] = {
	{ "radio0_domain_0x10",        0, 0, 0, 0, 1, 0x10, 0 },
	{ "radio1_domain_0",           1, 0, 0, 0, 1, 0, 0 },
	{ "radio2_domain_uint_max",    2, 0, 0, 0, 1, UINT_MAX, 0 },
	{ "radio255_forwarded",        255, 0, 0, 0, 1, 0x20, 0 },
	{ "radio_uint_max_forwarded",  UINT_MAX, 0, 0, 0, 1, 0x20, 0 },
	{ "platform_returns_1",        0, 0, 0, 1, 1, 0x30, 0 },
	{ "platform_returns_minus1",   0, 0, 0, -1, 0, 0, 0 },
	{ "platform_returns_int_min",  1, 0, 0, INT_MIN, 0, 0, 0 },
	{ "platform_does_not_write",   0, 0, 0, 0, 0, 0, 0 },
	{ "no_platform_function",      0, 0, 1, 0, 1, 0x10, 0 },
	{ "no_platform_function_radio_big", UINT_MAX, 0, 1, 0, 0, 0, 0 },
	{ "out_null_forwarded",        0, 1, 0, -1, 0, 0, 0 },
	{ "out_null_no_platform_function", 1, 1, 1, 0, 0, 0, 0 },
	{ NULL }
};
