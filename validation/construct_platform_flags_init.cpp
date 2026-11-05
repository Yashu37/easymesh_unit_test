/*
 * UNIT TEST (input constructor): construct_platform_flags_init
 *
 * platform_flags_init(flags) (platform/banana-pi) logs and ASSIGNS *flags = PLATFORM_FLAGS_STA_INACTIVITY_TIMER | PLATFORM_FLAGS_CONTROL_PORT_FRAME
 * (0x10 | 0x02 = 0x12), returns 0.  The only caller (src/wifi_hal.c:569) passes (int *)&g_wifi_hal.platform_flags, a 4-byte enum member of a larger
 * struct.  The runner places the int in the middle of a canary slab, POISONS the bytes around it (head and tail) and checks that exactly 4 bytes
 * change.  Inputs crossed: previous value 0 / 0xFFFFFFFF / 0x12345678 / 0xA5A5A5A5 / 0x12 / 0x02 / 0x10 / 0x01 (the function assigns, it does not OR),
 * repeated calls, log prefilled / almost full / full, NULL flags (crashes the unfixed function: forked).
 */
#include "hwr_pfi.h"

/* name, preset, null_flags, calls, log_prefill, expected_ret, forked */
hwr_pfi_case_t platform_flags_init_suite[] = {
	{ "preset_zero",             0x00000000u, 0, 1,   0, 0, 0 },
	{ "preset_all_ones",         0xFFFFFFFFu, 0, 1,   0, 0, 0 },
	{ "preset_pattern_12345678", 0x12345678u, 0, 1,   0, 0, 0 },
	{ "preset_pattern_A5A5A5A5", 0xA5A5A5A5u, 0, 1,   0, 0, 0 },
	{ "preset_already_0x12",     0x00000012u, 0, 1,   0, 0, 0 },
	{ "preset_control_port_only", 0x00000002u, 0, 1,  0, 0, 0 },
	{ "preset_inactivity_only",  0x00000010u, 0, 1,   0, 0, 0 },
	{ "preset_set_bss_only",     0x00000001u, 0, 1,   0, 0, 0 },
	{ "two_calls_same_result",   0x00000000u, 0, 2,   0, 0, 0 },
	{ "log_prefilled_100",       0x00000000u, 0, 1, 100, 0, 0 },
	{ "log_almost_full",         0x00000000u, 0, 1, 254, 0, 0 },
	{ "log_full_nothing_written", 0x00000000u, 0, 1, 255, 0, 0 },
	{ "crash_flags_null",        0x00000000u, 1, 1,   0, -1, 1 },
	{ "crash_flags_null_two_calls", 0x00000000u, 1, 2, 0, -1, 1 },
	{ NULL, 0, 0, 0, 0, 0, 0 }
};
