/*
 * UNIT TEST (input constructor): construct_sg_wifi_hal_post_init
 *
 * wifi_hal_post_init(arg), both variants (0 = HAL_IPC wifi_hal_post_init_t *, 1 = plain wifi_vap_info_map_t *).  Inputs crossed: hook present / absent; argument NULL / pointer
 * to a fully POISONED runner slab (never read or written) / dangling; repeated calls; a log slot that is empty / holds text / is almost full / is full.  Expected: 0; one getter
 * call per call; the hook runs once per call (when present) with the argument UNCHANGED.
 */
#include "hwr_wpo.h"

#define OK 0
/* name, variant, hook_present, arg_mode, calls, prefill, expected_ret */
hwr_wpo_case_t sg_wifi_hal_post_init_suite[] = {
	{ "ipc_hook_arg_slab",            0, 1, 1,  1,   0, OK },
	{ "ipc_hook_arg_null",            0, 1, 0,  1,   0, OK },
	{ "ipc_hook_arg_dangling",        0, 1, 2,  1,   0, OK },
	{ "ipc_nohook_arg_slab",          0, 0, 1,  1,   0, OK },
	{ "ipc_nohook_arg_null",          0, 0, 0,  1,   0, OK },
	{ "ipc_nohook_arg_dangling",      0, 0, 2,  1,   0, OK },
	{ "ipc_hook_two_calls",           0, 1, 1,  2,   0, OK },
	{ "ipc_hook_fifty_calls",         0, 1, 1, 50,   0, OK },
	{ "ipc_nohook_fifty_calls",       0, 0, 1, 50,   0, OK },
	{ "ipc_hook_log_prefilled",       0, 1, 1,  1, 100, OK },
	{ "ipc_hook_log_almost_full",     0, 1, 1,  1, 254, OK },
	{ "ipc_hook_log_full",            0, 1, 1,  1, 255, OK },
	{ "ipc_nohook_log_full",          0, 0, 1,  1, 255, OK },
	{ "vap_hook_arg_slab",            1, 1, 1,  1,   0, OK },
	{ "vap_hook_arg_null",            1, 1, 0,  1,   0, OK },
	{ "vap_hook_arg_dangling",        1, 1, 2,  1,   0, OK },
	{ "vap_nohook_arg_slab",          1, 0, 1,  1,   0, OK },
	{ "vap_nohook_arg_null",          1, 0, 0,  1,   0, OK },
	{ "vap_nohook_arg_dangling",      1, 0, 2,  1,   0, OK },
	{ "vap_hook_two_calls",           1, 1, 1,  2,   0, OK },
	{ "vap_hook_fifty_calls",         1, 1, 1, 50,   0, OK },
	{ "vap_nohook_fifty_calls",       1, 0, 1, 50,   0, OK },
	{ "vap_hook_log_prefilled",       1, 1, 1,  1, 100, OK },
	{ "vap_hook_log_almost_full",     1, 1, 1,  1, 254, OK },
	{ "vap_hook_log_full",            1, 1, 1,  1, 255, OK },
	{ "vap_nohook_log_full",          1, 0, 1,  1, 255, OK },
	{ NULL, 0, 0, 0, 0, 0, 0 }
};
