/*
 * UNIT TEST (input constructor): construct_sg_wifi_hal_set_acs_keep_out_chans
 *
 * wifi_hal_set_acs_keep_out_chans(wifi_radio_oper_param, radioIndex).  Inputs crossed: parameter NULL (the exclusion list is cleared); radio index 0 / 1 / -1 / INT_MAX; every bandwidth entry empty; 1 .. 6 bandwidth
 * entries with 1 / 2 / 64 channel lists of 0 / 2 / 3 / 4 / 64 channels; negative num_channels_list; the platform chanspec hook failing on the first / second / third call; wifi_drv_set_acs_exclusion_list failing; exactly 256
 * chanspecs (the capacity of buff: ACS_MAX_VECTOR_LEN = 256 * 7), 255, and 257 / 1536 chanspecs (more than buff holds: the hook appends 7 bytes per channel with strcat and no size); num_channels_list above the 64-entry
 * channels_list array (65, INT_MAX) on the first and on the last bandwidth entry.  The runner allocates the parameter exactly (a heap block of sizeof(wifi_radio_operationParam_t)).  Expected (CORRECT behaviour,
 * reference model in the runner): a NULL parameter -> set(NULL), its result; otherwise the chanspec strings of all lists in order, the trailing comma removed, passed to the set function (empty string when there is
 * none), its result returned; a failing hook -> -1 and no set; a num_channels_list above 64 or a list that would not fit in buff -> -1, no overflow, no set.  Rows with last = 1 break the original: they run LAST.
 */
#include "hwr_wak.h"
#include <limits.h>

/* name, radio_index, null_param, nlist[6], nch[6], fail_at, set_ret, last */
hwr_wak_case_t sg_wifi_hal_set_acs_keep_out_chans_suite[] = {
	/* ---- NULL parameter ---- */
	{ "null_param_clears_list",      0, 1, {0},                  {0},                   0,  0, 0 },
	{ "null_param_set_fails",        0, 1, {0},                  {0},                   0, -1, 0 },
	{ "null_param_radio_1",          1, 1, {0},                  {0},                   0,  0, 0 },
	{ "null_param_radio_minus1",    -1, 1, {0},                  {0},                   0,  0, 0 },
	/* ---- normal lists ---- */
	{ "all_bandwidths_empty",        0, 0, {0},                  {0},                   0,  0, 0 },
	{ "one_bw_one_list_3ch",         0, 0, {1,0,0,0,0,0},        {3,0,0,0,0,0},         0,  0, 0 },
	{ "one_bw_two_lists",            0, 0, {2,0,0,0,0,0},        {2,0,0,0,0,0},         0,  0, 0 },
	{ "last_bw_only",                0, 0, {0,0,0,0,0,1},        {0,0,0,0,0,4},         0,  0, 0 },
	{ "each_bw_one_list",            0, 0, {1,1,1,1,1,1},        {2,2,2,2,2,2},         0,  0, 0 },
	{ "lists_with_zero_channels",    0, 0, {2,0,0,0,0,0},        {0,0,0,0,0,0},         0,  0, 0 },
	{ "mixed_lists",                 0, 0, {1,0,3,0,2,0},        {4,0,1,0,3,0},         0,  0, 0 },
	{ "one_list_64_channels",        0, 0, {1,0,0,0,0,0},        {64,0,0,0,0,0},        0,  0, 0 },
	{ "all_bw_64_lists_no_channels", 0, 0, {64,64,64,64,64,64},  {0,0,0,0,0,0},         0,  0, 0 },
	{ "num_channels_list_negative",  0, 0, {-1,0,INT_MIN,0,0,0}, {3,0,3,0,0,0},         0,  0, 0 },
	{ "radio_index_1",               1, 0, {1,0,0,0,0,0},        {3,0,0,0,0,0},         0,  0, 0 },
	{ "radio_index_minus1",         -1, 0, {1,0,0,0,0,0},        {3,0,0,0,0,0},         0,  0, 0 },
	{ "radio_index_int_max",   INT_MAX, 0, {1,0,0,0,0,0},        {3,0,0,0,0,0},         0,  0, 0 },
	/* ---- platform hook / set function failing ---- */
	{ "hook_fails_first_call",       0, 0, {2,1,0,0,0,0},        {2,2,0,0,0,0},         1,  0, 0 },
	{ "hook_fails_second_call",      0, 0, {2,1,0,0,0,0},        {2,2,0,0,0,0},         2,  0, 0 },
	{ "hook_fails_third_call",       0, 0, {2,1,0,0,0,0},        {2,2,0,0,0,0},         3,  0, 0 },
	{ "set_fails_minus1",            0, 0, {1,0,0,0,0,0},        {3,0,0,0,0,0},         0, -1, 0 },
	{ "set_fails_5",                 0, 0, {1,0,0,0,0,0},        {3,0,0,0,0,0},         0,  5, 0 },
	/* ---- buff capacity: 256 chanspecs of 7 bytes ---- */
	{ "exactly_256_chanspecs",       0, 0, {1,1,1,1,0,0},        {64,64,64,64,0,0},     0,  0, 0 },
	{ "255_chanspecs",               0, 0, {1,1,1,1,0,0},        {64,64,64,63,0,0},     0,  0, 0 },
	{ "256_chanspecs_in_64_lists",   0, 0, {64,0,0,0,0,0},       {4,0,0,0,0,0},         0,  0, 0 },
	/* ---- the original overruns buff (stack) or hands the hook a list pointer past the parameter ---- */
	{ "257_chanspecs_overflow_buff", 0, 0, {1,1,1,1,1,0},        {64,64,64,64,1,0},     0,  0, 1 },
	{ "1536_chanspecs_overflow_buff",0, 0, {4,4,4,4,4,4},        {64,64,64,64,64,64},   0,  0, 1 },
	{ "num_channels_list_65_first_bw", 0, 0, {65,0,0,0,0,0},     {0,0,0,0,0,0},         0,  0, 1 },
	{ "num_channels_list_65_last_bw",0, 0, {0,0,0,0,0,65},       {0,0,0,0,0,0},         0,  0, 1 },
	{ "num_channels_list_int_max_last_bw", 0, 0, {0,0,0,0,0,INT_MAX}, {0,0,0,0,0,0},    0,  0, 1 },
	{ NULL, 0, 0, {0}, {0}, 0, 0, 0 }
};
