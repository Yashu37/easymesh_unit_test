/*
 * UNIT TEST (input constructor): construct_int_wifi_sendActionFrameExt
 *
 * wifi_sendActionFrameExt(apIndex, MacAddr, frequency, wait, frame, len) (platform/intel) is an empty stub that returns RETURN_ERR (-1) for every input:
 * nothing is sent, nothing is logged and neither MacAddr nor frame is read.  The suite pins that contract.  Inputs crossed: apIndex 0 / 1 / 15 / -1 / INT_MIN /
 * INT_MAX, frequency 0 / 2412 / 5180 / 5955 / UINT_MAX, wait 0 / 1 / 100 / UINT_MAX, frame NULL / a fully POISONED runner slab / a dangling pointer, len 0 / 1 /
 * 24 / 255 / 4096 / UINT_MAX (the length is not backed by memory: the stub must not read the frame), the MAC address held in a fully POISONED 6-byte
 * array, repeated calls, and a log slot that is empty / holds text / is almost full / is full (it must stay as it was).
 */
#include <limits.h>
#include "hwr_isa.h"

#define ERR RETURN_ERR

/* name, ap_index, frequency, wait, frame_mode, len, calls, prefill, expected_ret */
hwr_isa_case_t int_wifi_sendActionFrameExt_suite[] = {
	{ "typical_ap0",                 0,     2412,        0, 1,        24,  1,   0, ERR },
	{ "typical_ap1_5ghz",            1,     5180,      100, 1,       255,  1,   0, ERR },
	{ "frequency_0",                 0,        0,        0, 1,        24,  1,   0, ERR },
	{ "frequency_5955_6ghz",         0,     5955,        0, 1,        24,  1,   0, ERR },
	{ "frequency_uint_max",          0, UINT_MAX,        0, 1,        24,  1,   0, ERR },
	{ "wait_1",                      0,     2412,        1, 1,        24,  1,   0, ERR },
	{ "wait_uint_max",               0,     2412, UINT_MAX, 1,        24,  1,   0, ERR },
	{ "ap_15",                      15,     2412,        0, 1,        24,  1,   0, ERR },
	{ "ap_negative",                -1,     2412,        0, 1,        24,  1,   0, ERR },
	{ "ap_int_min",            INT_MIN,     2412,        0, 1,        24,  1,   0, ERR },
	{ "ap_int_max",            INT_MAX,     2412,        0, 1,        24,  1,   0, ERR },
	{ "len_0",                       0,     2412,        0, 1,         0,  1,   0, ERR },
	{ "len_1",                       0,     2412,        0, 1,         1,  1,   0, ERR },
	{ "len_4096",                    0,     2412,        0, 1,      4096,  1,   0, ERR },
	{ "len_uint_max_poisoned_frame", 0,     2412,        0, 1,  UINT_MAX,  1,   0, ERR },
	{ "frame_null_len_0",            0,     2412,        0, 0,         0,  1,   0, ERR },
	{ "frame_null_len_24",           0,     2412,        0, 0,        24,  1,   0, ERR },
	{ "frame_null_len_uint_max",     0,     2412,        0, 0,  UINT_MAX,  1,   0, ERR },
	{ "frame_dangling_len_24",       0,     2412,        0, 2,        24,  1,   0, ERR },
	{ "frame_dangling_len_uint_max", 0,     2412,        0, 2,  UINT_MAX,  1,   0, ERR },
	{ "all_extremes",          INT_MIN, UINT_MAX, UINT_MAX, 1,  UINT_MAX,  1,   0, ERR },
	{ "two_calls",                   0,     2412,        0, 1,        24,  2,   0, ERR },
	{ "ten_calls_null_frame",        1,     5180,       50, 0,        24, 10,   0, ERR },
	{ "log_prefilled_1",             0,     2412,        0, 1,        24,  1,   1, ERR },
	{ "log_prefilled_100",           0,     2412,        0, 1,        24,  1, 100, ERR },
	{ "log_almost_full",             0,     2412,        0, 1,        24,  1, 254, ERR },
	{ "log_full",                    0,     2412,        0, 1,        24,  1, 255, ERR },
	{ "log_full_frame_null",         0,     2412,        0, 0,        24,  1, 255, ERR },
	{ NULL, 0, 0, 0, 0, 0, 0, 0, 0 }
};
