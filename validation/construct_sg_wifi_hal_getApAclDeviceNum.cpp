/*
 * UNIT TEST (input constructor): construct_sg_wifi_hal_getApAclDeviceNum
 *
 * wifi_hal_getApAclDeviceNum(apIndex, aclCount).  Inputs crossed: aclCount NULL (with the driver call succeeding / failing); apIndex 0 / 7 / -1 / INT_MAX / INT_MIN, which must reach the driver call unchanged;
 * the driver call returning 0 / -1 / 1 / 5 / INT_MIN / INT_MAX; the count it reports: 0 / 1 / 5 / UINT_MAX.  aclCount is an exact 4-byte heap block initialised to a sentinel.  Expected (CORRECT behaviour):
 * NULL aclCount -> -1 and the driver call not made; otherwise the driver call is made once with the same apIndex and the same pointer, result 0 when it returns 0 (aclCount = the reported count) and -1 for any
 * other value (aclCount left at its sentinel).  No crash case is expected.
 */
#include "hwr_wgn.h"
#include <limits.h>

/* name, apIndex, null_count, drv_ret, drv_value, last */
hwr_wgn_case_t sg_wifi_hal_getApAclDeviceNum_suite[] = {
	{ "aclCount_null",             0, 1, 0, 5, 0 },
	{ "aclCount_null_driver_fails",0, 1,-1, 5, 0 },
	{ "aclCount_null_apIndex_minus1", -1, 1, 0, 5, 0 },
	{ "count_0",                   0, 0, 0, 0, 0 },
	{ "count_1",                   0, 0, 0, 1, 0 },
	{ "count_5",                   7, 0, 0, 5, 0 },
	{ "count_uint_max",            0, 0, 0, UINT_MAX, 0 },
	{ "apIndex_minus1",           -1, 0, 0, 3, 0 },
	{ "apIndex_int_max",     INT_MAX, 0, 0, 3, 0 },
	{ "apIndex_int_min",     INT_MIN, 0, 0, 3, 0 },
	{ "driver_fails_minus1",       0, 0,-1, 9, 0 },
	{ "driver_fails_1",            0, 0, 1, 9, 0 },
	{ "driver_fails_5",            2, 0, 5, 9, 0 },
	{ "driver_fails_int_min",      0, 0, INT_MIN, 9, 0 },
	{ "driver_fails_int_max",      0, 0, INT_MAX, 9, 0 },
	{ "driver_fails_apIndex_minus1", -1, 0,-1, 9, 0 },
	{ NULL, 0, 0, 0, 0, 0 }
};
