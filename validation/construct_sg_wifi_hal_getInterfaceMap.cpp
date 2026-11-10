/*
 * UNIT TEST (input constructor): construct_sg_wifi_hal_getInterfaceMap
 *
 * wifi_hal_getInterfaceMap(if_map, max_entries, if_map_size).  Inputs crossed: map size 0 / 1 / 6 / 40; max_entries below / equal / above the size (0, size-1,
 * size, size+1, 1000, UINT_MAX); if_map NULL / exact-size poisoned slab / dangling; if_map_size NULL or valid; repeated calls.  Expected: size <= max -> 0 and the
 * table copied; size > max -> -1, *if_map_size = size, nothing copied.  Rows with last = 1 (NULL if_map_size; NULL if_map with entries to copy) abort the original: they run LAST.
 */
#include "hwr_gim.h"
#include <limits.h>

#define OK 0
#define ER -1
#define U UINT_MAX
/* name, size, max_entries, map_mode, size_mode, calls, expected_ret, last */
hwr_gim_case_t sg_wifi_hal_getInterfaceMap_suite[] = {
	{ "size6_max6_exact",               6,    6, 1, 1, 1, OK, 0 },
	{ "size6_max7",                     6,    7, 1, 1, 1, OK, 0 },
	{ "size6_max1000",                  6, 1000, 1, 1, 1, OK, 0 },
	{ "size6_max_uintmax",              6,    U, 1, 1, 1, OK, 0 },
	{ "size6_max5_too_small",           6,    5, 1, 1, 1, ER, 0 },
	{ "size6_max1_too_small",           6,    1, 1, 1, 1, ER, 0 },
	{ "size6_max0_too_small",           6,    0, 1, 1, 1, ER, 0 },
	{ "size1_max1",                     1,    1, 1, 1, 1, OK, 0 },
	{ "size1_max0_too_small",           1,    0, 1, 1, 1, ER, 0 },
	{ "size1_max2",                     1,    2, 1, 1, 1, OK, 0 },
	{ "size40_max40",                  40,   40, 1, 1, 1, OK, 0 },
	{ "size40_max39_too_small",        40,   39, 1, 1, 1, ER, 0 },
	{ "size40_max41",                  40,   41, 1, 1, 1, OK, 0 },
	{ "size40_max0_too_small",         40,    0, 1, 1, 1, ER, 0 },
	{ "size0_max0",                     0,    0, 1, 1, 1, OK, 0 },
	{ "size0_max5",                     0,    5, 1, 1, 1, OK, 0 },
	{ "size0_max_uintmax",              0,    U, 1, 1, 1, OK, 0 },
	{ "size6_max6_two_calls",           6,    6, 1, 1, 2, OK, 0 },
	{ "size6_max5_two_calls",           6,    5, 1, 1, 2, ER, 0 },
	{ "size40_max40_five_calls",       40,   40, 1, 1, 5, OK, 0 },
	/* if_map NULL / dangling: only fine when nothing is copied */
	{ "map_null_too_small",             6,    5, 0, 1, 1, ER, 0 },
	{ "map_null_max0_size1",            1,    0, 0, 1, 1, ER, 0 },
	{ "map_dangling_too_small",         6,    5, 2, 1, 1, ER, 0 },
	{ "map_dangling_size40_max0",      40,    0, 2, 1, 1, ER, 0 },
	{ "map_null_size0",                 0,    5, 0, 1, 1, OK, 0 },
	{ "map_dangling_size0",             0,    5, 2, 1, 1, OK, 0 },
	/* if_map_size NULL when the call is rejected / accepted: dereferenced before any check */
	{ "size_ptr_null_too_small",        6,    5, 1, 0, 1, ER, 1 },
	{ "size_ptr_null_ok",               6,    6, 1, 0, 1, OK, 1 },
	{ "size_ptr_null_size0",            0,    0, 1, 0, 1, OK, 1 },
	{ "size_ptr_null_map_null",         6,    6, 0, 0, 1, OK, 1 },
	{ "map_null_size6_max6",            6,    6, 0, 1, 1, OK, 1 },
	{ "map_null_size1_max1",            1,    1, 0, 1, 1, OK, 1 },
	{ "map_null_size40_max_uintmax",   40,    U, 0, 1, 1, OK, 1 },
	{ "map_dangling_size6_max6",        6,    6, 2, 1, 1, OK, 1 },
	{ NULL, 0, 0, 0, 0, 0, 0, 0 }
};
