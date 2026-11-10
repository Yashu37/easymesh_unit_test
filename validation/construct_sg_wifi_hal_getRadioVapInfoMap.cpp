/*
 * UNIT TEST (input constructor): construct_sg_wifi_hal_getRadioVapInfoMap
 *
 * wifi_hal_getRadioVapInfoMap(index, map).  Inputs crossed: radio index (0 / 1, -1, MAX_NUM_RADIOS, INT_MIN); map NULL; no radio / radio->interface_map NULL / an empty interface map; 1 / 2 / 3 / 8 / 9 / 12 /
 * 16 / 20 interfaces in the radio's interface map; interfaces with a negative vap_index (radio interfaces: skipped, first / middle / alternate / all); every vap_name kind ("wl_ap<k>" -> the interface MAC is the
 * bssid, "sim_sta<k>" and "mesh_sta<k>" -> the sta mac, a name too short for the prefix, an empty name, a 32-character name without a terminator, "sim_stax", a mix); vap_index INT_MAX.  The runner allocates the map
 * exactly (a heap block of sizeof(wifi_vap_info_map_t), whose vap_array holds 8 entries).  Expected (CORRECT behaviour): an invalid argument -> -4, no radio / no interface map / empty map -> -1, the map untouched;
 * otherwise 0, the first min(count, 8) non-negative interfaces copied in order with their MAC stored by the name rule, map->num_vaps = min(count, 8), nothing written past the array.  Rows with last = 1 (more than 8
 * VAP interfaces) break the original: they run LAST.
 */
#include "hwr_wvm.h"
#include <limits.h>

/* name, index, null_map, no_radio, null_imap, n_if, neg_mask, name_kind, vap_index0, last */
hwr_wvm_case_t sg_wifi_hal_getRadioVapInfoMap_suite[] = {
	/* ---- argument / radio preconditions ---- */
	{ "map_null",                  0, 1, 0, 0, 3, 0,    0, 0, 0 },
	{ "index_minus1",             -1, 0, 0, 0, 3, 0,    0, 0, 0 },
	{ "index_max_num_radios", MAX_NUM_RADIOS, 0, 0, 0, 3, 0, 0, 0, 0 },
	{ "index_int_min",       INT_MIN, 0, 0, 0, 3, 0,    0, 0, 0 },
	{ "no_radio",                  0, 0, 1, 0, 3, 0,    0, 0, 0 },
	{ "interface_map_null",        0, 0, 0, 1, 3, 0,    0, 0, 0 },
	{ "interface_map_empty",       0, 0, 0, 0, 0, 0,    0, 0, 0 },
	/* ---- counts ---- */
	{ "one_interface",             0, 0, 0, 0, 1, 0,    0, 0, 0 },
	{ "two_interfaces",            0, 0, 0, 0, 2, 0,    0, 0, 0 },
	{ "three_interfaces",          0, 0, 0, 0, 3, 0,    0, 0, 0 },
	{ "eight_interfaces_array_size",0,0, 0, 0, 8, 0,    0, 0, 0 },
	{ "radio_index_1",             1, 0, 0, 0, 3, 0,    0, 0, 0 },
	{ "vap_index_int_max",         0, 0, 0, 0, 1, 0,    0, 0x7fffffffu, 0 },
	/* ---- radio interfaces (negative vap_index) are skipped ---- */
	{ "first_interface_negative",  0, 0, 0, 0, 3, 1,    0, 0, 0 },
	{ "middle_interface_negative", 0, 0, 0, 0, 3, 2,    0, 0, 0 },
	{ "alternate_negative",        0, 0, 0, 0, 6, 0x2a, 0, 0, 0 },
	{ "all_interfaces_negative",   0, 0, 0, 0, 3, 7,    0, 0, 0 },
	{ "nine_interfaces_one_negative", 0, 0, 0, 0, 9, 1, 0, 0, 0 },
	/* ---- MAC stored by the vap_name rule ---- */
	{ "name_sim_sta",              0, 0, 0, 0, 3, 0,    1, 0, 0 },
	{ "name_mesh_sta",             0, 0, 0, 0, 3, 0,    2, 0, 0 },
	{ "name_too_short_mesh_st",    0, 0, 0, 0, 3, 0,    3, 0, 0 },
	{ "name_empty",                0, 0, 0, 0, 3, 0,    4, 0, 0 },
	{ "name_unterminated_32",      0, 0, 0, 0, 3, 0,    5, 0, 0 },
	{ "name_sim_stax",             0, 0, 0, 0, 3, 0,    6, 0, 0 },
	{ "names_mixed",               0, 0, 0, 0, 6, 0,    7, 0, 0 },
	/* ---- more VAP interfaces than the 8-entry vap_array: the original writes vap_array[8..] beyond the map ---- */
	{ "nine_interfaces",           0, 0, 0, 0, 9, 0,    0, 0, 1 },
	{ "twelve_interfaces",         0, 0, 0, 0, 12, 0,   0, 0, 1 },
	{ "sixteen_interfaces_sta_names", 0, 0, 0, 0, 16, 0, 1, 0, 1 },
	{ "twenty_interfaces",         0, 0, 0, 0, 20, 0,   7, 0, 1 },
	{ NULL, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
};
