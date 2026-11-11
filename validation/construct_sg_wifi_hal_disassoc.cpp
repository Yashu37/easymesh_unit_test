/*
 * UNIT TEST (input constructor): construct_sg_wifi_hal_disassoc
 *
 * wifi_hal_disassoc(vap_index, status, mac).  Inputs crossed: vap_index of the existing interfaces 0 / 1 / 5 / 14 and of NO interface (7, 2, 15, 100, -1, INT_MIN); status 0 / 1 / 3 / 8 / 0xFFFF / 0x10000 /
 * -1 / INT_MAX; mac a normal station address / all 0xff / all zero; the interface's hostapd own address normal / all 0xff / all zero.  Expected (CORRECT behaviour): an unknown vap index -> nothing is done (no
 * driver call, no crash); otherwise exactly one driver call with the looked-up interface, the interface's own address, the SAME mac pointer and reason == (u16)status, with hapd_lock released again (it is free
 * while the driver runs); nothing else in the interface is read.  Rows with last = 1 break the original: they run LAST.
 */
#include "hwr_wdi.h"
#include <limits.h>

/* name, vap_index, status, mac_mode, own_kind, last */
hwr_wdi_case_t sg_wifi_hal_disassoc_suite[] = {
	{ "vap0_status1",            0, 1, 1, 0, 0 },
	{ "vap1_status3",            1, 3, 1, 0, 0 },
	{ "vap5_status0",            5, 0, 1, 0, 0 },
	{ "vap14_status8",           14, 8, 1, 0, 0 },
	{ "status_0xffff",           0, 0xFFFF, 1, 0, 0 },
	{ "status_0x10000_truncates",1, 0x10000, 1, 0, 0 },
	{ "status_minus1",           5, -1, 1, 0, 0 },
	{ "status_int_max",          14, INT_MAX, 1, 0, 0 },
	{ "mac_broadcast",           0, 3, 2, 0, 0 },
	{ "mac_all_zero",            1, 3, 3, 0, 0 },
	{ "own_addr_all_ff",         5, 8, 1, 1, 0 },
	{ "own_addr_all_zero",       14, 8, 1, 2, 0 },
	{ "own_addr_ff_mac_ff",      0, 1, 2, 1, 0 },
	{ "vap7_no_interface",       7, 3, 1, 0, 1 },
	{ "vap2_no_interface",       2, 1, 1, 0, 1 },
	{ "vap15_first_above_last",  15, 3, 1, 0, 1 },
	{ "vap100_no_interface",     100, 3, 1, 0, 1 },
	{ "vap_minus1",              -1, 3, 1, 0, 1 },
	{ "vap_int_min",             INT_MIN, 3, 1, 0, 1 },
	{ NULL }
};
