/*
 * UNIT TEST (input constructor): construct_bcm_wifi_setApManagementFramePowerControl
 *
 * wifi_setApManagementFramePowerControl(apIndex, dBm) (platform/broadcom) looks up the VAP interface, builds a vendor SET_MGT_FRAME_PWR command in
 * set_ap_pwr (vendor-data nest holding a 4-byte RDK_VENDOR_ATTR_MGT_FRAME_PWR_LEVEL with the power) and sends it.  The "driver" stub parses the real libnl
 * request and the runner checks interface / wiphy, vendor id, sub-command, nest, attribute length 4 and the power on the wire.  The suite crosses: powers
 * 0 / 1 / -1 / 10 / 20 / 23 / 30 / 127 / -127 / 128 / 255 / -128 / INT_MIN / INT_MAX, apIndex 0 / 15 / INT_MAX, interface found / missing / other vap,
 * command message NULL, a failing send (-EPERM, -EINVAL, -EIO, -ENOMEM, a positive value), the request too small for the nest / the power attribute (libnl
 * default message size 51 / 52 / 55 / 56 / 63 bytes: the real error paths that free the message) and exactly big enough (64), two calls.
 * Result expected: RETURN_OK exactly when the command was sent and the driver reported 0, RETURN_ERR otherwise; no command is sent when the lookup or
 * the message creation fails; the power on the wire is the argument.
 * Row layout: see bsp_case_t in hwr_bsp.h.
 */
#include <limits.h>
#include "hwr_bsp.h"

#define OK   RETURN_OK
#define ERR  RETURN_ERR
/* default row: ap 0, interface found, no failures, normal message size, one call, command sent and accepted */
#define R(name, dbm) { name, 0, 1, dbm, 0, 0, 0, 1, OK, 1 }

bsp_case_t bcm_wifi_setApManagementFramePowerControl_suite[] = {
	/* ---- power values ---- */
	R("dbm_0",            0),
	R("dbm_1",            1),
	R("dbm_minus_1",     -1),
	R("dbm_10",          10),
	R("dbm_20",          20),
	R("dbm_23",          23),
	R("dbm_30",          30),
	R("dbm_127",        127),
	R("dbm_minus_127", -127),
	R("dbm_128",        128),
	R("dbm_255",        255),
	R("dbm_minus_128", -128),
	R("dbm_int_min",  INT_MIN),
	R("dbm_int_max",  INT_MAX),
	/* ---- apIndex / interface ---- */
	{ "ap_index_15",          15, 1, 20, 0, 0, 0, 1, OK, 1 },
	{ "ap_index_int_max", INT_MAX, 1, 20, 0, 0, 0, 1, OK, 1 },
	{ "iface_missing",         0, 0, 20, 0, 0, 0, 1, ERR, 0 },
	{ "iface_other_vap_index", 0, 2, 20, 0, 0, 0, 1, ERR, 0 },
	{ "two_calls",             0, 1, 17, 0, 0, 0, 2, OK, 1 },
	/* ---- command / send failures ---- */
	{ "command_message_null",  0, 1, 20, 1, 0, 0, 1, ERR, 0 },
	{ "send_fails_eperm",      0, 1, 20, 0, -1, 0, 1, ERR, 1 },
	{ "send_fails_einval",     0, 1, 20, 0, -22, 0, 1, ERR, 1 },
	{ "send_fails_eio",        0, 1, 20, 0, -5, 0, 1, ERR, 1 },
	{ "send_fails_enomem",     0, 1, 20, 0, -12, 0, 1, ERR, 1 },
	{ "send_returns_positive", 0, 1, 20, 0, 1, 0, 1, ERR, 1 },
	/* ---- request too small (libnl default message size): the real error paths ---- */
	{ "room_51_no_vendor_subcmd",     0, 1, 20, 0, 0, 51, 1, ERR, 0 },
	{ "room_52_no_room_for_nest",     0, 1, 20, 0, 0, 52, 1, ERR, 0 },
	{ "room_55_no_room_for_nest",     0, 1, 20, 0, 0, 55, 1, ERR, 0 },
	{ "room_56_no_room_for_power",    0, 1, 20, 0, 0, 56, 1, ERR, 0 },
	{ "room_63_no_room_for_power",    0, 1, 20, 0, 0, 63, 1, ERR, 0 },
	{ "room_64_exact_fit",            0, 1, 20, 0, 0, 64, 1, OK, 1 },
	{ NULL }
};
