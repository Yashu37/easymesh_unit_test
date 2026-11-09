/*
 * UNIT TEST (input constructor): construct_wifi_drv_get_phy_eht_cap_mac
 *
 * wifi_drv_get_phy_eht_cap_mac(eht_capab, tb) (platform/banana-pi) copies the 2-byte little-endian EHT MAC capability from the
 * NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MAC attribute of the parsed band-iftype attribute table tb into eht_capab->mac_cap, only when the attribute exists
 * and carries at least 2 bytes.  The caller (src/wifi_hal_nl80211.c:5073) parses tb with nla_parse_nested, so malformed attribute lengths are
 * normally rejected by libnl, and it always passes a non-NULL eht_capab and tb.  The suite crosses: attribute absent / present, payload 0 / 1 / 2 / 3 / 4 /
 * 20 / 100 bytes, several 16-bit values (little-endian check), malformed header lengths 0 / 2 / 3 (a 4-byte block whose nla_len() is negative: must be
 * ignored), other attributes present in tb (must not be read), a stale mac_cap that must stay when the attribute is ignored, repeated calls.  The attribute
 * is an exact-size heap block, so reading more than 2 payload bytes aborts under ASan.  Rows named invalid_* pass NULL eht_capab with a usable attribute
 * or a NULL tb: the original dereferences them (expected safe behaviour: return without writing); they run LAST.
 * Row: name, attr, payload_len, b0, b1, raw_nla_len, others, tb_mode, eht_mode, calls, last.
 */
#include "hwr_gem.h"

#define HDR (-1)

hwr_gem_case_t wifi_drv_get_phy_eht_cap_mac_suite[] = {
	{ "no_attr",                       0, 0, 0,    0,    HDR, 0, 1, 1, 1, 0 },
	{ "no_attr_other_attrs_present",   0, 0, 0,    0,    HDR, 1, 1, 1, 1, 0 },
	{ "attr_len0",                     1, 0, 0,    0,    HDR, 0, 1, 1, 1, 0 },
	{ "attr_len1",                     1, 1, 0xFF, 0,    HDR, 0, 1, 1, 1, 0 },
	{ "attr_len2_0x0000",              1, 2, 0x00, 0x00, HDR, 0, 1, 1, 1, 0 },
	{ "attr_len2_0x1234_little_endian",1, 2, 0x34, 0x12, HDR, 0, 1, 1, 1, 0 },
	{ "attr_len2_0xffff",              1, 2, 0xFF, 0xFF, HDR, 0, 1, 1, 1, 0 },
	{ "attr_len2_0x00ff",              1, 2, 0xFF, 0x00, HDR, 0, 1, 1, 1, 0 },
	{ "attr_len2_0xff00",              1, 2, 0x00, 0xFF, HDR, 0, 1, 1, 1, 0 },
	{ "attr_len2_0x0001",              1, 2, 0x01, 0x00, HDR, 0, 1, 1, 1, 0 },
	{ "attr_len2_0x8000",              1, 2, 0x00, 0x80, HDR, 0, 1, 1, 1, 0 },
	{ "attr_len3",                     1, 3, 0x0B, 0x0A, HDR, 0, 1, 1, 1, 0 },
	{ "attr_len4",                     1, 4, 0x0D, 0x0C, HDR, 0, 1, 1, 1, 0 },
	{ "attr_len20",                    1, 20, 0x21, 0x43, HDR, 0, 1, 1, 1, 0 },
	{ "attr_len100",                   1, 100, 0x65, 0x87, HDR, 0, 1, 1, 1, 0 },
	{ "attr_len2_other_attrs_present", 1, 2, 0x78, 0x56, HDR, 1, 1, 1, 1, 0 },
	{ "attr_len1_other_attrs_present", 1, 1, 0x78, 0x56, HDR, 1, 1, 1, 1, 0 },
	{ "malformed_nla_len_0",           1, 0, 0,    0,    0,   0, 1, 1, 1, 0 },
	{ "malformed_nla_len_2",           1, 0, 0,    0,    2,   0, 1, 1, 1, 0 },
	{ "malformed_nla_len_3",           1, 0, 0,    0,    3,   0, 1, 1, 1, 0 },
	{ "two_calls_len2",                1, 2, 0x34, 0x12, HDR, 0, 1, 1, 2, 0 },
	{ "ten_calls_len2",                1, 2, 0xCD, 0xAB, HDR, 0, 1, 1, 10, 0 },
	{ "two_calls_no_attr",             0, 0, 0,    0,    HDR, 0, 1, 1, 2, 0 },
	{ "eht_null_no_attr",              0, 0, 0,    0,    HDR, 0, 1, 0, 1, 0 },
	{ "eht_null_attr_len1",            1, 1, 0xFF, 0,    HDR, 0, 1, 0, 1, 0 },
	{ "eht_null_attr_len0",            1, 0, 0,    0,    HDR, 0, 1, 0, 1, 0 },
	{ "eht_null_malformed_nla_len_3",  1, 0, 0,    0,    3,   0, 1, 0, 1, 0 },
	/* ---- invalid inputs that crash the original (run last) ---- */
	{ "invalid_eht_null_attr_len2",    1, 2, 0x34, 0x12, HDR, 0, 1, 0, 1, 1 },
	{ "invalid_eht_null_attr_len20",   1, 20, 0x21, 0x43, HDR, 0, 1, 0, 1, 1 },
	{ "invalid_tb_null",               0, 0, 0,    0,    HDR, 0, 0, 1, 1, 1 },
	{ "invalid_tb_null_eht_null",      0, 0, 0,    0,    HDR, 0, 0, 0, 1, 1 },
	{ NULL, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
};
