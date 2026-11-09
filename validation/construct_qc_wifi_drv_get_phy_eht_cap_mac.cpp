/*
 * UNIT TEST (input constructor): construct_qc_wifi_drv_get_phy_eht_cap_mac
 *
 * wifi_drv_get_phy_eht_cap_mac(eht_capab, tb) (platform/qualcomm: platform_ext.c and platform_xer5.c hold identical code) should copy the little-endian EHT MAC
 * capability of the NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MAC attribute of tb into eht_capab->mac_cap.  The original does os_memcpy(eht_capab->mac_cap, ...) where
 * mac_cap is a u16, i.e. it uses the VALUE of mac_cap as the destination address: it only survives when the attribute is absent or empty.  The suite crosses:
 * attribute absent / present, payload 0 / 1 / 2 / 3 / 4 / 20 / 100 bytes, several 16-bit values, other attributes present in tb (must not be read), a stale
 * mac_cap (0xBEEF), eht_capab NULL, repeated calls.  Expected (correct) behaviour: payload >= 2 -> mac_cap = little-endian first 2 bytes; payload 1 -> only the low
 * byte of mac_cap is replaced; payload 0 or no attribute -> mac_cap unchanged; the rest of the struct is never touched.  The attribute is an exact-size heap
 * block, so reading more than the clamped 2 payload bytes aborts under ASan.  Malformed header lengths are left out: the caller (src/wifi_hal_nl80211.c) parses
 * tb with nla_parse_nested, which rejects them.  Rows with last = 1 (attribute with data, or NULL tb / eht_capab) crash the original: they run LAST.
 * Row: name, attr, payload_len, b0, b1, others, tb_mode, eht_mode, calls, last.
 */
#include "hwr_qem.h"

hwr_qem_case_t qc_wifi_drv_get_phy_eht_cap_mac_suite[] = {
	/* ---- rows the original survives: nothing is copied ---- */
	{ "no_attr",                          0, 0,   0,    0,    0, 1, 1, 1, 0 },
	{ "no_attr_other_attrs_present",      0, 0,   0,    0,    1, 1, 1, 1, 0 },
	{ "attr_len0",                        1, 0,   0,    0,    0, 1, 1, 1, 0 },
	{ "attr_len0_other_attrs_present",    1, 0,   0,    0,    1, 1, 1, 1, 0 },
	{ "two_calls_no_attr",                0, 0,   0,    0,    0, 1, 1, 2, 0 },
	{ "ten_calls_attr_len0",              1, 0,   0,    0,    0, 1, 1, 10, 0 },
	{ "eht_null_no_attr",                 0, 0,   0,    0,    0, 1, 0, 1, 0 },
	/* ---- attribute with data: the original writes to the address held in mac_cap (run last) ---- */
	{ "attr_len1",                        1, 1,   0xFF, 0,    0, 1, 1, 1, 1 },
	{ "attr_len2_0x0000",                 1, 2,   0x00, 0x00, 0, 1, 1, 1, 1 },
	{ "attr_len2_0x1234_little_endian",   1, 2,   0x34, 0x12, 0, 1, 1, 1, 1 },
	{ "attr_len2_0xffff",                 1, 2,   0xFF, 0xFF, 0, 1, 1, 1, 1 },
	{ "attr_len2_0x00ff",                 1, 2,   0xFF, 0x00, 0, 1, 1, 1, 1 },
	{ "attr_len2_0xff00",                 1, 2,   0x00, 0xFF, 0, 1, 1, 1, 1 },
	{ "attr_len2_0x8000",                 1, 2,   0x00, 0x80, 0, 1, 1, 1, 1 },
	{ "attr_len3",                        1, 3,   0x0B, 0x0A, 0, 1, 1, 1, 1 },
	{ "attr_len4",                        1, 4,   0x0D, 0x0C, 0, 1, 1, 1, 1 },
	{ "attr_len20",                       1, 20,  0x21, 0x43, 0, 1, 1, 1, 1 },
	{ "attr_len100",                      1, 100, 0x65, 0x87, 0, 1, 1, 1, 1 },
	{ "attr_len2_other_attrs_present",    1, 2,   0x78, 0x56, 1, 1, 1, 1, 1 },
	{ "attr_len1_other_attrs_present",    1, 1,   0x78, 0x56, 1, 1, 1, 1, 1 },
	{ "two_calls_len2",                   1, 2,   0x34, 0x12, 0, 1, 1, 2, 1 },
	{ "ten_calls_len2",                   1, 2,   0xCD, 0xAB, 0, 1, 1, 10, 1 },
	{ "eht_null_attr_len0",               1, 0,   0,    0,    0, 1, 0, 1, 1 },   /* the argument eht_capab->mac_cap is read even for a 0-byte copy */
	{ "eht_null_attr_len2",               1, 2,   0x34, 0x12, 0, 1, 0, 1, 1 },
	{ "eht_null_attr_len20",              1, 20,  0x21, 0x43, 0, 1, 0, 1, 1 },
	/* ---- NULL tb (the original dereferences it) ---- */
	{ "invalid_tb_null",                  0, 0,   0,    0,    0, 0, 1, 1, 1 },
	{ "invalid_tb_null_eht_null",         0, 0,   0,    0,    0, 0, 0, 1, 1 },
	{ NULL, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
};
