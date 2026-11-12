/*
 * UNIT TEST (input constructor): construct_sg_wifi_hal_band_to_wps_band
 *
 * wifi_hal_band_to_wps_band(hal_band, wps_band) stores the WPS RF band for a HAL band through wps_band.  Inputs crossed: every defined band (2.4 / 5 / 5L / 5H / 6 / 60 GHz), values outside the enum (0, a
 * bit mask of two bands, 0x40, 0xFFFFFFFF, 0x80000000) and a NULL output pointer.
 * Expected (CORRECT behaviour): 2.4 GHz -> RETURN 0 and 0x01; 5 / 5L / 5H -> 0 and 0x02; 6 GHz -> 0 and 0 (WPS is not supported there); 60 GHz and every value that is not exactly one defined band -> -1 with
 * the output untouched; a NULL output pointer -> -1 and no write (for every band).  Rows with last = 1 break the original: they run LAST.
 */
#include "hwr_wbw.h"

/* name, band, out_null, want_ret, want_out, last */
hwr_wbw_case_t sg_wifi_hal_band_to_wps_band_suite[] = {
	{ "band_2_4",                        0x1,        0,  0, 0x01, 0 },
	{ "band_5",                          0x2,        0,  0, 0x02, 0 },
	{ "band_5L",                         0x4,        0,  0, 0x02, 0 },
	{ "band_5H",                         0x8,        0,  0, 0x02, 0 },
	{ "band_6_not_supported_gives_0",    0x10,       0,  0, 0x00, 0 },
	{ "band_60_unsupported",             0x20,       0, -1, 0,    0 },
	{ "band_0",                          0x0,        0, -1, 0,    0 },
	{ "band_mask_2_4_and_5",             0x3,        0, -1, 0,    0 },
	{ "band_0x40",                       0x40,       0, -1, 0,    0 },
	{ "band_0x80000000",                 0x80000000, 0, -1, 0,    0 },
	{ "band_0xFFFFFFFF",                 0xFFFFFFFF, 0, -1, 0,    0 },
	{ "null_out_unsupported_band_0",     0x0,        1, -1, 0,    0 },
	{ "null_out_unsupported_band_60",    0x20,       1, -1, 0,    0 },
	/* inputs that crash the original: run LAST */
	{ "null_out_band_2_4",               0x1,        1, -1, 0,    1 },
	{ "null_out_band_5",                 0x2,        1, -1, 0,    1 },
	{ "null_out_band_6",                 0x10,       1, -1, 0,    1 },
	{ NULL }
};
