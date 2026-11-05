/* hwr_psd.h - plumbing for the platform_get_ssid_default harness (platform/banana-pi) */
#ifndef HWR_PSD_H
#define HWR_PSD_H
#include "hwr_defs.h"
#include <stdio.h>
extern char hwr_psd_path[256];                                    /* temporary copy of /nvram/serial_number.txt, set by the runner */
extern "C" int hwr_platform_get_ssid_default(char *ssid, int vap_index);
extern "C" BOOL hwr_psd_is_mesh_sta(UINT ap_index);
extern "C" int hwr_psd_json(char *out);
extern "C" FILE *hwr_psd_fopen(const char *path, const char *mode);
typedef struct {
	int mesh_sta_index;            /* vap_index for which is_wifi_hal_vap_mesh_sta() is true, -2 = none */
	int json_ret; const char *json_val;
	int json_calls;
} hwr_psd_rec_t;
extern hwr_psd_rec_t hwr_psd_rec;
typedef struct {
	const char *test_name;
	int vap_index;
	int mesh_sta_index;
	int json_ret; const char *json_val;
	const char *file;              /* content of /nvram/serial_number.txt, NULL = file missing */
	unsigned file_len;             /* 0 = strlen(file) (needed for embedded NUL) */
	int null_ssid;
	int expected_ret;
	const char *expected_ssid;     /* NULL = ssid untouched */
	int expected_json_calls;
	int forked;
} hwr_psd_case_t;
extern hwr_psd_case_t platform_get_ssid_default_suite[];
extern "C" void run_all_tests_platform_get_ssid_default(void);
#endif
