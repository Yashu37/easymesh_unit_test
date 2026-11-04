/* hwr_gan.h - types / plumbing for the wifi_hal_getApName harness */
#ifndef HWR_GAN_H
#define HWR_GAN_H
#include "hwr_defs.h"
#define HWR_GAN_MAX_RADIOS 3
#define HWR_GAN_MAP_MAX    6
typedef struct { unsigned int rdk_radio_index; struct { UINT maxNumberVAPs; } capab; } hwr_gan_radio_t;
typedef struct { unsigned int num_radios; hwr_gan_radio_t *radio_info; } hwr_gan_world_t;
extern hwr_gan_world_t hwr_gan_world;
extern wifi_interface_name_idex_map_t hwr_gan_map[HWR_GAN_MAP_MAX];       /* REAL wifi_interface_name_idex_map_t */
extern unsigned int hwr_gan_map_size;
extern "C" INT hwr_wifi_hal_getApName(INT apIndex, CHAR *output_string);   /* renamed, see the handler file */

typedef struct { unsigned rdk_index; unsigned max_vaps; } hwr_gan_rd_t;
typedef struct { unsigned index; const char *name; } hwr_gan_en_t;
typedef struct {
	const char *test_name;
	int nradios; hwr_gan_rd_t r[HWR_GAN_MAX_RADIOS];
	int nmap; hwr_gan_en_t m[HWR_GAN_MAP_MAX];
	int query; int null_out; int calls; int check_log;
	int expected_ret; const char *expected_out; int forked;       /* expected_out: NULL = output must stay untouched */
} hwr_gan_case_t;
extern hwr_gan_case_t wifi_hal_getApName_suite[];
extern "C" void run_all_tests_wifi_hal_getApName(void);
#endif
