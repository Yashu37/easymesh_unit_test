/* hwr_wrt.h - plumbing for the sg_wifi_hal_getRadioTemperature harness (src/wifi_hal.c).
 * platform_get_radio_phytemperature_t is declared exactly like wifi_hal_priv.h:778; wifi_radioTemperature_t and wifi_radio_index_t are the REAL types from the HAL headers.  The getter
 * get_platform_get_radio_phytemperature_fn (wifi_hal_priv.h) is runner-controlled and can return NULL; the platform function is a stub that models the real ones: it returns a runner-chosen value and only
 * writes the temperature when asked and when the pointer is non-NULL (the banana-pi and emulator versions return 0 without touching it). */
#ifndef HWR_WRT_H
#define HWR_WRT_H
#include "hwr_defs.h"
#include <stdint.h>
typedef int (*platform_get_radio_phytemperature_t)(wifi_radio_index_t index, wifi_radioTemperature_t *radioPhyTemperature);
typedef struct {
	int no_fn, fn_ret, write_temp; unsigned temp_value;
	int getter_calls, calls; unsigned call_index; wifi_radioTemperature_t *call_out;
	void *unrelated[4];            /* poisoned: the function must not touch it */
} hwr_wrt_world_t;
extern hwr_wrt_world_t hwr_wrt_world;
extern "C" INT hwr_sg_wifi_hal_getRadioTemperature(wifi_radio_index_t radioIndex, wifi_radioTemperature_t *radioPhyTemperature);
typedef struct {
	const char *test_name;
	unsigned radio_index;
	int out_null;                  /* radioPhyTemperature is NULL */
	int no_fn;                     /* the getter returns NULL */
	int fn_ret;                    /* platform function return value */
	int write_temp; unsigned temp_value;   /* platform writes temp_value to the output when write_temp */
	int last;                      /* 1: input that crashes the original, run LAST */
} hwr_wrt_case_t;
extern hwr_wrt_case_t sg_wifi_hal_getRadioTemperature_suite[];
extern "C" void run_all_tests_sg_wifi_hal_getRadioTemperature(void);
#endif
