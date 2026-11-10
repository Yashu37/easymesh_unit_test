/* hwr_wem.h - plumbing for the sg_wifi_hal_hostApGetErouter0Mac harness (src/wifi_hal.c) */
#ifndef HWR_WEM_H
#define HWR_WEM_H
#include "hwr_defs.h"
extern "C" int hwr_sg_wifi_hal_hostApGetErouter0Mac(char *out);
typedef struct {
	const char *test_name;
	int out_mode;                  /* 0 NULL; 1 heap buffer of exactly 18 bytes (redzones: a write past the MAC string and its NUL aborts under ASan); 2 slab of 64 bytes whose bytes after the first 18 are POISONED; 3 dangling 0xdeadbeef is NOT used (not checked by the function) */
	unsigned char fill;            /* byte the output buffer is preset to (0 = zeros, 'z' = a longer old string) */
	int calls;
	int prefill;                   /* bytes of the log slot already used before the call */
	int expected_ret;
} hwr_wem_case_t;
extern hwr_wem_case_t sg_wifi_hal_hostApGetErouter0Mac_suite[];
extern "C" void run_all_tests_sg_wifi_hal_hostApGetErouter0Mac(void);
#endif
