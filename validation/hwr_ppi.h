/* hwr_ppi.h - plumbing for the platform_pre_init harness (platform/banana-pi) */
#ifndef HWR_PPI_H
#define HWR_PPI_H
#include "hwr_defs.h"
extern "C" int hwr_platform_pre_init();
typedef struct {
	const char *test_name;
	int prefill;                   /* bytes of the log slot already used before the call */
	int calls;                     /* number of calls */
	int expected_ret;
	int expect_log;                /* 1: the log must hold one "platform_pre_init:<line> " line per call (when it fits) */
} hwr_ppi_case_t;
extern hwr_ppi_case_t platform_pre_init_suite[];
extern "C" void run_all_tests_platform_pre_init(void);
#endif
