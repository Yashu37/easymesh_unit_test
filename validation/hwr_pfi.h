/* hwr_pfi.h - plumbing for the platform_flags_init harness (platform/banana-pi) */
#ifndef HWR_PFI_H
#define HWR_PFI_H
#include "hwr_defs.h"
/* src/wifi_hal_priv.h:626-633 verbatim */
typedef enum {
    PLATFORM_FLAGS_SET_BSS                 = 0x1,
    PLATFORM_FLAGS_CONTROL_PORT_FRAME      = 0x1 << 1,
    PLATFORM_FLAGS_PROBE_RESP_OFFLOAD      = 0x1 << 2,
    PLATFORM_FLAGS_UPDATE_WIPHY_ON_PRIMARY = 0x1 << 3,
    PLATFORM_FLAGS_STA_INACTIVITY_TIMER    = 0x1 << 4,
} wifi_hal_platform_flags_t;
extern "C" int hwr_platform_flags_init(int *flags);
typedef struct {
	const char *test_name;
	unsigned int preset;           /* value of *flags before the call */
	int null_flags;
	int calls;
	int log_prefill;
	int expected_ret;
	int forked;
} hwr_pfi_case_t;
extern hwr_pfi_case_t platform_flags_init_suite[];
extern "C" void run_all_tests_platform_flags_init(void);
#endif
