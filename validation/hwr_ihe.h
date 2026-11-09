/* hwr_ihe.h - plumbing for the intel wifi_drv_get_phy_eht_cap_mac harness (platform/intel) */
#ifndef HWR_IHE_H
#define HWR_IHE_H
#include "hwr_gem.h"     /* struct eht_capabilities (copied from hostap driver.h), libnl types */
extern "C" void hwr_int_wifi_drv_get_phy_eht_cap_mac(struct eht_capabilities *eht_capab, struct nlattr **tb);
typedef struct {
	const char *test_name;
	int eht_mode;                  /* 0 eht_capab NULL, 1 the runner's struct (fully POISONED during the call), 2 dangling pointer 0xdeadbeef */
	int tb_mode;                   /* 0 tb NULL, 1 the runner's pointer array (fully POISONED), 2 dangling pointer 0xdeadbeef */
	int calls;
	int prefill;                   /* bytes of the log slot already used before the call */
} hwr_ihe_case_t;
extern hwr_ihe_case_t int_wifi_drv_get_phy_eht_cap_mac_suite[];
extern "C" void run_all_tests_int_wifi_drv_get_phy_eht_cap_mac(void);
#endif
