/* hwr_qem.h - plumbing for the qualcomm wifi_drv_get_phy_eht_cap_mac harness (platform/qualcomm) */
#ifndef HWR_QEM_H
#define HWR_QEM_H
#include "hwr_gem.h"     /* struct eht_capabilities (hostap driver.h: u16 mac_cap), libnl types */
extern "C" void hwr_qc_wifi_drv_get_phy_eht_cap_mac(struct eht_capabilities *eht_capab, struct nlattr **tb);
typedef struct {
	const char *test_name;
	int attr;                      /* 0 no EHT_CAP_MAC attribute in tb, 1 present */
	int payload_len;               /* payload bytes of the attribute (nla_len() = this) */
	unsigned char b0, b1;          /* first two payload bytes (the rest is 0xCC) */
	int others;                    /* 1: tb also holds HE_CAP_MAC and EHT_CAP_PHY attributes (the function must not read them) */
	int tb_mode;                   /* 0 tb is NULL, 1 tb is the runner's array */
	int eht_mode;                  /* 0 eht_capab is NULL, 1 eht_capab is the runner's struct */
	int calls;
	int last;                      /* 1: invalid-input / crash row, run LAST */
} hwr_qem_case_t;
extern hwr_qem_case_t qc_wifi_drv_get_phy_eht_cap_mac_suite[];
extern "C" void run_all_tests_qc_wifi_drv_get_phy_eht_cap_mac(void);
#endif
