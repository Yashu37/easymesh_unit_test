/* hwr_gem.h - plumbing for the wifi_drv_get_phy_eht_cap_mac harness (platform/banana-pi) */
#ifndef HWR_GEM_H
#define HWR_GEM_H
#include <netlink/netlink.h>
#include <netlink/attr.h>
#include <linux/nl80211.h>
#include "hwr_defs.h"

/* struct eht_capabilities, copied from hostap-2.10 src/drivers/driver.h:203-210 (lengths from ieee802_11_defs.h) */
#define EHT_PHY_CAPAB_LEN 9
#define EHT_MCS_NSS_CAPAB_LEN 9
#define EHT_PPE_THRESH_CAPAB_LEN 62
struct eht_capabilities {
	bool eht_supported;
	unsigned short mac_cap;
	unsigned char phy_cap[EHT_PHY_CAPAB_LEN];
	unsigned char mcs[EHT_MCS_NSS_CAPAB_LEN];
	unsigned char ppet[EHT_PPE_THRESH_CAPAB_LEN];
};
extern "C" void hwr_wifi_drv_get_phy_eht_cap_mac(struct eht_capabilities *eht_capab, struct nlattr **tb);

typedef struct {
	const char *test_name;
	int attr;                      /* 0 no EHT_CAP_MAC attribute in tb, 1 present */
	int payload_len;               /* payload bytes of the attribute (nla_len() = this) */
	unsigned char b0, b1;          /* first two payload bytes (the rest is 0xCC) */
	int raw_nla_len;               /* -1: header nla_len = 4 + payload_len; otherwise this value is written into the header (malformed attribute, 4-byte block) */
	int others;                    /* 1: tb also holds HE_CAP_MAC and EHT_CAP_PHY attributes (the function must not read them) */
	int tb_mode;                   /* 0 tb is NULL, 1 tb is the runner's array */
	int eht_mode;                  /* 0 eht_capab is NULL, 1 eht_capab is the runner's struct */
	int calls;
	int last;                      /* 1: invalid-input row (crashes the original): runs LAST */
} hwr_gem_case_t;
extern hwr_gem_case_t wifi_drv_get_phy_eht_cap_mac_suite[];
extern "C" void run_all_tests_wifi_drv_get_phy_eht_cap_mac(void);
#endif
