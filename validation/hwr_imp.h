/* hwr_imp.h - plumbing for the intel wifi_setApManagementFramePowerControl harness (platform/intel) */
#ifndef HWR_IMP_H
#define HWR_IMP_H
#include "hwr_defs.h"
#define IMP_OUI_LTQ        0xAC9A96u    /* the harness's own values: the vendor header (OUI_LTQ, LTQ_NL80211_VENDOR_SUBCMD_*) is not in the source tree */
#define IMP_SUBCMD_PWR     0x44u
typedef struct { unsigned vap_index; unsigned pad[7]; } imp_iface_t;   /* opaque for the function: it only passes the pointer on */
extern "C" INT hwr_int_wifi_setApManagementFramePowerControl(INT apIndex, INT dBm);
typedef struct {
	int calls;
	imp_iface_t *iface; unsigned iface_vap;     /* the interface the lookup finds, and the VAP index it answers to (copy kept outside the poisoned object) */
	void *last_priv; unsigned last_oui, last_subcmd; unsigned char last_data[16]; unsigned long last_len; int last_nested; void *last_extra;
	int ret;                       /* what the stub wifi_drv_vendor_cmd returns */
} hwr_imp_world_t;
extern hwr_imp_world_t hwr_imp_world;
typedef struct {
	const char *test_name;
	int ap_index;
	int has_iface;                 /* 0 no interface, 1 interface found for ap_index, 2 only an interface with another VAP index */
	int dbm;
	int vendor_ret;                /* result of the vendor command */
	int calls;
	int prefill;                   /* bytes of the log slot already used before the call */
} hwr_imp_case_t;
extern hwr_imp_case_t int_wifi_setApManagementFramePowerControl_suite[];
extern "C" void run_all_tests_int_wifi_setApManagementFramePowerControl(void);
#endif
