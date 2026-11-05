/* hwr_ppv.h - plumbing for the platform_pre_create_vap harness (platform/banana-pi) */
#ifndef HWR_PPV_H
#define HWR_PPV_H
#include "hwr_defs.h"
/* minimal STAND-IN: the function only reads interface->vap_info.vap_mode (the MLO block is compiled out) */
typedef struct wifi_interface_info_t { wifi_vap_info_t vap_info; } wifi_interface_info_t;
extern "C" int hwr_platform_pre_create_vap(wifi_radio_index_t index, wifi_vap_info_map_t *map);
extern "C" int hwr_ppv_nvram(char *in, char *out);
extern "C" wifi_interface_info_t *hwr_ppv_get_if(unsigned int vap_index);
extern "C" BOOL hwr_ppv_is_lnf(UINT ap_index);
extern "C" BOOL hwr_ppv_is_hotspot(UINT ap_index);
#define HWR_PPV_LNF_IDX     4      /* vap_index the lnf_radius stub answers true for */
#define HWR_PPV_HOTSPOT_IDX 5      /* vap_index the hotspot_secure stub answers true for */
typedef struct {
	const char *ip_val; int ip_ret; const char *port_val; int port_ret; const char *key_val; int key_ret;
	int n_ip, n_port, n_key, n_other;
	int get_if_calls;
	int if_mode[16];               /* get_interface_by_vap_index: -1 = NULL, else the interface's vap_mode */
} hwr_ppv_state_t;
extern hwr_ppv_state_t hwr_ppv_st;
typedef struct {
	int mode, sec;
	unsigned int vap_index;
	const char *ip, *s_ip;         /* "0.0.0.0" = not configured */
	unsigned short port, s_port;
	const char *key, *s_key;
	int if_mode;
} hwr_ppv_vap_t;
typedef struct {
	const char *test_name;
	int null_map;
	unsigned int num_vaps;         /* vaps beyond v[] are plain AP / WPA2 personal and not described */
	hwr_ppv_vap_t v[3];
	const char *ip_val; int ip_ret;
	const char *port_val; int port_ret;
	const char *key_val; int key_ret;
	int expected_ret;
	int forked;
} hwr_ppv_case_t;
extern hwr_ppv_case_t platform_pre_create_vap_suite[];
extern "C" void run_all_tests_platform_pre_create_vap(void);
#endif
