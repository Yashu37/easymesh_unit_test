/* hwr_wdd.h - plumbing for the sg_wifi_hal_delHostapdDenyAclDevice harness (src/wifi_hal.c).
 * wifi_interface_info_t / g_wifi_hal / the hostapd structs are minimal STAND-INS with the members the function uses (interface->vap_info.vap_mode, interface->u.ap.hapd {iface, conf}, conf->deny_mac /
 * num_deny_mac, g_wifi_hal.hapd_lock); wifi_vap_info_t is the REAL type from wifi_hal.h.  get_interface_by_vap_index and the two hostapd calls are stubs over runner data: acl_del_mac keeps the
 * behaviour of hostapd's hostapd_ctrl_iface_acl_del_mac (an empty list returns 0 before the MAC is parsed, hwaddr_aton parse, -1 on a bad MAC, a listed MAC is removed); hostapd_set_acl reads
 * hapd->iface like the real one (hapd->iface->drv_max_acl_mac_addrs). */
#ifndef HWR_WDD_H
#define HWR_WDD_H
#include "hwr_defs.h"
#include <pthread.h>
#include <stdint.h>
#define HWR_WDD_MAXI 4
struct mac_acl_entry { unsigned char addr[6]; };
struct hostapd_iface { int drv_max_acl_mac_addrs; };
struct hostapd_bss_config { struct mac_acl_entry *deny_mac; int num_deny_mac; };
struct hostapd_data { struct hostapd_iface *iface; struct hostapd_bss_config *conf; };
typedef struct wifi_interface_info_t {
	wifi_vap_info_t vap_info;
	union {
		struct { struct hostapd_data hapd; } ap;
		struct { int state; } sta;
	} u;
} wifi_interface_info_t;
typedef struct { pthread_mutex_t hapd_lock; } hwr_wdd_hal_t;
typedef struct {
	hwr_wdd_hal_t hal;
	wifi_interface_info_t ifs[HWR_WDD_MAXI];
	struct hostapd_iface hiface;
	struct hostapd_bss_config hconf;
	int n_if, set_acl_calls, del_calls;
} hwr_wdd_world_t;
extern hwr_wdd_world_t hwr_wdd_world;
extern "C" int hwr_sg_wifi_hal_delHostapdDenyAclDevice(INT apIndex, CHAR *DeviceMacAddress);
typedef struct {
	const char *test_name;
	int apIndex;
	int no_iface;                  /* no interface has this vap index */
	int vap_mode_sta;              /* the interface is a STA VAP */
	int mac_null;
	int conf_null, iface_null;     /* hapd->conf / hapd->iface NULL */
	int mac_kind;                  /* 0 valid, not in the list, 1 valid upper case (not in the list), 2 in the list (the first entry), 3 too short, 4 bad hex digit, 5 empty, 6 no colons, 7 valid + " VLAN_ID=5", 8 valid, trailing garbage, 9 in the list (the second entry), 10 in the list (the third entry) */
	int pre_n;                     /* MACs already in the deny list */
	int n_if, ap_pos;              /* interfaces in the world and the position of the addressed one */
	int last;                      /* 1: input that crashes the original, run LAST */
} hwr_wdd_case_t;
extern hwr_wdd_case_t sg_wifi_hal_delHostapdDenyAclDevice_suite[];
extern "C" void run_all_tests_sg_wifi_hal_delHostapdDenyAclDevice(void);
#endif
