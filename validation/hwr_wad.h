/* hwr_wad.h - plumbing for the sg_wifi_hal_addHostapdDenyAclDevice harness (src/wifi_hal.c).
 * wifi_interface_info_t / g_wifi_hal / the hostapd structs are minimal STAND-INS with the members the function uses (interface->vap_info.vap_mode, interface->u.ap.hapd {iface, conf}, conf->deny_mac /
 * num_deny_mac, g_wifi_hal.hapd_lock); wifi_vap_info_t is the REAL type from wifi_hal.h.  get_interface_by_vap_index and the three hostapd calls are stubs over runner data: acl_add_mac keeps the
 * behaviour of hostapd's hostapd_ctrl_iface_acl_add_mac (hwaddr_aton parse, already-listed MAC not added twice, list grown by one entry, -1 on a bad MAC / allocation failure); hostapd_set_acl reads
 * hapd->iface like the real one (hapd->iface->drv_max_acl_mac_addrs). */
#ifndef HWR_WAD_H
#define HWR_WAD_H
#include "hwr_defs.h"
#include <pthread.h>
#include <stdint.h>
#define HWR_WAD_MAXI 4
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
typedef struct { pthread_mutex_t hapd_lock; } hwr_wad_hal_t;
typedef struct {
	hwr_wad_hal_t hal;
	wifi_interface_info_t ifs[HWR_WAD_MAXI];
	struct hostapd_iface hiface;
	struct hostapd_bss_config hconf;
	int n_if, alloc_fail, set_acl_calls, disassoc_calls, add_calls;
} hwr_wad_world_t;
extern hwr_wad_world_t hwr_wad_world;
extern "C" int hwr_sg_wifi_hal_addHostapdDenyAclDevice(INT apIndex, CHAR *DeviceMacAddress);
typedef struct {
	const char *test_name;
	int apIndex;
	int no_iface;                  /* no interface has this vap index */
	int vap_mode_sta;              /* the interface is a STA VAP */
	int mac_null;
	int conf_null, iface_null;     /* hapd->conf / hapd->iface NULL */
	int mac_kind;                  /* 0 valid, 1 valid upper case, 2 already in the list, 3 too short, 4 bad hex digit, 5 empty, 6 no colons, 7 valid + " VLAN_ID=5", 8 valid, trailing garbage */
	int pre_n;                     /* MACs already in the deny list */
	int alloc_fail;                /* growing the list fails */
	int n_if, ap_pos;              /* interfaces in the world and the position of the addressed one */
	int last;                      /* 1: input that crashes the original, run LAST */
} hwr_wad_case_t;
extern hwr_wad_case_t sg_wifi_hal_addHostapdDenyAclDevice_suite[];
extern "C" void run_all_tests_sg_wifi_hal_addHostapdDenyAclDevice(void);
#endif
