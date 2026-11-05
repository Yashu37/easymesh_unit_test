/* hwr_pcv.h - plumbing for the platform_create_vap harness (platform/banana-pi).
 * wifi_interface_info_t / hostapd_data / hostapd_mld are minimal STAND-INS with the members the function uses
 * (interface->vap_info, interface->u.ap.conf.disable_11be, interface->u.ap.hapd, hapd->mld->links, link->mld_link_id);
 * the vap info / map types are the REAL ones from wifi_hal.h. */
#ifndef HWR_PCV_H
#define HWR_PCV_H
#include "hwr_defs.h"
#include <stddef.h>
#include <stdbool.h>

/* list.h (hostapd src/utils/list.h:15 / 67 / 78) verbatim */
struct dl_list {
	struct dl_list *next;
	struct dl_list *prev;
};
#define dl_list_entry(item, type, member) \
	((type *) ((char *) item - offsetof(type, member)))
#define dl_list_for_each(item, list, type, member) \
	for (item = dl_list_entry((list)->next, type, member); \
	     &item->member != (list); \
	     item = dl_list_entry(item->member.next, type, member))

struct hostapd_mld { struct dl_list links; };
struct hostapd_data { struct hostapd_mld *mld; struct dl_list link; int mld_link_id; };
typedef struct wifi_interface_info_t {
	char name[16];
	wifi_vap_info_t vap_info;
	struct { struct { struct { int disable_11be; } conf; struct hostapd_data hapd; } ap; } u;
} wifi_interface_info_t;

extern "C" int hwr_platform_create_vap(wifi_radio_index_t index, wifi_vap_info_map_t *map);

#define HWR_MAX_IF   16
#define HWR_MAX_LINK 4
typedef struct {
	int mode;                      /* vap_array[i].vap_mode: 0 ap, 1 sta, 2 monitor */
	int vap_index;
	int has_if;                    /* an interface with this vap_index exists */
	int if_mode;                   /* interface->vap_info.vap_mode (0 ap, 1 sta, 2 monitor) */
	int enabled;                   /* interface->vap_info.u.bss_info.enabled */
	int dis11be;                   /* interface->u.ap.conf.disable_11be */
	int mld_en;                    /* interface->vap_info.u.bss_info.mld_info.common_info.mld_enable */
	int nlinks;                    /* links in hapd->mld->links */
	int mld_null;                  /* hapd.mld == NULL although mld_en */
} hwr_pcv_vap_t;
typedef struct {
	const char *test_name;
	int map_null;
	unsigned num_vaps;             /* value of map->num_vaps */
	int nvap;                      /* entries filled in vap_array (<= 8) */
	hwr_pcv_vap_t v[8];
	int fail_at;                   /* 1-based number of the set_beacon call that fails, 0 = none */
	int expected_ret;
	const char *expected_calls;    /* the link ids ("vap_index*10+link") ieee802_11_set_beacon was called with, space separated */
	int expected_errs;             /* error lines in the log */
	int forked;
} hwr_pcv_case_t;
extern hwr_pcv_case_t platform_create_vap_suite[];

/* collaborator stubs, state kept by the construct file */
extern wifi_interface_info_t hwr_pcv_if[HWR_MAX_IF];
extern int hwr_pcv_if_used[HWR_MAX_IF];
extern struct hostapd_mld hwr_pcv_mld[HWR_MAX_IF];
extern struct hostapd_data hwr_pcv_link[HWR_MAX_IF][HWR_MAX_LINK];
extern int hwr_pcv_beacon_calls, hwr_pcv_fail_at, hwr_pcv_called[32];
extern "C" wifi_interface_info_t *hwr_pcv_get_interface_by_vap_index(unsigned int vap_index);
extern "C" int hwr_pcv_set_beacon(struct hostapd_data *hapd);
extern "C" char *hwr_pcv_get_interface_name(wifi_interface_info_t *interface);
extern "C" void run_all_tests_platform_create_vap(void);
#endif
