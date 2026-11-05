/* hwr_gai.h - types / plumbing for the wifi_hal_getAssociationReqIEs harness */
#ifndef HWR_GAI_H
#define HWR_GAI_H
#include "hwr_defs.h"
#include <pthread.h>
#include <stdint.h>
#include <stddef.h>
typedef unsigned char u8;
struct hwr_gai_sta_info { u8 *assoc_req; size_t assoc_req_len; };          /* the two fields the function reads */
struct hwr_gai_conf { int n; unsigned char mac[4][6]; hwr_gai_sta_info *sta[4]; };   /* stands for hapd->sta_hash */
struct hwr_gai_hostapd { hwr_gai_conf *conf; };
typedef struct { hwr_gai_hostapd hapd; char pad[256]; } hwr_gai_ap_t;               /* wifi_ap_priv_t: hapd first */
typedef struct { char junk[sizeof(hwr_gai_ap_t)]; } hwr_gai_sta_t;                  /* wifi_sta_priv_t: other state in the same bytes */
typedef struct { int vap_index; wifi_vap_info_t vap_info; union { hwr_gai_ap_t ap; hwr_gai_sta_t sta; } u; } hwr_gai_if_t;
#define wifi_interface_info_t hwr_gai_if_t
typedef struct { pthread_mutex_t hapd_lock; } hwr_gai_world_t;
extern hwr_gai_world_t hwr_gai_world;
extern "C" hwr_gai_if_t *hwr_gai_get_interface(unsigned int vap_index);
extern "C" hwr_gai_sta_info *hwr_gai_ap_get_sta(hwr_gai_hostapd *hapd, const u8 *addr);
extern "C" INT hwr_wifi_hal_getAssociationReqIEs(UINT apIndex, const mac_address_t *clientMacAddress, CHAR *req_ies, UINT req_ies_size, UINT *req_ies_len);   /* renamed, see the handler file */

typedef struct {
	const char *test_name;
	unsigned ap; unsigned char mac[6];
	unsigned null_mask;            /* 1 clientMacAddress, 2 req_ies, 4 req_ies_len passed as NULL */
	int sta_mode;                  /* the interface is a STA VAP */
	int client;                    /* 0 no client registered, 1 the queried client, 2 only another client */
	unsigned assoc_len;            /* length of the client's association request IEs */
	unsigned req_size;             /* req_ies_size passed in */
	int other_present;             /* a second client with other IEs is registered as well */
	int calls; int check_log;      /* check_log 1: Enter, 2: too small message */
	int expected_ret;
	int forked;
} hwr_gai_case_t;
extern hwr_gai_case_t wifi_hal_getAssociationReqIEs_suite[];
extern "C" void run_all_tests_wifi_hal_getAssociationReqIEs(void);
typedef struct { int calls; hwr_gai_hostapd *hapd; unsigned char addr[6]; } hwr_gai_rec_t;
extern hwr_gai_rec_t hwr_gai_rec;
void hwr_gai_configure(hwr_gai_if_t *iface);
#endif
