/* hwr_saf.h - plumbing for the wifi_sendActionFrame harness (platform/banana-pi -> wifi_sendActionFrameExt -> src/wifi_hal.c wifi_hal_send_mgmt_frame) */
#ifndef HWR_SAF_H
#define HWR_SAF_H
#include "hwr_defs.h"

#define SAF_FRAME_MAX 65700
/* reduced stand-ins for the hostap structures (src/common/ieee802_11_defs.h): the 24-byte header and the action category byte */
struct ieee80211_hdr { unsigned short frame_control, duration_id; unsigned char addr1[6], addr2[6], addr3[6]; unsigned short seq_ctrl; } __attribute__((packed));
typedef struct ieee80211_hdr saf_hdr_t;
typedef struct {
    unsigned short frame_control, duration;
    unsigned char da[6], sa[6], bssid[6];
    unsigned short seq_ctrl;
    union { struct { unsigned char category; unsigned char variable[1]; } __attribute__((packed)) action; } u;
} __attribute__((packed)) saf_mgmt_t;

typedef struct { unsigned int vap_index; unsigned char mac[6]; int index; } saf_interface_t;

typedef struct {
    saf_interface_t *iface;                     /* interface returned for iface->vap_index (NULL = none) */
    int              fail_alloc;                /* os_zalloc returns NULL */
    int              mlme_rc;                   /* what wifi_drv_send_mlme returns */
    /* recorded by the wifi_drv_send_mlme stub */
    int              mlme_calls, mlme_noack, mlme_no_encrypt, mlme_csa;
    unsigned int     mlme_freq, mlme_wait;
    size_t           mlme_len;
    unsigned char    mlme_cat;
    unsigned char    mlme_frame[SAF_FRAME_MAX];
} saf_world_t;
extern saf_world_t hwr_saf_world;

extern "C" int hwr_saf_wifi_hal_send_mgmt_frame(int apIndex, mac_address_t sta, const unsigned char *data, size_t data_len, unsigned int freq, unsigned int wait);
extern "C" INT hwr_saf_wifi_sendActionFrameExt(INT apIndex, mac_address_t MacAddr, UINT frequency, UINT wait, UCHAR *frame, UINT len);
extern "C" INT hwr_wifi_sendActionFrame(INT apIndex, mac_address_t MacAddr, UINT frequency, UCHAR *frame, UINT len);

/* name, ap_index, has_iface (0 none, 1 iface with vap_index == ap_index, 2 iface with another vap_index), frame_mode (0 NULL, 1 runner buffer),
 * len, mac_mode (0 NULL, 1 runner mac), freq, mlme_rc, fail_alloc, expected_ret, exp_calls, last (1: invalid-input rows, run last) */
typedef struct {
    const char *test_name;
    int ap_index, has_iface, frame_mode; unsigned int len; int mac_mode; unsigned int freq; int mlme_rc, fail_alloc;
    int expected_ret, exp_calls, last;
} hwr_saf_case_t;
extern hwr_saf_case_t wifi_sendActionFrame_suite[];
extern "C" void run_all_tests_wifi_sendActionFrame(void);
#endif
