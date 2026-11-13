/* wf6ap_tget_params harness types (namespace wtp). Own header, kept out of common.h. */
#ifndef WF6AP_TGET_PARAMS_H
#define WF6AP_TGET_PARAMS_H
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include "common.h"

namespace wtp {
#define WTP_ROOT_LEFT 16
#define WTP_ROOT_SZ 200
using ccs::bus_error_t; using ccs::bus_error_success;
using ccs::bus_data_prop_t;
#undef MAX_MCS
#define MAX_MCS 3
#define EM_MIN_HE_MCS_LEN 4
#define MAP_AP_ROLE_MAX 2
typedef unsigned char mac_address_t[6];

/* verbatim from inc/em_base.h */
typedef struct { unsigned short tx_he_mcs; unsigned short rx_he_mcs; } __attribute__((__packed__)) em_ap_he_mcs_maps_t;
typedef struct {
    unsigned char  mcs_nss_num : 4;
    unsigned char  he_8080 : 1;
    unsigned char  he_160 : 1;
    unsigned char  agent_role : 2;
} __attribute__((__packed__)) em_wifi6_cap_role_head_tlv_t;
typedef struct {
    unsigned char  dl_ofdma : 1;
    unsigned char  ul_ofdma : 1;
    unsigned char  ul_mumimo : 1;
    unsigned char  beam_formee_sts_g80 : 1;
    unsigned char  beam_formee_sts_l80 : 1;
    unsigned char  mu_beam_former : 1;
    unsigned char  su_beam_formee : 1;
    unsigned char  su_beam_former : 1;
    unsigned char  max_ul_mumimo_rx : 4;
    unsigned char  max_dl_mumimo_tx : 4;
    unsigned char  max_dl_ofdma_tx;
    unsigned char  max_ul_ofdma_rx;
    unsigned char  anticipated_channel_usage : 1;
    unsigned char  spatial_reuse : 1;
    unsigned char  twt_resp : 1;
    unsigned char  twt_req : 1;
    unsigned char  mu_edca : 1;
    unsigned char  multi_bssid : 1;
    unsigned char  mu_rts : 1;
    unsigned char  rts : 1;
} __attribute__((__packed__)) em_wifi6_cap_role_tail_tlv_t;
typedef struct {
    em_wifi6_cap_role_head_tlv_t role_head;
    em_ap_he_mcs_maps_t sprt_tx_rx_mcs[MAX_MCS];
    em_wifi6_cap_role_tail_tlv_t role_tail;
} __attribute__((__packed__)) em_wifi6_role_wire_t;
typedef struct {
    unsigned char  num_role;
    em_wifi6_role_wire_t roles[MAP_AP_ROLE_MAX];
} __attribute__((__packed__)) em_radio_wifi6_cap_data_t;


typedef struct {
    em_radio_wifi6_cap_data_t wifi6_cap;
    unsigned char rest_of_struct[64];   /* fields that follow wifi6_cap in the real em_radio_cap_info_t (runner poisons it) */
} em_radio_cap_info_t;
class dm_radio_cap_t { public: em_radio_cap_info_t info; bool present; em_radio_cap_info_t *get_radio_cap_info() { return &info; } };
typedef struct { struct { unsigned char ruid[6]; } id; } em_radio_info_t;
class dm_easy_mesh_t {
public:
    dm_radio_cap_t cap;     /* the radio cap of the one radio (RUID 02:00:00:00:00:01) */
    dm_radio_cap_t *get_radio_cap(unsigned char *ruid)
    {   static const unsigned char r1[6] = {2, 0, 0, 0, 0, 1};
        return (cap.present && !memcmp(ruid, r1, 6)) ? &cap : NULL; }
};
extern dm_easy_mesh_t *g_dm;

typedef struct {
    const char *test_name;
    const char *root;
    int num_role;          /* wifi6_cap.num_role (only 2 roles are really stored) */
    int mcs_num;           /* role_head.mcs_nss_num (4 bit) of both roles */
    bool cap_present;      /* radio cap entry exists */
    bool other_radio;      /* ri is a radio (RUID ..:02) that has no cap entry */
    int expect_roles;      /* number of roles reported (count of "HE160=" lines), -1 = unchecked */
    const char *has;       /* substring of the recorded "name=value" lines that must appear */
    const char *not_has;   /* must NOT appear */
    bool crash;
} test_case_t;

extern test_case_t suite[];
extern char root_store[WTP_ROOT_LEFT + WTP_ROOT_SZ + 64];
extern char g_rec[];
extern int g_roles;
extern int g_rc;
void construct_input(const test_case_t *tc);
int invoke(const char *root, bool other_radio);
void teardown(void);
}
void run_all_tests_wf6ap_tget_params(void);
#endif
