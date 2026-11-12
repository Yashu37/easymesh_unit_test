/* wf6ap_get_inner harness types (namespace w6g). Kept out of common.h so `make` stays incremental. */
#ifndef WF6AP_GET_INNER_H
#define WF6AP_GET_INNER_H
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include "common.h"

namespace w6g {
#define W6G_LEFT 16          /* poisoned bytes in front of event_name */
#define W6G_NAME_SZ 300
#define W6G_PAD 64
#define W6G_MAXDM 4
#define W6G_GUARD 256        /* bytes before / after dm->m_radio[] (stand for the neighbouring members), poisoned by the runner */

using ccs::bus_error_t;
using ccs::bus_error_success; using ccs::bus_error_invalid_input;
using ccs::bus_data_type_string;
using ccs::raw_data_t; using ccs::bus_data_prop_t;

#define MAX_INSTANCE_LEN 32
#define DATAELEMS_NETWORK "Device.WiFi.DataElements.Network."
#undef MAX_MCS
#define MAX_MCS 3
#define EM_MIN_HE_MCS_LEN 4
#define MAP_AP_ROLE_MAX 2
#define EM_MAX_BANDS 3
typedef unsigned char mac_address_t[6];
typedef struct { int unused; } bus_user_data_t;

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
class dm_radio_cap_t { public: em_radio_cap_info_t info; em_radio_cap_info_t *get_radio_cap_info() { return &info; } };
typedef struct { struct { unsigned char ruid[6]; } id; } em_radio_info_t;
class dm_radio_t { public: em_radio_info_t info; em_radio_info_t *get_radio_info() { return &info; } };
class dm_easy_mesh_t {
public:
    unsigned char before[W6G_GUARD];    /* stands for the members in front of m_radio[] */
    dm_radio_t m_radio[EM_MAX_BANDS];
    unsigned char after[W6G_GUARD];     /* stands for the members after m_radio[] */
    int id;
    dm_radio_cap_t cap[EM_MAX_BANDS];
    bool has_cap[EM_MAX_BANDS];
    int get_id() const { return id; }
    dm_radio_cap_t *get_radio_cap(unsigned char *ruid)
    {   for (int i = 0; i < EM_MAX_BANDS; i++) if (has_cap[i] && !memcmp(m_radio[i].info.id.ruid, ruid, 6)) return &cap[i];
        return NULL; }
};
extern dm_easy_mesh_t *g_dm[W6G_MAXDM + 1];
extern int g_ndm;

typedef struct {
    int id;               /* dm->get_id() */
    int num_role;         /* rci->wifi6_cap.num_role for every radio cap (only 2 roles are really stored) */
    bool cap0, cap1, cap2;/* radio i has a radio cap entry */
} dm_spec_t;

typedef struct {
    const char *test_name;
    const char *event;     /* NULL passes a NULL event_name */
    bool no_pdata;
    dm_spec_t dms[W6G_MAXDM];
    int expect_rc;         /* 0 success, 2 invalid_input */
    const char *expect_val;/* recorded raw_data_set value ("1", "0", "12"...), NULL = nothing recorded expected / unchecked */
    bool check_val;
    bool crash;
} test_case_t;

extern test_case_t suite[];
extern char name_store[W6G_LEFT + W6G_NAME_SZ + W6G_PAD];
extern int g_rc;
extern int g_nset;
extern char g_val[64];
void construct_input(const test_case_t *tc);
int invoke(const char *event, bool no_pdata);
void teardown(void);
}
void run_all_tests_wf6ap_get_inner(void);
#endif
