/* radio_tget_params harness types (namespace rtp). Own header, kept out of common.h. */
#ifndef RADIO_TGET_PARAMS_H
#define RADIO_TGET_PARAMS_H
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include "common.h"

namespace rtp {
#define RTP_GUARD 256
#define RTP_ROOT_SZ 700
#define EM_MAX_BANDS 3
#define EM_MAX_OPCLASS 64
#define MAX_CAPS_STR_LEN 32
#define MAX_STDLEN 64
using ccs::bus_error_t; using ccs::bus_error_success;
using ccs::bus_data_prop_t;
typedef unsigned char mac_address_t[6];
typedef char em_long_string_t[128];
typedef unsigned int wifi_ieee80211Variant_t;
#define WIFI_80211_VARIANT_A  0x01
#define WIFI_80211_VARIANT_B  0x02
#define WIFI_80211_VARIANT_G  0x04
#define WIFI_80211_VARIANT_N  0x08
#define WIFI_80211_VARIANT_AC 0x10
#define WIFI_80211_VARIANT_AX 0x20
#define WIFI_80211_VARIANT_BE 0x40
#define WIFI_80211_VARIANT_BN 0x80
typedef enum { em_op_class_type_none = 0, em_op_class_type_current = 1, em_op_class_type_capability = 2 } em_op_class_type_t;
typedef struct { struct { unsigned char ruid[6]; em_op_class_type_t type; } id; int op_class; } em_op_class_info_t;
class dm_op_class_t { public: em_op_class_info_t info; em_op_class_info_t *get_op_class_info() { return &info; } };
typedef struct {
    struct { unsigned char ruid[6]; } id;
    bool enabled; unsigned int number_of_bss; int noise;
    unsigned char transmit, receive_self, receive_other; unsigned short utilization;
    em_long_string_t chip_vendor; unsigned char radio_temp;
} em_radio_info_t;
class dm_radio_t { public: em_radio_info_t info; em_radio_info_t *get_radio_info() { return &info; } };
typedef struct { unsigned char max_sprt_tx_streams, max_sprt_rx_streams; bool gi_sprt_20mhz, gi_sprt_40mhz, ht_sprt_40mhz; } em_ap_ht_cap_t;
typedef struct { unsigned short sprt_tx_mcs, sprt_rx_mcs; unsigned char max_sprt_tx_streams, max_sprt_rx_streams;
    bool gi_sprt_80mhz, gi_sprt_160mhz, sprt_80_80_mhz, sprt_160mhz, su_beamformer_cap, mu_beamformer_cap; } em_ap_vht_cap_t;
typedef struct { struct { unsigned char mac[6]; } ruid; wifi_ieee80211Variant_t mode; em_ap_ht_cap_t ht_cap; em_ap_vht_cap_t vht_cap; } em_radio_cap_info_t;
class dm_radio_cap_t { public: em_radio_cap_info_t m_radio_cap_info; em_radio_cap_info_t *get_radio_cap_info() { return &m_radio_cap_info; } };
typedef struct { mac_address_t id; } em_sta_info_t;
class dm_sta_t { public: em_sta_info_t info; em_sta_info_t *get_sta_info() { return &info; } };

class dm_easy_mesh_t {
public:
    unsigned int m_num_radios;
    dm_radio_t m_radio[EM_MAX_BANDS];
    dm_radio_cap_t m_radio_cap[EM_MAX_BANDS];
    unsigned char after_cap[RTP_GUARD];      /* members after m_radio_cap[] (runner poisons it) */
    unsigned int m_num_opclass;
    dm_op_class_t m_op_class[EM_MAX_OPCLASS];
    unsigned char after_oc[RTP_GUARD];       /* members after m_op_class[] (runner poisons it) */
    unsigned int get_num_radios() { return (m_num_radios > EM_MAX_BANDS) ? EM_MAX_BANDS : m_num_radios; }
    unsigned int get_num_op_class() { return m_num_opclass; }
    dm_op_class_t *get_op_class(unsigned int index) { return &m_op_class[index]; }
    dm_radio_t *get_radio(unsigned int index);
    dm_radio_cap_t *get_radio_cap(mac_address_t mac);
};
extern dm_easy_mesh_t *g_dm;

typedef struct {
    const char *test_name;
    const char *root;      /* path root; "" never NULL */
    int n_radios;          /* raw m_num_radios (get_num_radios clamps it to 3) */
    int n_oc;              /* raw m_num_opclass; -1 = number of entries actually filled */
    int cur[3];            /* current op classes filled per radio 1..3 */
    int cap[3];            /* capability op classes filled per radio 1..3 */
    unsigned char has_cap; /* bit i: a radio cap entry exists for radio i+1 */
    int nbss;              /* number_of_bss of every radio */
    bool bh;               /* a backhaul sta exists */
    unsigned int mode;     /* radio cap mode */
    int expect_ids;        /* number of "ID" properties, -1 = unchecked */
    const char *has;       /* "idx:name=value" line that must appear */
    const char *not_has;   /* must NOT appear */
    bool crash;
} test_case_t;

extern test_case_t suite[];
extern char g_rec[];
extern int g_ids;
extern int g_rc;
void construct_input(const test_case_t *tc);
int invoke(const char *root);
void teardown(void);
void set_bh(bool b);
}
void run_all_tests_radio_tget_params(void);
#endif
