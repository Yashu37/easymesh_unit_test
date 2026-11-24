/* dm_easy_mesh_t::print_config harness types (namespace pcf). Own header, kept out of common.h so `make` stays incremental. */
#ifndef PRINT_CONFIG_H
#define PRINT_CONFIG_H
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <string>
#include <vector>
#include "common.h"

namespace pcf {
#define PCF_GUARD 128
#define EM_MAX_NET_SSIDS 5
#define EM_MAX_BANDS 3
#define EM_MAX_BSSS (EM_MAX_BANDS*8)
#define EM_MAX_OPCLASS 64
#define EM_MAX_CHANNELS_IN_LIST 64
typedef unsigned char mac_address_t[6];
typedef char em_long_string_t[128]; typedef char ssid_t[32];
/* em_scan_cap_op_class_info_t / em_channel_scan_cap_radio_t exactly as in inc/em_base.h */
typedef struct { unsigned char channel[EM_MAX_CHANNELS_IN_LIST]; } __attribute__((__packed__)) em_per_op_class_channels_list_t;
typedef struct { unsigned char op_class; unsigned char num; em_per_op_class_channels_list_t channels; } __attribute__((__packed__)) em_scan_cap_op_class_info_t;
typedef struct {
    mac_address_t ruid; unsigned char reserved : 5; unsigned char scan_impact : 2; unsigned char boot_only : 1;
    unsigned int min_scan_interval; unsigned char op_classes_num; em_scan_cap_op_class_info_t op_classes[EM_MAX_OPCLASS];
} __attribute__((__packed__)) em_channel_scan_cap_radio_t;
/* em_radio_cap_info_t cut down to the members print_config reads; after_ch_scan stands for the members that follow ch_scan (poisoned by the runner) */
typedef struct { mac_address_t mac; } em_intf_t;
typedef struct { unsigned int tx_he_mcs, rx_he_mcs; } he_mcs_t;
typedef struct {
    em_intf_t ruid;
    struct { unsigned char num_role; struct { struct { unsigned char su_beam_former; } role_tail; } roles[4]; } wifi6_cap;
    struct { unsigned char sprt_mcs_len; he_mcs_t sprt_tx_rx_mcs[3]; unsigned char sprt_80_80_mhz, sprt_160mhz, max_sprt_rx_streams, max_sprt_tx_streams,
        dl_ofdma_cap, ul_ofdma_cap, dl_mimo_ofdma_cap, ul_mimo_ofdma_cap, ul_mimo_cap, mu_beamformer_cap, su_beamformer_cap; } he_cap;
    struct { unsigned short sprt_tx_mcs, sprt_rx_mcs; unsigned char gi_sprt_160mhz, gi_sprt_80mhz, max_sprt_rx_streams, max_sprt_tx_streams,
        mu_beamformer_cap, su_beamformer_cap, sprt_160mhz, sprt_80_80_mhz; } vht_cap;
    struct { unsigned char ht_sprt_40mhz, gi_sprt_40mhz, gi_sprt_20mhz, max_sprt_rx_streams, max_sprt_tx_streams; } ht_cap;
    em_channel_scan_cap_radio_t ch_scan;
    unsigned char after_ch_scan[PCF_GUARD];
} em_radio_cap_info_t;
typedef struct { em_intf_t intf; int band; int transmit_power_limit; } em_radio_info_t;
typedef struct { em_intf_t ruid; em_intf_t bssid; } em_bss_info_t;
class dm_radio_cap_t { public: em_radio_cap_info_t info; em_radio_cap_info_t *get_radio_cap_info() { return &info; } };
class dm_radio_t { public: em_radio_info_t info; em_radio_info_t *get_radio_info() { return &info; } };
class dm_bss_t { public: em_bss_info_t info; em_bss_info_t *get_bss_info() { return &info; } };
class dm_network_ssid_t { public: struct { ssid_t ssid; } m_network_ssid_info; };
class dm_network_t { public: struct { em_long_string_t id; } m_net_info; };

namespace util { std::string mac_to_string(unsigned char *mac); }
void em_printfout_fn(const char *fmt, ...);
#define em_printfout(...) pcf::em_printfout_fn(__VA_ARGS__)
extern std::vector<std::string> g_lines;

/* dm_easy_mesh_t cut down to the members print_config uses; the after_* guards stand for the members that follow the arrays in the real class */
class dm_easy_mesh_t {
public:
    dm_network_t m_network;
    unsigned int m_num_net_ssids; dm_network_ssid_t m_network_ssid[EM_MAX_NET_SSIDS]; unsigned char after_ssids[PCF_GUARD];
    unsigned int m_num_opclass;
    unsigned int m_num_bss; dm_bss_t m_bss[EM_MAX_BSSS]; unsigned char after_bss[PCF_GUARD];
    unsigned int m_num_radios; dm_radio_t m_radio[EM_MAX_BANDS]; unsigned char after_radio[PCF_GUARD];
    dm_radio_cap_t m_radio_cap[EM_MAX_BANDS];
    unsigned char *get_controller_interface_mac() { static unsigned char m[6]; return m; }
    unsigned char *get_ctrl_al_interface_mac() { static unsigned char m[6]; return m; }
    unsigned char *get_agent_al_interface_mac() { static unsigned char m[6]; return m; }
    const char *get_manufacturer() { return "mfr"; } const char *get_manufacturer_model() { return "model"; } const char *get_software_version() { return "1.0"; }
    dm_bss_t *get_bss(unsigned int i) { return &m_bss[i]; }
    void print_config();
    void init() {}      /* stand-ins: the harness object is zero initialised, the real one is initialised by init() */
    void deinit() {}
};
typedef struct { unsigned char before[PCF_GUARD]; dm_easy_mesh_t dm; unsigned char after[PCF_GUARD]; } box_t;

typedef struct {
    const char *test_name;
    unsigned int num_ssids, num_bss, num_radios;
    unsigned int op_classes_num;     /* ch_scan.op_classes_num of radio 0 */
    int oc_num;                      /* num of every op class entry of radio 0 (-1: 0 channels for entry 0 only), see construct */
    int last_oc_num;                 /* num of op class entry 63 (-1 unchanged) */
    int fill;                        /* 0 channels 1..64 (1-2 digits), 1 channels 100+i (3 digits), 2 channels 36 40 44 ... */
    int expect_lines;                /* output lines, -1 unchecked */
    const char *expect_ch_line;      /* substring that must appear in a "ch_scan op_class[0]" line, NULL unchecked */
    bool crash;
} test_case_t;
extern test_case_t suite[];
extern box_t *g_box;
void construct_input(const test_case_t *tc);
void invoke(void);
void teardown(void);
}
void run_all_tests_print_config(void);
#endif
