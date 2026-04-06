/* SPDX-License-Identifier: GPL-2.0 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string>
#include <utility>
#include <cjson/cJSON.h>
#include <iostream>
#include <atomic>

namespace util {
	inline std::string mac_to_string(const uint8_t mac[6], const std::string & delim = ":") {
		char mac_str[18]; // Max size: 6 bytes * 2 hex chars + 5 delimiters + null terminator
		snprintf(mac_str, sizeof(mac_str), "%02x%s%02x%s%02x%s%02x%s%02x%s%02x",
				mac[0], delim.c_str(), mac[1], delim.c_str(),
				mac[2], delim.c_str(), mac[3], delim.c_str(),
				mac[4], delim.c_str(), mac[5]);
		return std::string(mac_str);
	}
}

typedef struct {
	unsigned char   type;
	unsigned short  len;
	unsigned char   value[0];
} __attribute__((__packed__)) em_tlv_t;

#define MAC_ADDRESS_LEN 6
typedef uint8_t mac_address_t[MAC_ADDRESS_LEN];
typedef char    em_string_t[32];
typedef char    em_short_string_t[64];
typedef char    em_long_string_t[128];
typedef char    em_small_string_t[16];
#define EM_MAX_FRAME_BODY_LEN   512
#define MAX_VENDOR_INFO 5
#define EM_MAX_BEACON_MEASUREMENT_LEN  400
#define EM_BACKHAUL_DOWNMAC_ADDR 16
#define EM_MAX_TLV_MEMBERS 64
#define EM_MAX_AKMS     10
#define WIFI_AP_MAX_VENDOR_IE_LEN 2310
#define EM_MAX_SAMPLES_PER_LINK_REPORT  10
#define EM_MAX_BEACON_REPORTS_PER_SCAN 10
#define HASH_MAP_MAX_KEY_SIZE   100
#define EM_LOG_LVL_INFO 1
#define EM_STDOUT 0
#define _FILENAME_ _FILE_
#define EM_LOG_LVL_ERROR 2
#define EM_LOG_LVL_DEBUG 3
#define EM_MAX_DB_CFG_CRITERIA  32


// PCAP Global Header
struct pcap_global_header {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
};

// PCAP Packet Header
struct pcap_packet_header {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
};

typedef int easymesh_log_level_t;
typedef int easymesh_dbg_type_t;

typedef struct element_t {
	void     *data;
	struct element_t *next;
} element_t;

typedef struct {
	element_t    *head;
	uint32_t count;
} queue_t;

typedef struct {
	void    *data;
	char    *key;
} hash_element_t;

typedef struct {
	queue_t *queue;
	element_t    *itr;
} hash_map_t;

int8_t     queue_push(queue_t *q, void *data);
int8_t hash_map_put(hash_map_t *map, char *key, void *data);
void *hash_map_get(hash_map_t *map, const char *key);

extern unsigned char vendor_elements[];

typedef char em_interface_name_t[32];

extern inline unsigned char *get_radio_interface_mac(void);

std::pair < FILE *, std::string >
get_module_log_fd_name(int module, int level);

void get_formatted_time_em(char *time_buff);

#define em_printfout(format, ...)  em_util_print(EM_LOG_LVL_INFO, EM_STDOUT, __FILE__, __LINE__, format, ##__VA_ARGS__)// general log

void em_util_print(easymesh_log_level_t level, easymesh_dbg_type_t module, const char *func, int line, const char *format, ...);

#define UCHAR unsigned char /**< Unsigned character type. */
#define ULLONG unsigned long long  /**< Unsigned long long type. */
#define USHORT unsigned short   /**< Unsigned short type. */
#define UINT unsigned int /**< Unsigned integer type. */
#define BOOL unsigned char /**< Boolean type. */
#define USHORT unsigned short   /**< Unsigned short type. */

typedef struct{
	UCHAR bandwidth; /**< Bandwidth. */
	UCHAR centerSeg0; /**< Center segment 0. */
	UCHAR centerSeg1; /**< Center segment 1. */
} wifi_WideBWChannel_t;

typedef struct{
	UCHAR opClass; /**< Operating class. */
	UCHAR channel; /**< Channel number. */
	ULLONG startTime; /**< Start time. */
	USHORT duration; /**< Duration. */
	UCHAR frameInfo; /**< Frame information. */
	UCHAR rcpi; /**< Received Channel Power Indicator (RCPI). */
	UCHAR rsni; /**< Received Signal to Noise Indicator (RSNI). */
	fsid_t bssid; /**< BSSID. */
	UCHAR antenna; /**< Antenna ID. */
	UINT tsf; /**< Timing Synchronization Function (TSF) value. */
	BOOL wideBandWidthChannelPresent; /**< Whether the Wide Bandwidth Channel field is present. */
	wifi_WideBWChannel_t wideBandwidthChannel; /**< Wide Bandwidth Channel information. */
	USHORT numRepetitions; /**< Number of repetitions. */
} wifi_BeaconReport_t;

typedef struct {
	float link_quality_score;
	em_string_t reporting_time;
	float snr;
	float per;
	float phy;
} __attribute__((__packed__)) em_alarm_samples_t;

typedef struct {
	mac_address_t sta_mac;
	em_string_t reporting_timestamp;
	float link_quality_threshold;
	bool alarm_triggered;
	int sample_count;
	em_alarm_samples_t alarm_sample[EM_MAX_SAMPLES_PER_LINK_REPORT];
} __attribute__((__packed__)) em_link_report_t;

typedef struct {
	mac_address_t   id;
	mac_address_t   bssid;
	mac_address_t radiomac;
	bool associated;
	em_string_t sta_client_type;
	em_long_string_t    timestamp;
	unsigned int    last_ul_rate;
	unsigned int    last_dl_rate;
	unsigned int    est_ul_rate;
	unsigned int    est_dl_rate;
	unsigned int    last_conn_time;
	unsigned int    retrans_count;
	signed int      signal_strength;
	unsigned char   rcpi;
	unsigned int    util_tx;
	unsigned int    util_rx;
	unsigned int    pkts_tx;
	unsigned int    pkts_rx;
	unsigned int    bytes_tx;
	unsigned int    bytes_rx;
	unsigned int    errors_tx;
	unsigned int    errors_rx;
	unsigned int        frame_body_len;
	unsigned char       frame_body[EM_MAX_FRAME_BODY_LEN];
	unsigned int    num_vendor_infos;
	bool            multi_band_cap;
	unsigned int    num_beacon_meas_report;
	unsigned int    beacon_report_len;
	unsigned char   beacon_report_elem[EM_MAX_BEACON_MEASUREMENT_LEN];

	em_long_string_t    cap;
	em_long_string_t    ht_cap;
	em_long_string_t    vht_cap;
	em_long_string_t    he_cap;
	em_long_string_t    wifi6_cap;
	em_long_string_t    wifi7_cap;
	em_long_string_t    cellular_data_pref;
	em_long_string_t    listen_interval;
	em_long_string_t    ssid;
	em_long_string_t    supp_rates;
	em_long_string_t    power_cap;
	em_long_string_t    supp_channels;
	em_long_string_t    rsn_info;
	em_long_string_t    ext_supp_rates;
	em_long_string_t    supp_op_classes;
	em_long_string_t    ext_cap;
	em_long_string_t    rm_cap;
	em_long_string_t    multi_link;
	em_long_string_t    vendor_info[MAX_VENDOR_INFO];

	wifi_BeaconReport_t beacon_reports[EM_MAX_BEACON_REPORTS_PER_SCAN];
	em_link_report_t link_stats_report;
} em_sta_info_t;

typedef enum {
	em_get_sta_list_reason_none,
	em_get_sta_list_reason_steer,
	em_get_sta_list_reason_btm,
	em_get_sta_list_reason_disassoc,
	em_get_sta_list_reason_neighbors,
	em_get_sta_list_reason_topology,
	em_get_sta_list_reason_alarm_report,
} em_get_sta_list_reason_t;

typedef char    em_string_t[32];
typedef mac_address_t bssid_t;

class dm_sta_t {
public:
		em_sta_info_t    m_sta_info;

public:
		int init(void) { memset(&m_sta_info, 0, sizeof(em_sta_info_t)); return 0; }

		em_sta_info_t *get_sta_info(void) { return &m_sta_info; }

		int decode(const cJSON *obj, void *parent_id);

		void encode(cJSON *obj, em_get_sta_list_reason_t reson = em_get_sta_list_reason_none);

		void encode_beacon_report(cJSON *obj);

		bool operator == (const dm_sta_t & obj);

		void operator = (const dm_sta_t & obj);

		static void parse_sta_bss_radio_from_key(const char *key, mac_address_t sta, bssid_t bssid, mac_address_t radio);

		static void decode_sta_capability(dm_sta_t *sta);

		static void decode_beacon_report(dm_sta_t *sta);

		dm_sta_t(em_sta_info_t *sta) {
			if (sta)
				memcpy(&m_sta_info, sta, sizeof(em_sta_info_t));
		}

		dm_sta_t(const dm_sta_t & sta);

		dm_sta_t();

		virtual ~dm_sta_t() = default;
};

typedef enum {
	db_cfg_type_none,
	db_cfg_type_network_list_update = (1 << 0),
	db_cfg_type_network_list_delete = (1 << 1),
	db_cfg_type_device_list_update = (1 << 2),
	db_cfg_type_device_list_delete = (1 << 3),
	db_cfg_type_radio_list_update = (1 << 4),
	db_cfg_type_radio_list_delete = (1 << 5),
	db_cfg_type_op_class_list_update = (1 << 6),
	db_cfg_type_op_class_list_delete = (1 << 7),
	db_cfg_type_bss_list_update = (1 << 8),
	db_cfg_type_bss_list_delete = (1 << 9),
	db_cfg_type_sta_list_update = (1 << 10),
	db_cfg_type_sta_list_delete = (1 << 11),
	db_cfg_type_network_ssid_list_update = (1 << 12),
	db_cfg_type_network_ssid_list_delete = (1 << 13),
	db_cfg_type_radio_cap_list_update = (1 << 14),
	db_cfg_type_radio_cap_list_delete = (1 << 15),
	db_cfg_type_1905_security_list_update = (1 << 16),
	db_cfg_type_1905_security_list_delete = (1 << 17),
	db_cfg_type_sta_metrics_update = (1 << 18),
	db_cfg_type_policy_list_update = (1 << 19),
	db_cfg_type_policy_list_delete = (1 << 20),
	db_cfg_type_scan_result_list_update = (1 << 21),
	db_cfg_type_scan_result_list_delete = (1 << 22),
} db_cfg_type_t;

typedef struct {
	unsigned int db_cfg_type;
	em_long_string_t        db_cfg_criteria[EM_MAX_DB_CFG_CRITERIA];
} em_db_cfg_param_t;

typedef unsigned char mac_address_t[6];

typedef enum {
	em_media_type_ieee8023ab = 0x01,
	em_media_type_ieee80211b_24 = 0x0100,
	em_media_type_ieee80211g_24,
	em_media_type_ieee80211a_5,
	em_media_type_ieee80211n_24,
	em_media_type_ieee80211n_5,
	em_media_type_ieee80211ac_5,
	em_media_type_ieee80211ad_60,
	em_media_type_ieee80211af,
} em_media_type_t;

typedef struct {
	em_long_string_t    net_id;
	mac_address_t   dev_mac;
	em_media_type_t media;
} em_device_id_t;

/*
typedef enum {
em_media_type_ieee8023ab = 0x01,
em_media_type_ieee80211b_24 = 0x0100,
em_media_type_ieee80211g_24,
em_media_type_ieee80211a_5,
em_media_type_ieee80211n_24,
em_media_type_ieee80211n_5,
em_media_type_ieee80211ac_5,
em_media_type_ieee80211ad_60,
em_media_type_ieee80211af,
} em_media_type_t;

*/

typedef char    em_tiny_string_t[4];

typedef struct {
	em_interface_name_t name;
	mac_address_t   mac;
	em_media_type_t media;
} __attribute__((__packed__)) em_interface_t;

typedef enum {
	em_profile_type_reserved,
	em_profile_type_1,
	em_profile_type_2,
	em_profile_type_3,
} em_profile_type_t;

typedef struct {
	unsigned short  auth_flags;
	unsigned short  encr_flags;
	unsigned short  conn_flags;
	unsigned short  cfg_methods;
} ieee_1905_security_t;

typedef enum{
	WIFI_80211_VARIANT_A = 0x01, /**< 802.11a. */
	WIFI_80211_VARIANT_B = 0x02, /**< 802.11b. */
	WIFI_80211_VARIANT_G = 0x04, /**< 802.11g. */
	WIFI_80211_VARIANT_N = 0x08, /**< 802.11n. */
	WIFI_80211_VARIANT_H = 0x10, /**< 802.11h. */
	WIFI_80211_VARIANT_AC = 0x20, /**< 802.11ac. */
	WIFI_80211_VARIANT_AD = 0x40, /**< 802.11ad. */
	WIFI_80211_VARIANT_AX = 0x80, /**< 802.11ax. */
	WIFI_80211_VARIANT_BE = 0x100 /**< 802.11be. */
} wifi_ieee80211Variant_t;

typedef struct {
	em_device_id_t  id;
	em_interface_t      intf;
	em_profile_type_t   profile;
	em_long_string_t    multi_ap_cap;
	unsigned int   coll_interval;
	bool    report_unsuccess_assocs;
	unsigned short  max_reporting_rate;
	unsigned short  ap_metrics_reporting_interval;
	em_long_string_t    manufacturer;
	em_long_string_t    serial_number;
	em_long_string_t    manufacturer_model;
	em_string_t             software_ver;
	em_string_t             exec_env;
	em_string_t             dscp_map;
	unsigned char   max_pri_rules;
	unsigned char   max_vids;
	em_tiny_string_t        country_code;
	bool    prioritization_sup;
	bool    report_ind_scans;
	bool    traffic_sep_allowed;
	bool    svc_prio_allowed;
	bool    dfs_enable;
	unsigned short  max_unsuccessful_assoc_report_rate;
	bool    sta_steer_state;
	bool    coord_cac_allowed;
	em_string_t    ctrl_operation_mode;
	em_interface_t   backhaul_mac;
	unsigned char    num_backhaul_down_mac;
	em_string_t      backhaul_down_mac[EM_BACKHAUL_DOWNMAC_ADDR];
	wifi_ieee80211Variant_t  backhaul_media_type;
	unsigned int    backhaul_phyrate;
	em_interface_t   backhaul_alid;
	mac_address_t   backhaul_sta;
	bool    traffic_sep_cap;
	bool    easy_conn_cap;
	unsigned char test_cap;
	unsigned char apmld_maxlinks;
	unsigned char   tidlink_map;
	unsigned char assoc_sta_reporting_int;
	unsigned char max_nummlds;
	unsigned char bstamld_maxlinks;

	em_small_string_t    primary_device_type;
	em_small_string_t    secondary_device_type;
	ieee_1905_security_t    sec_1905;
} em_device_info_t;

typedef struct {
	mac_address_t  ruid;
	unsigned char  reserved : 7;
	unsigned char  bsta_mac_present : 1;
	mac_address_t  bsta_addr;
} __attribute__((__packed__)) em_bh_sta_radio_cap_t;

typedef enum {
    em_tlv_type_eom = 0,
    em_tlv_type_al_mac_address = 1,
    em_tlv_type_mac_address = 2,
    em_tlv_type_device_info = 3,
    em_tlv_type_device_bridging_cap = 4,
    em_tlv_type_non1905_neigh_list = 6,
    em_tlv_type_1905_neigh_list = 7,
    em_tlv_type_link_metric = 8,
    em_tlv_type_transmitter_link_metric = 9,
    em_tlv_type_receiver_link_metric = 0x0a,
    em_tlv_type_vendor_specific = 0x0b,
    em_tlv_type_link_metric_result_code = 0x0c,
    em_tlv_type_searched_role = 0x0d,
    em_tlv_type_autoconf_freq_band = 0x0e,
    em_tlv_type_supported_role = 0x0f,
    em_tlv_type_supported_freq_band = 0x10,
    em_tlv_type_wsc = 0x11,
    em_tlv_type_supported_service = 0x80,
    em_tlv_type_searched_service = 0x81,
    em_tlv_type_radio_id = 0x82,
    em_tlv_type_operational_bss = 0x83,
    em_tlv_type_associated_clients = 0x84,
    em_tlv_type_ap_radio_basic_cap = 0x85,
    em_tlv_type_ht_cap = 0x86,
    em_tlv_type_vht_cap = 0x87,
    em_tlv_type_he_cap = 0x88,
    em_tlv_type_steering_policy = 0x89,
    em_tlv_type_metric_reporting_policy = 0x8a,
    em_tlv_type_channel_pref = 0x8b,
    em_tlv_type_radio_op_restriction = 0x8c,
    em_tlv_type_tx_power = 0x8d,
    em_tlv_type_channel_sel_resp = 0x8e,
    em_tlv_type_op_channel_report = 0x8f,
    em_tlv_type_client_info = 0x90,
    em_tlv_type_client_cap_report = 0x91,
    em_tlv_type_client_assoc_event = 0x92,
    em_tlv_type_ap_metrics_query = 0x93,
    em_tlv_type_ap_metrics = 0x94,
    em_tlv_type_sta_mac_addr = 0x95,
    em_tlv_type_assoc_sta_link_metric = 0x96,
    em_tlv_type_unassoc_sta_link_metric_query = 0x97,
    em_tlv_type_unassoc_sta_link_metric_rsp = 0x98,
    em_tlv_type_bcon_metric_query = 0x99,
    em_tlv_type_bcon_metric_rsp = 0x9a,
    em_tlv_type_steering_request = 0x9b,
    em_tlv_type_steering_btm_rprt = 0x9c,
    em_tlv_type_client_assoc_ctrl_req = 0x9d,
    em_tlv_type_bh_steering_req = 0x9e,
    em_tlv_type_bh_steering_rsp = 0x9f,
    em_tlv_type_higher_layer_data = 0xa0,
    em_tlv_type_ap_cap = 0xa1,
    em_tlv_type_assoc_sta_traffic_sts = 0xa2,
    em_tlv_type_error_code = 0xa3,
    em_tlv_type_channel_scan_rprt_policy = 0xa4,
    em_tlv_type_channel_scan_cap = 0xa5,
    em_tlv_type_channel_scan_req = 0xa6,
    em_tlv_type_channel_scan_rslt = 0xa7,
    em_tlv_type_timestamp = 0xa8,
    em_tlv_type_1905_layer_security_cap = 0xa9,
    em_tlv_type_ap_wifi6_cap = 0xaa,
    em_tlv_type_mic = 0xab,
    em_tlv_type_encrypt_payload = 0xac,
    em_tlv_type_cac_req = 0xad,
    em_tlv_type_cac_term = 0xae,
    em_tlv_type_cac_cmpltn_rprt = 0xaf,
    em_tlv_type_assoc_wifi6_sta_rprt = 0xb0,
    em_tlv_type_cac_sts_rprt = 0xb1,
    em_tlv_type_cac_cap = 0xb2,
    em_tlv_type_profile = 0xb3,
    em_tlv_type_profile_2_ap_cap = 0xb4,
    em_tlv_type_dflt_8021q_settings = 0xb5,
    em_tlv_type_traffic_separation_policy = 0xb6,
    em_tlv_type_bss_conf_rep = 0xb7,
    em_tlv_type_bssid = 0xb8,
    em_tlv_type_svc_prio_rule = 0xb9,
    em_tlv_type_dscp_map_tbl = 0xba,
    em_tlv_type_bss_conf_req = 0xbb,
    em_tlv_type_profile_2_error_code = 0xbc,
    em_tlv_type_bss_conf_rsp = 0xbd,
    em_tlv_type_ap_radio_advanced_cap = 0xbe,
    em_tlv_type_assoc_sts_notif = 0xbf,
    em_tlv_type_src_info = 0xc0,
    em_tlv_type_tunneled_msg_type = 0xc1,
    em_tlv_type_tunneled = 0xc2,
    em_tlv_type_profile2_steering_request = 0xc3,
    em_tlv_type_unsucc_assoc_policy = 0xc4,
    em_tlv_type_metric_cltn_interval = 0xc5,
    em_tlv_type_radio_metric = 0xc6,
    em_tlv_type_ap_ext_metric = 0xc7,
    em_tlv_type_assoc_sta_ext_link_metric = 0xc8,
    em_tlv_type_status_code = 0xc9,
    em_tlv_type_reason_code = 0xca,
    em_tlv_type_bh_sta_radio_cap = 0xcb,
    em_tlv_type_akm_suite = 0xcc,
    em_tlv_type_1905_encap_dpp = 0xcd,
    em_tlv_type_1905_encap_eapol = 0xce,
    em_tlv_type_dpp_bootstrap_uri_notification = 0xcf,
    em_tlv_type_backhaul_bss_conf = 0xd0,
    em_tlv_type_dpp_msg = 0xd1,
    em_tlv_type_dpp_cce_indication = 0xd2,
    em_tlv_type_dpp_chirp_value = 0xd3,
    em_tlv_type_device_inventory = 0xd4,
    em_tlv_type_agent_list = 0xd5,
    em_tlv_type_anticipated_channel_pref = 0xd6,
    em_tlv_type_channel_usage = 0xd7,
    em_tlv_type_spatial_reuse_req = 0xd8,
    em_tlv_type_spatial_reuse_rep = 0xd9,
    em_tlv_type_spatial_reuse_cfg_rsp = 0xda,
    em_tlv_type_qos_mgmt_policy = 0xdb,
    em_tlv_type_qos_mgmt_desc = 0xdc,
    em_tlv_type_ctrl_cap = 0xdd,
    em_tlv_type_wifi7_agent_cap = 0xdf,
    em_tlv_type_ap_mld_config = 0xe0,
    em_tlv_type_bsta_mld_config = 0xe1,
    em_tlv_type_assoc_sta_mld_conf_rep = 0xe2,
    em_tlv_type_tid_to_link_map_policy = 0xe6,
    em_tlv_eht_operations = 0xe7,
    em_tlv_type_avail_spectrum_inquiry_reg = 0xe8,
    em_tlv_type_avail_spectrum_inquiry_rsp = 0xe9,
    em_tlv_type_vendor_operational_bss = 0xf2,

    em_tlv_type_max
} em_tlv_type_t;

typedef struct {
    mac_address_t client_mac_addr;
    unsigned char bssid[6];
} __attribute__((__packed__)) em_client_info_t;

// Forward declaration
class dm_sta_t;
class dm_device_t{
public:
		em_device_info_t    m_device_info;
		em_device_info_t *get_device_info(void) { return &m_device_info; }
};

class dm_easy_mesh_t {
public:
		static char *macbytes_to_string(mac_address_t mac, char *string);

		void set_db_cfg_param(db_cfg_type_t cfg_type, const char *criteria);

		dm_device_t m_device;

		em_device_info_t *get_device_info(void) { return m_device.get_device_info(); }

		bool    m_colocated;

		bool get_colocated(void) { return m_colocated; }

		// REQUIRED MEMBER
		hash_map_t *m_sta_assoc_map;
		em_db_cfg_param_t   m_db_cfg_param;

		/*dm_easy_mesh_t*  m_data_model;*/
		// Constructor
		dm_easy_mesh_t() {
			m_sta_assoc_map = NULL;
		}
};

inline char *dm_easy_mesh_t::macbytes_to_string(mac_address_t mac, char *string)
{
	if (mac != NULL) {
		sprintf(const_cast < char * > (string), "%02x:%02x:%02x:%02x:%02x:%02x",
				mac[0] & 0xff,
				mac[1] & 0xff,
				mac[2] & 0xff,
				mac[3] & 0xff,
				mac[4] & 0xff,
				mac[5] & 0xff);
	}
	return const_cast < char * > (string);
}

class em_capability_t {
public:
	//	int handle_client_cap_report(unsigned char *buff, unsigned int len);
		
		int handle_bsta_cap_report(unsigned char *buff, unsigned int len);
	
		int handle_bsta_radio_cap(unsigned char *buff, unsigned int len);
	
		int handle_client_info(unsigned char *buff, unsigned int len);
	
		int process_1905_eth_message(unsigned char *buff, unsigned int len, em_tlv_type_t tlv_type, int (em_capability_t::*handler)(unsigned char*, unsigned int));
		
//		int handle_client_info_report(unsigned char *buff, unsigned int len);

		//int parse_tlvs(unsigned char *buff, unsigned int len);

		dm_easy_mesh_t dm;

		virtual dm_easy_mesh_t *get_data_model(void) { return &dm; }

		em_capability_t();

		virtual ~em_capability_t();
};

typedef unsigned char mac_addr_t[6];

typedef enum {
	em_msg_type_topo_disc = 0x0000,
	em_msg_type_topo_notif,
	em_msg_type_topo_query,
	em_msg_type_topo_resp,
	em_msg_type_topo_vendor,
	em_msg_type_link_metric_query,
	em_msg_type_link_metric_resp,
	em_msg_type_autoconf_search,
	em_msg_type_autoconf_resp,
	em_msg_type_autoconf_wsc,
	em_msg_type_autoconf_renew,
	em_msg_type_1905_ack = 0x8000,
	em_msg_type_ap_cap_query,
	em_msg_type_ap_cap_rprt,
	em_msg_type_map_policy_config_req,
	em_msg_type_channel_pref_query,
	em_msg_type_channel_pref_rprt,
	em_msg_type_channel_sel_req,
	em_msg_type_channel_sel_rsp,
	em_msg_type_op_channel_rprt,
	em_msg_type_client_cap_query,
	em_msg_type_client_cap_rprt,
	em_msg_type_ap_metrics_query,
	em_msg_type_ap_metrics_rsp,
	em_msg_type_assoc_sta_link_metrics_query,
	em_msg_type_assoc_sta_link_metrics_rsp,
	em_msg_type_unassoc_sta_link_metrics_query,
	em_msg_type_unassoc_sta_link_metrics_rsp,
	em_msg_type_beacon_metrics_query,
	em_msg_type_beacon_metrics_rsp,
	em_msg_type_combined_infra_metrics,
	em_msg_type_client_steering_req,
	em_msg_type_client_steering_btm_rprt,
	em_msg_type_client_assoc_ctrl_req,
	em_msg_type_steering_complete,
	em_msg_type_higher_layer_data,
	em_msg_type_bh_steering_req,
	em_msg_type_bh_steering_rsp,
	em_msg_type_channel_scan_req,
	em_msg_type_channel_scan_rprt,
	em_msg_type_dpp_cce_ind,
	em_msg_type_1905_rekey_req,
	em_msg_type_1905_decrypt_fail,
	em_msg_type_cac_req,
	em_msg_type_cac_term,
	em_msg_type_client_disassoc_stats,
	em_msg_type_svc_prio_req,
	em_msg_type_err_rsp,
	em_msg_type_assoc_status_notif,
	em_msg_type_tunneled,
	em_msg_type_bh_sta_cap_query,
	em_msg_type_bh_sta_cap_rprt,
	em_msg_type_proxied_encap_dpp,
	em_msg_type_direct_encap_dpp,
	em_msg_type_reconfig_trigger,
	em_msg_type_bss_config_req,
	em_msg_type_bss_config_rsp,
	em_msg_type_bss_config_res,
	em_msg_type_chirp_notif,
	em_msg_type_1905_encap_eapol,
	em_msg_type_dpp_bootstrap_uri_notif,
	em_msg_type_anticipated_channel_pref,
	em_msg_type_failed_conn,
	em_msg_type_agent_list = 0x8035,
	em_msg_type_anticipated_channel_usage_rprt,
	em_msg_type_qos_mgmt_notif,
	em_msg_type_ap_mld_config_req = 0x8044,
	em_msg_type_ap_mld_config_resp,
	em_msg_type_bsta_mld_config_req,
	em_msg_type_bsta_mld_config_resp,
	em_msg_type_avail_spectrum_inquiry = 0x8049,
} em_msg_type_t;
/*
typedef enum {
em_profile_type_reserved,
em_profile_type_1,
em_profile_type_2,
em_profile_type_3,
} em_profile_type_t;
*/
/*typedef enum {
	em_tlv_type_eom = 0,
	em_tlv_type_al_mac_address = 1,
	em_tlv_type_mac_address = 2,
	em_tlv_type_device_info = 3,
	em_tlv_type_device_bridging_cap = 4,
	em_tlv_type_non1905_neigh_list = 6,
	em_tlv_type_1905_neigh_list = 7,
	em_tlv_type_link_metric = 8,
	em_tlv_type_transmitter_link_metric = 9,
	em_tlv_type_receiver_link_metric = 0x0a,
	em_tlv_type_vendor_specific = 0x0b,
	em_tlv_type_link_metric_result_code = 0x0c,
	em_tlv_type_searched_role = 0x0d,
	em_tlv_type_autoconf_freq_band = 0x0e,
	em_tlv_type_supported_role = 0x0f,
	em_tlv_type_supported_freq_band = 0x10,
	em_tlv_type_wsc = 0x11,
	em_tlv_type_supported_service = 0x80,
	em_tlv_type_searched_service = 0x81,
	em_tlv_type_radio_id = 0x82,
	em_tlv_type_operational_bss = 0x83,
	em_tlv_type_associated_clients = 0x84,
	em_tlv_type_ap_radio_basic_cap = 0x85,
	em_tlv_type_ht_cap = 0x86,
	em_tlv_type_vht_cap = 0x87,
	em_tlv_type_he_cap = 0x88,
	em_tlv_type_steering_policy = 0x89,
	em_tlv_type_metric_reporting_policy = 0x8a,
	em_tlv_type_channel_pref = 0x8b,
	em_tlv_type_radio_op_restriction = 0x8c,
	em_tlv_type_tx_power = 0x8d,
	em_tlv_type_channel_sel_resp = 0x8e,
	em_tlv_type_op_channel_report = 0x8f,
	em_tlv_type_client_info = 0x90,
	em_tlv_type_client_cap_report = 0x91,
	em_tlv_type_client_assoc_event = 0x92,
	em_tlv_type_ap_metrics_query = 0x93,
	em_tlv_type_ap_metrics = 0x94,
	em_tlv_type_sta_mac_addr = 0x95,
	em_tlv_type_assoc_sta_link_metric = 0x96,
	em_tlv_type_unassoc_sta_link_metric_query = 0x97,
	em_tlv_type_unassoc_sta_link_metric_rsp = 0x98,
	em_tlv_type_bcon_metric_query = 0x99,
	em_tlv_type_bcon_metric_rsp = 0x9a,
	em_tlv_type_steering_request = 0x9b,
	em_tlv_type_steering_btm_rprt = 0x9c,
	em_tlv_type_client_assoc_ctrl_req = 0x9d,
	em_tlv_type_bh_steering_req = 0x9e,
	em_tlv_type_bh_steering_rsp = 0x9f,
	em_tlv_type_higher_layer_data = 0xa0,
	em_tlv_type_ap_cap = 0xa1,
	em_tlv_type_assoc_sta_traffic_sts = 0xa2,
	em_tlv_type_error_code = 0xa3,
	em_tlv_type_channel_scan_rprt_policy = 0xa4,
	em_tlv_type_channel_scan_cap = 0xa5,
	em_tlv_type_channel_scan_req = 0xa6,
	em_tlv_type_channel_scan_rslt = 0xa7,
	em_tlv_type_timestamp = 0xa8,
	em_tlv_type_1905_layer_security_cap = 0xa9,
	em_tlv_type_ap_wifi6_cap = 0xaa,
	em_tlv_type_mic = 0xab,
	em_tlv_type_encrypt_payload = 0xac,
	em_tlv_type_cac_req = 0xad,
	em_tlv_type_cac_term = 0xae,
	em_tlv_type_cac_cmpltn_rprt = 0xaf,
	em_tlv_type_assoc_wifi6_sta_rprt = 0xb0,
	em_tlv_type_cac_sts_rprt = 0xb1,
	em_tlv_type_cac_cap = 0xb2,
	em_tlv_type_profile = 0xb3,
	em_tlv_type_profile_2_ap_cap = 0xb4,
	em_tlv_type_dflt_8021q_settings = 0xb5,
	em_tlv_type_traffic_separation_policy = 0xb6,
	em_tlv_type_bss_conf_rep = 0xb7,
	em_tlv_type_bssid = 0xb8,
	em_tlv_type_svc_prio_rule = 0xb9,
	em_tlv_type_dscp_map_tbl = 0xba,
	em_tlv_type_bss_conf_req = 0xbb,
	em_tlv_type_profile_2_error_code = 0xbc,
	em_tlv_type_bss_conf_rsp = 0xbd,
	em_tlv_type_ap_radio_advanced_cap = 0xbe,
	em_tlv_type_assoc_sts_notif = 0xbf,
	em_tlv_type_src_info = 0xc0,
	em_tlv_type_tunneled_msg_type = 0xc1,
	em_tlv_type_tunneled = 0xc2,
	em_tlv_type_profile2_steering_request = 0xc3,
	em_tlv_type_unsucc_assoc_policy = 0xc4,
	em_tlv_type_metric_cltn_interval = 0xc5,
	em_tlv_type_radio_metric = 0xc6,
	em_tlv_type_ap_ext_metric = 0xc7,
	em_tlv_type_assoc_sta_ext_link_metric = 0xc8,
	em_tlv_type_status_code = 0xc9,
	em_tlv_type_reason_code = 0xca,
	em_tlv_type_bh_sta_radio_cap = 0xcb,
	em_tlv_type_akm_suite = 0xcc,
	em_tlv_type_1905_encap_dpp = 0xcd,
	em_tlv_type_1905_encap_eapol = 0xce,
	em_tlv_type_dpp_bootstrap_uri_notification = 0xcf,
	em_tlv_type_backhaul_bss_conf = 0xd0,
	em_tlv_type_dpp_msg = 0xd1,
	em_tlv_type_dpp_cce_indication = 0xd2,
	em_tlv_type_dpp_chirp_value = 0xd3,
	em_tlv_type_device_inventory = 0xd4,
	em_tlv_type_agent_list = 0xd5,
	em_tlv_type_anticipated_channel_pref = 0xd6,
	em_tlv_type_channel_usage = 0xd7,
	em_tlv_type_spatial_reuse_req = 0xd8,
	em_tlv_type_spatial_reuse_rep = 0xd9,
	em_tlv_type_spatial_reuse_cfg_rsp = 0xda,
	em_tlv_type_qos_mgmt_policy = 0xdb,
	em_tlv_type_qos_mgmt_desc = 0xdc,
	em_tlv_type_ctrl_cap = 0xdd,
	em_tlv_type_wifi7_agent_cap = 0xdf,
	em_tlv_type_ap_mld_config = 0xe0,
	em_tlv_type_bsta_mld_config = 0xe1,
	em_tlv_type_assoc_sta_mld_conf_rep = 0xe2,
	em_tlv_type_tid_to_link_map_policy = 0xe6,
	em_tlv_eht_operations = 0xe7,
	em_tlv_type_avail_spectrum_inquiry_reg = 0xe8,
	em_tlv_type_avail_spectrum_inquiry_rsp = 0xe9,
	em_tlv_type_vendor_operational_bss = 0xf2,

	em_tlv_type_max
} em_tlv_type_t;*/

typedef enum {
	mandatory,
	optional,
	bad,
} em_tlv_requirement_t;

class em_tlv_member_t {
public:
		em_tlv_type_t m_type;

		em_tlv_requirement_t m_requirement;

		em_short_string_t m_spec;

		bool m_present;

		int m_tlv_length;
public:

		em_tlv_member_t(em_tlv_type_t type, em_tlv_requirement_t requirement, const char *spec, int tlv_length) {
			m_type = type;

			m_requirement = requirement;

			snprintf(m_spec, sizeof(m_spec), "%s", spec);

			m_tlv_length = tlv_length; // for tlv size check

			m_present = false;
		}
		em_tlv_member_t() { }

		~em_tlv_member_t() { }
};

typedef enum {
	em_freq_band_24,    //IEEE-1905-1-2013 table 6-23
	em_freq_band_5,
	em_freq_band_60,
	em_freq_band_6,     // Extended for 6GHz Band
	em_freq_band_unknown
} em_freq_band_t;

class em_msg_t {
	em_msg_type_t m_type;
	em_profile_type_t m_profile;
	unsigned int m_num_tlv;
	em_tlv_member_t m_tlv_member[EM_MAX_TLV_MEMBERS];
	unsigned int m_num_errors;
	em_short_string_t m_errors[EM_MAX_TLV_MEMBERS];
	unsigned char *m_buff;
	unsigned int m_len;
public:

	static unsigned char *add_buff_element(unsigned char *buff, unsigned int *len, unsigned char *element, unsigned int element_len);

	static unsigned char *add_tlv(unsigned char *buff, unsigned int *len, em_tlv_type_t tlv_type, unsigned char *value, unsigned int value_len);

	static em_tlv_t *get_tlv(em_tlv_t *tlvs_buff, unsigned int buff_len, em_tlv_type_t type);

	static em_tlv_t *get_first_tlv(em_tlv_t *tlvs_buff, unsigned int buff_len);

	static em_tlv_t *get_next_tlv(em_tlv_t *tlv, em_tlv_t *tlvs_buff, unsigned int buff_len);

	static inline  unsigned char *add_eom_tlv(unsigned char *buff, unsigned int *len)
	{
		return add_tlv(buff, len, em_tlv_type_eom, NULL, 0);
	}
	static unsigned char *add_1905_header(unsigned char *buff, unsigned int *len, mac_addr_t dst, mac_addr_t src, em_msg_type_t msg_type, unsigned short msg_id);

	unsigned int validate(char *errors[]);

	bool get_radio_id(mac_address_t *mac);

	bool get_bss_id(mac_address_t *mac);

	bool get_profile(em_profile_type_t *profile);

	bool get_freq_band(em_freq_band_t *band);

	bool get_tlv(em_tlv_t *tlv);

	bool get_profile_type(em_profile_type_t *profile);

	bool get_al_mac_address(unsigned char *mac);

	em_tlv_t *get_tlv(em_tlv_type_t type);

	void autoconfig_search(void);

	void autoconfig_resp(void);

	void autoconfig_wsc_m1(void);

	void autoconfig_wsc_m2(void);

	void topo_disc(void);

	void topo_notif(void);

	void topo_query(void);

	void topo_resp(void);

	void topo_vendor(void);

	void link_metric_query(void);

	void link_metric_resp(void);

	void autoconfig_renew(void);

	void ap_cap_query(void);

	void ap_cap_rprt(void);

	void policy_config_req(void);

	void channel_pref_query(void);

	void channel_pref_rprt(void);

	void channel_sel_req(void);

	void channel_sel_rsp(void);

	void op_channel_rprt(void);

	void client_cap_query(void);

	void client_steering_req(void);

	void client_steering_btm_rprt(void);

	void client_assoc_ctrl_req(void);

	void steering_complete(void);

	void higher_layer_data(void);

	void bh_steering_req(void);

	void bh_steering_rsp(void);

	void client_cap_rprt(void);

	void ap_metrics_query(void);

	void ap_metrics_rsp(void);

	void sta_link_metrics_query(void);

	void sta_link_metrics_rsp(void);

	void unassoc_sta_link_metrics_query(void);

	void unassoc_sta_link_metrics_rsp(void);

	void beacon_metrics_query(void);

	void beacon_metrics_rsp(void);

	void combined_infra_metrics(void);

	void channel_scan_req(void);

	void qos_mgmt_notif(void);

	void anticipated_channel_usage_rprt(void);

	void anticipated_channel_pref(void);

	void agent_list(void);

	void failed_conn(void);

	void dpp_bootstrap_uri_notif(void);

	void i1905_encap_eapol(void);

	void chirp_notif(void);

	void bss_config_res(void);

	void bss_config_rsp(void);

	void bss_config_req(void);

	void channel_scan_rprt(void);

	void dpp_cce_ind(void);

	void i1905_rekey_req(void);

	void i1905_decrypt_fail(void);

	void cac_term(void);

	void client_disassoc_stats(void);

	void svc_prio_req(void);

	void err_rsp(void);

	void assoc_status_notif(void);

	void tunneled(void);

	void bh_sta_cap_query(void);

	void bh_sta_cap_rprt(void);

	void proxied_encap_dpp(void);

	void direct_encap_dpp(void);

	void reconfig_trigger(void);

	void cac_req(void);

	void ap_mld_config_req(void);

	void ap_mld_config_rsp(void);

	void i1905_ack(void);

	void set_m1(unsigned char *tlvs, unsigned int len);

	bool get_client_mac_info(mac_address_t *mac);

	em_msg_t(em_msg_type_t type, em_profile_type_t profile, unsigned char *tlvs, unsigned int len);

	em_msg_t(unsigned char *tlvs, unsigned int len);

	em_msg_t() {}

	~em_msg_t() {}
};

typedef struct {
	mac_address_t   dst;
	mac_address_t   src;
	unsigned short  type;
} __attribute__((__packed__)) em_raw_hdr_t;

typedef struct {
	unsigned char ver;
	unsigned char   reserved;
	unsigned short  type;
	unsigned short  id;
	unsigned char   frag_id;
	unsigned char   reserved_field:6;
	unsigned char   relay_ind:1;
	unsigned char   last_frag_ind:1;
} __attribute__((__packed__)) em_cmdu_t;

typedef enum {
	em_wsc_msg_type_none,
	em_wsc_msg_type_beacon,
	em_wsc_msg_type_probe_req,
	em_wsc_msg_type_probe_rsp,
	em_wsc_msg_type_m1,
	em_wsc_msg_type_m2,
	em_wsc_msg_type_m2d,
	em_wsc_msg_type_m3,
	em_wsc_msg_type_m4,
	em_wsc_msg_type_m5,
	em_wsc_msg_type_m6,
	em_wsc_msg_type_m7,
	em_wsc_msg_type_m8,
	em_wsc_msg_type_ack,
	em_wsc_msg_type_nack,
	em_wsc_msg_type_done,
} em_wsc_msg_type_t;

/*static em_wsc_msg_type_t get_wsc_msg_type(unsigned char *buff, unsigned int len); */

class em_configuration_t {
public:
	static em_wsc_msg_type_t get_wsc_msg_type(unsigned char *tlvs, unsigned int len) { return em_wsc_msg_type_m1; }

};

typedef char mac_addr_str_t[18];

typedef enum {
	em_state_agent_unconfigured,
	em_state_agent_1905_unconfigured,
	em_state_agent_1905_securing,
	em_state_agent_autoconfig_rsp_pending,
	em_state_agent_wsc_m2_pending,
	em_state_agent_owconfig_pending,
	em_state_agent_onewifi_bssconfig_ind,
	em_state_agent_autoconfig_renew_pending,
	em_state_agent_topo_synchronized,
	em_state_agent_ap_cap_report,
	em_state_agent_channel_pref_query,
	em_state_agent_channel_selection_pending,
	em_state_agent_channel_select_configuration_pending,
	em_state_agent_channel_report_pending,
	em_state_agent_channel_scan_result_pending,
	em_state_agent_configured,

	// Transient agent stats
	em_state_agent_topology_notify,
	em_state_agent_client_cap_report,
	em_state_agent_sta_link_metrics_pending,
	em_state_agent_steer_btm_res_pending,
	em_state_agent_beacon_report_pending,
	em_state_agent_ap_metrics_pending,
	em_state_agent_link_quality_report_pending,

	em_state_ctrl_unconfigured = 0x100,
	em_state_ctrl_wsc_m1_pending,
	em_state_ctrl_wsc_m2_sent,
	em_state_ctrl_topo_sync_pending,
	em_state_ctrl_topo_synchronized,
	em_state_ctrl_ap_cap_query_pending,
	em_state_ctrl_ap_cap_report_received,
	em_state_ctrl_channel_query_pending,
	em_state_ctrl_channel_pref_report_pending,
	em_state_ctrl_channel_queried,
	em_state_ctrl_channel_select_pending,
	em_state_ctrl_channel_selected,
	em_state_ctrl_channel_cnf_pending,
	em_state_ctrl_channel_report_pending,
	em_state_ctrl_channel_scan_pending,
	em_state_ctrl_configured,
	em_state_ctrl_misconfigured,
	em_state_ctrl_sta_cap_pending,
	em_state_ctrl_sta_cap_confirmed = 1,
	em_state_ctrl_sta_link_metrics_pending,
	em_state_ctrl_sta_steer_pending,
	em_state_ctrl_steer_btm_req_ack_rcvd,
	em_state_ctrl_sta_disassoc_pending,
	em_state_ctrl_set_policy_pending,
	em_state_ctrl_ap_mld_config_pending,
	em_state_ctrl_ap_mld_configured,
	em_state_ctrl_bsta_mld_config_pending,
	em_state_ctrl_ap_mld_req_ack_rcvd,
	em_state_ctrl_avail_spectrum_inquiry_pending,
	em_state_ctrl_bsta_cap_pending,
	em_state_ctrl_topo_publish_pending,

	em_state_max,
} em_state_t;

typedef enum {
	em_service_type_ctrl,
	em_service_type_agent,
	em_service_type_cli,
	em_service_type_none
} em_service_type_t;

class em_sm_t {
	em_state_t      m_state;

public:

	int set_state(em_state_t state);

	bool validate_sm(em_state_t state);

	em_state_t get_state(void) { return m_state; }

	void init_sm(em_service_type_t service);

	em_sm_t() {}

	~em_sm_t() {}

};

class em_t {
public:

		em_sm_t  m_sm;

		void set_state(em_state_t state) {  m_sm.set_state(state); }
};

static em_t m_sm;

inline void set_state(em_state_t state)
{
	m_sm.set_state(state);
}

class dm_bss_t;

typedef enum {
	em_vap_mode_ap,
	em_vap_mode_sta
} em_vap_mode_t;

typedef struct {
	mac_address_t bssid;
	unsigned char reserved1 : 2;
	unsigned char group_addr_bu_ind_exp : 2;
	unsigned char group_addr_bu_ind_limit : 1;
	unsigned char default_pe_duration : 1;
	unsigned char disabled_subchannel_valid : 1;
	unsigned char op_info_valid : 1;
	unsigned char eht_msc_nss_set[4];
	unsigned char control;
	unsigned char ccfs0;
	unsigned char ccfs1;
	unsigned char disabled_subchannel_bitmap[2];
	unsigned char reserved2[16];
} __attribute__((__packed__)) em_eht_operations_bss_t;

typedef struct {
	// Vap Index is constant. Any modification will not be reflected in OneWifi.
	unsigned int vap_index;
	// Vap Mode is constant. Any modification will not be reflected in OneWifi.
	em_vap_mode_t vap_mode;
	dm_bss_t     *id;
	em_interface_name_t  bssid;
	em_interface_name_t  ruid;
	fsid_t  ssid;
	bool    enabled;
	unsigned int last_change;
	em_long_string_t     timestamp;
	unsigned int unicast_bytes_sent;
	unsigned int    unicast_bytes_rcvd;
	unsigned int    numberofsta;
	em_string_t     est_svc_params_be;
	em_string_t     est_svc_params_bk;
	em_string_t     est_svc_params_vi;
	em_string_t     est_svc_params_vo;
	unsigned int    byte_counter_units;
	unsigned char   num_fronthaul_akms;
	em_long_string_t     fronthaul_akm[EM_MAX_AKMS];
	unsigned char   num_backhaul_akms;
	em_long_string_t     backhaul_akm[EM_MAX_AKMS];
	bool    profile_1b_sta_allowed;
	bool    profile_2b_sta_allowed;
	unsigned int    assoc_allowed_status;
	bool    backhaul_use;
	bool    fronthaul_use;
	bool    r1_disallowed;
	bool    r2_disallowed;
	bool    multi_bssid;
	bool    transmitted_bssid;
	em_eht_operations_bss_t eht_ops;
	em_long_string_t mesh_sta_passphrase;
	unsigned int vlan_id;
	mac_address_t   mld_mac;
	mac_address_t   sta_mac;

	// Extra vendor information elements for the BSS
	// @note Don't manually allocate, use the helper functions to add/remove elements
	unsigned char vendor_elements[WIFI_AP_MAX_VENDOR_IE_LEN];
	size_t vendor_elements_len;
	bool    connect_status;
} em_bss_info_t;

typedef enum {
	em_haul_type_fronthaul,
	em_haul_type_backhaul,
	em_haul_type_iot,
	em_haul_type_configurator,
	em_haul_type_hotspot,
	em_haul_type_max,
} em_haul_type_t;

typedef struct {
	em_long_string_t        net_id;
	mac_address_t   dev_mac;
	mac_address_t  ruid;
	mac_address_t  bssid;
	em_haul_type_t  haul_type;
} em_bss_id_t;

class dm_bss_t {
public:
		em_bss_info_t    m_bss_info;

public:

		int init(void) { memset(&m_bss_info, 0, sizeof(em_bss_info_t)); return 0; }

		em_bss_info_t *get_bss_info(void) { return &m_bss_info; }

		int decode(const cJSON *obj, void *parent_id);

		void encode(cJSON *obj, bool summary = false);

		bool operator == (const dm_bss_t & obj);

		void operator = (const dm_bss_t & obj);

		bool match_criteria(char *criteria);

		static int parse_bss_id_from_key(const char *key, em_bss_id_t *id);

		bool add_vendor_ie(const struct ieee80211_vs_ie *vs_ie);

		void remove_vendor_ie(const struct ieee80211_vs_ie *vs_ie);

		dm_bss_t(em_bss_info_t *bss);

		dm_bss_t(const dm_bss_t & bss);

		dm_bss_t();

		virtual ~dm_bss_t();
};

/*typedef enum {
em_media_type_ieee8023ab = 0x01,
em_media_type_ieee80211b_24 = 0x0100,
em_media_type_ieee80211g_24,
em_media_type_ieee80211a_5,
em_media_type_ieee80211n_24,
em_media_type_ieee80211n_5,
em_media_type_ieee80211ac_5,
em_media_type_ieee80211ad_60,
em_media_type_ieee80211af,
} em_media_type_t;
*/
