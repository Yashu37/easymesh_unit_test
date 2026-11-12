#include <pthread.h>
/* SPDX-License-Identifier: GPL-2.0 */

#include <stdio.h>
#include <stddef.h>  /* offsetof (os_nif_list_get ds_list stub) */
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>        /* struct timespec (em stats timestamp types) */
#include <sys/types.h>   /* ssize_t (used by the base64_decode harness) */
#include <string>
#include <utility>
#include <cjson/cJSON.h>
#include <iostream>
#include <atomic>
#include <vector>
#include <functional>
#include <memory>

namespace util {
	inline std::string mac_to_string(const uint8_t mac[6], const std::string & delim = ":") {
		char mac_str[18]; // Max size: 6 bytes * 2 hex chars + 5 delimiters + null terminator
		snprintf(mac_str, sizeof(mac_str), "%02x%s%02x%s%02x%s%02x%s%02x%s%02x",
				mac[0], delim.c_str(), mac[1], delim.c_str(),
				mac[2], delim.c_str(), mac[3], delim.c_str(),
				mac[4], delim.c_str(), mac[5]);
		return std::string(mac_str);
	}

	char *get_date_time_rfc3399(char *buff, unsigned int len);
}

typedef struct {
	unsigned char   type;
	unsigned short  len;
	unsigned char   value[0];
} __attribute__((__packed__)) em_tlv_t;

#define EM_MAX_NET_SSIDS 5
#define EM_MAX_HAUL_TYPES   8
#define EM_DATE_TIME_BUFF_SZ    64
#define EM_MAX_SERVICE          8
#define EM_MAX_UNASSOC_STA 64
#define EM_MAX_DM_CHILDREN      64
#define EM_MAX_RADIO_PER_AGENT         4
#define MAX_STA_TO_DISASSOC             32
#define EM_CLI_MAX_ARGS 5
#define EM_VENDOR_OUI_SIZE 3
#define MAC_ADDRESS_LEN 6
typedef char    em_2xlong_string_t[256];
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
#define EM_MAX_BANDS 3
#define EM_MAX_BSSS (EM_MAX_BANDS * 8)
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
#define EM_MAX_NEIGHBORS        16
#define EM_MSCS_DISALLOWED_STA      10
#define EM_SCS_DISALLOWED_STA       10
#define EM_ASSERT_MSG_FALSE(x, ret, errMsg, ...) \
	if(x) { \
		em_printfout(errMsg, ## __VA_ARGS__); \
		return ret; \
	}

#define EM_ASSERT_MSG_TRUE(x, ret, errMsg, ...) EM_ASSERT_MSG_FALSE(!(x), ret, errMsg, ## __VA_ARGS__)
#define EM_ASSERT_NOT_NULL(x, ret, errMsg, ...) EM_ASSERT_MSG_FALSE(x == NULL, ret, errMsg, ## __VA_ARGS__)
#define EM_MAX_CHANNELS_IN_LIST  64
#define EM_MAX_OP_CLASS    48
#define ACK_FROM_AGENT 0
#define ACK_FROM_CTRL  1
#define MAX_EM_BUFF_SZ  1024
#define ETH_P_1905      0x893a
#define ETH_ALEN 6
using handshake_completed_handler = std::function<void(uint8_t[ETH_ALEN], bool)>;
#define ETH_P_ALL       0x0003
#define IF_NAMESIZE     16
# define IFNAMSIZ       IF_NAMESIZE
#define         BPF_LD          0x00
#define         BPF_H           0x08 /* 16-bit */
#define         BPF_JMP         0x05
//#define         BPF_ABS         0x20i
#define         BPF_JEQ         0x10
#define         BPF_K           0x00
#define         BPF_RET         0x06
#define PACKET_MR_PROMISC       1
#define PACKET_ADD_MEMBERSHIP           1

static     const unsigned char em_vendor_oui[EM_VENDOR_OUI_SIZE] = {0xd8, 0x9c, 0x8e};
extern uint8_t packet[4096];
extern uint8_t *ptr;
extern uint32_t packet_len;
extern FILE *fp;
typedef void (*tlv_constructor_t)(void);
typedef struct {
	const char* test_name;      // The name of the test (e.g., "pkt49_a_b_e1_rb")
	const char* pcap_file;  // The pcap file (e.g., "pkt49.pcap")
	tlv_constructor_t tlv_func; // The specific TLV constructor function
	int expected_result;        // The value that means PASS (-1 or 0)
} pkt_test_case_t;

void construct_global_header(void);
void construct_ethernet_header(void);
void construct_1905_header(void);
void construct_pcap_header(void);

extern void construct_common_headers(const char *pcap_file_name);
int construct_pcap_and_test(int (*test_func)(void));

// test function declarations
int test_handle_bsta_cap_report(void);
int test_get_first_tlv(void);
int test_get_next_tlv(void);
int test_handle_ap_metrics_response(void);
int test_handle_channel_scan_rprt(void);
int test_handle_channel_scan_req(void);
int test_handle_unassoc_sta_link_metrics_tlv(void);
int test_get_supported_service(void);
int test_handle_ap_operational_bss(void);
int test_handle_beacon_metrics_query(void);

void run_all_tests_handle_bsta_cap_report(void);
void run_all_tests_get_first_tlv(void);
void run_all_tests_get_next_tlv(void);
void run_all_tests_handle_ap_metrics_response(void);
void run_all_tests_handle_channel_scan_rprt(void);
void run_all_tests_handle_channel_scan_req(void);
void run_all_tests_get_radio_id_channel_scan_req(void);
void run_all_tests_handle_unassoc_sta_link_metrics_tlv(void);
void run_all_tests_get_supported_service(void);
void run_all_tests_handle_ap_operational_bss(void);
void run_all_tests_handle_beacon_metrics_query(void);

extern pkt_test_case_t handle_bsta_cap_report_suite[];
extern pkt_test_case_t get_first_tlv_suite[];
extern pkt_test_case_t get_next_tlv_suite[];
extern pkt_test_case_t handle_ap_metrics_response_suite[];
extern pkt_test_case_t handle_channel_scan_rprt_suite[];
extern pkt_test_case_t handle_channel_scan_req_suite[];
extern pkt_test_case_t get_radio_id_channel_scan_req_suite[];
extern pkt_test_case_t handle_unassoc_sta_link_metrics_suite[];
extern pkt_test_case_t get_supported_service_suite[];
extern pkt_test_case_t handle_ap_operational_bss_suite[];
extern pkt_test_case_t handle_beacon_metrics_query_suite[];

// --- base64_decode harness (OneWifi lib/common/util.c) ---
typedef struct {
	const char *test_name;      // case name
	const char *input;          // base64 input string
	ssize_t     out_sz;         // output-buffer size handed to base64_decode()
	int         expected_result;// return value if it did NOT crash
} base64_test_case_t;

extern char    b64_input[512];
extern uint8_t b64_out[4096];
extern ssize_t b64_out_sz;
extern const char *b64_case_name;
extern base64_test_case_t base64_decode_suite[];

void construct_base64_input(const base64_test_case_t *tc);
int  test_base64_decode(void);
void run_all_tests_base64_decode(void);

// --- base64_encode harness (OneWifi lib/common/util.c) ---
typedef struct {
	const char *test_name;      // case name
	const char *input;          // input bytes (may contain NUL/binary)
	ssize_t     in_sz;          // input_sz handed to base64_encode()
	ssize_t     out_sz;         // out_sz   handed to base64_encode()
	int         expected_result;// return value if it did NOT crash
} base64_enc_test_case_t;

extern uint8_t b64e_in[512];
extern char    b64e_out[4096];
extern ssize_t b64e_in_sz;
extern ssize_t b64e_out_sz;
extern const char *b64e_case_name;
extern base64_enc_test_case_t base64_encode_suite[];

void construct_base64_encode_input(const base64_enc_test_case_t *tc);
int  test_base64_encode(void);
void run_all_tests_base64_encode(void);

// --- cmd_log harness (OneWifi lib/common/os.c) ---
typedef struct {
	const char *test_name;      // case name
	const char *shell_cmd;      // command passed to cmd_log()
	int         expected_rc;    // expected child exit code (0 = success)
} cmd_log_test_case_t;

extern const char *cmdlog_cmd;
extern const char *cmdlog_case_name;
extern cmd_log_test_case_t cmd_log_suite[];

void construct_cmd_log_input(const cmd_log_test_case_t *tc);
int  test_cmd_log(void);
void run_all_tests_cmd_log(void);

// --- file_get harness (OneWifi lib/common/util.c) ---
typedef struct {
	const char *test_name;      // case name
	ssize_t     size;           // bytes to create (<0 => leave file missing)
	int         expected_null;  // 1 if file_get() is expected to return NULL
} file_get_test_case_t;

extern char        fileget_path[256];
extern const char *fileget_case_name;
extern ssize_t     fileget_make_size;
extern file_get_test_case_t file_get_suite[];

void construct_file_get_input(const file_get_test_case_t *tc);
int  test_file_get(void);
void run_all_tests_file_get(void);

// --- mon_check_process harness (OneWifi lib/common/monitor.c) ---
#define MONCP_EXIT    0
#define MONCP_SIGNAL  1
#define MONCP_ALIVE   2
typedef struct {
	const char *test_name;      // case name
	int         kind;           // MONCP_EXIT / MONCP_SIGNAL / MONCP_ALIVE
	int         param;          // exit code, or signal (<0 => realtime signal)
	int         expected_ret;   // 1 = alive(true), 0 = dead(false)
	int         expected_status;// expected *exit_status
} mon_cp_test_case_t;

extern pid_t       moncp_child;
extern const char *moncp_case_name;
extern mon_cp_test_case_t mon_check_process_suite[];

void construct_mon_check_process_input(const mon_cp_test_case_t *tc);
int  test_mon_check_process(const mon_cp_test_case_t *tc);
void run_all_tests_mon_check_process(void);

// --- mon_sig_crash harness (OneWifi lib/common/monitor.c) ---
#define MSC_DIRECT  0
#define MSC_FORK    1
typedef struct {
	const char *test_name;      // case name
	int         kind;           // MSC_DIRECT / MSC_FORK
	int         sig;            // signal to use
	int         expect_termsig; // FORK: expected term signal; DIRECT: 0
} mon_sig_crash_test_case_t;

extern pid_t       msc_child;
extern const char *msc_case_name;
extern mon_sig_crash_test_case_t mon_sig_crash_suite[];

void construct_mon_sig_crash_input(const mon_sig_crash_test_case_t *tc);
int  test_mon_sig_crash(const mon_sig_crash_test_case_t *tc);
void run_all_tests_mon_sig_crash(void);

// --- mon_sig_forward harness (OneWifi lib/common/monitor.c) ---
#define MSF_NOPID  0
#define MSF_LIVE   1
#define MSF_DEAD   2
typedef struct {
	const char *test_name;      // case name
	int         kind;           // MSF_NOPID / MSF_LIVE / MSF_DEAD
	int         sig;            // signal to forward
	int         expect;         // LIVE: child term signal; NOPID/DEAD: 0
} mon_sig_forward_test_case_t;

extern pid_t       mon_sig_forward_pid;   // defined in mon_sig_forward.cpp
extern pid_t       msf_child;
extern const char *msf_case_name;
extern mon_sig_forward_test_case_t mon_sig_forward_suite[];

void construct_mon_sig_forward_input(const mon_sig_forward_test_case_t *tc);
int  test_mon_sig_forward(const mon_sig_forward_test_case_t *tc);
void run_all_tests_mon_sig_forward(void);

// --- mon_sig_str harness (OneWifi lib/common/monitor.c) ---
typedef struct {
	const char *test_name;      // case name
	int         signum;         // signum passed to mon_sig_str()
	size_t      sigstr_sz;      // size of the caller buffer handed in
} mon_sig_str_test_case_t;

extern int         mss_signum;
extern size_t      mss_size;
extern const char *mss_case_name;
extern mon_sig_str_test_case_t mon_sig_str_suite[];

void construct_mon_sig_str_input(const mon_sig_str_test_case_t *tc);
int  test_mon_sig_str(void);
void run_all_tests_mon_sig_str(void);

// --- os_cmd_exec_xv harness (OneWifi lib/common/os_exec.c) ---
#ifndef OS_CMD_FLAG_ANY_EXIT_CODE
#define OS_CMD_FLAG_ANY_EXIT_CODE   1
#define OS_CMD_FLAG_NO_LOG_OUTPUT   2
#define OS_CMD_FLAG_LOG_ERROR_DEBUG 4
#endif
typedef struct {
	const char *test_name;      // case name
	const char *fmt;            // format string
	char        arg_fill;       // byte to fill the %s argument with (0 = no arg)
	int         arg_len;        // length of the %s argument (0 = none)
	int         flags;          // os_cmd_exec flags
	int         expect_ret;     // expected bool return (1/0)
} os_cmd_exec_test_case_t;

extern char        g_arg[1024];
extern size_t      g_arg_len;
extern const char *oce_case_name;
extern os_cmd_exec_test_case_t os_cmd_exec_suite[];

void construct_os_cmd_exec_xv_input(const os_cmd_exec_test_case_t *tc);
int  test_os_cmd_exec_xv(const os_cmd_exec_test_case_t *tc);
void run_all_tests_os_cmd_exec_xv(void);

// --- os_pid_from_file harness (OneWifi lib/common/os.c) ---
#define OSPID_LIVE      0
#define OSPID_LONGLINE  1
#define OSPID_DEAD      2
#define OSPID_ZERO      3
#define OSPID_NONNUM    4
#define OSPID_EMPTY     5
#define OSPID_MISSING   6
typedef struct {
	const char *test_name;      // case name
	int         kind;           // OSPID_* kind
	int         expect_nonzero; // 1 if a pid should be returned, 0 otherwise
} os_pid_test_case_t;

extern char        ospid_path[256];
extern const char *ospid_case_name;
extern os_pid_test_case_t os_pid_suite[];

void construct_os_pid_from_file_input(const os_pid_test_case_t *tc);
int  test_os_pid_from_file(void);
void run_all_tests_os_pid_from_file(void);

// --- os_popen harness (OneWifi lib/common/os.c) ---
typedef struct {
	const char *test_name;      // case name
	const char *shell_cmd;      // command passed to os_popen()
	int         expect_output;  // 1 if output bytes expected, 0 otherwise
} os_popen_test_case_t;

extern const char *osp_cmd;
extern const char *osp_case_name;
extern os_popen_test_case_t os_popen_suite[];

void construct_os_popen_input(const os_popen_test_case_t *tc);
int  test_os_popen(const os_popen_test_case_t *tc);
void run_all_tests_os_popen(void);

// --- parse_uri harness (OneWifi lib/common/util.c) ---
typedef struct {
	const char *test_name;      // case name
	const char *uri;            // literal URI (when use_fill == 0)
	int         use_fill;       // 0=literal, 1="ssl:"+fill, 2="ssl:"+fill+":443"
	char        fill_ch;        // fill byte
	int         fill_len;       // number of fill bytes
	int         expect_ret;     // 1/0; -1 = suspected crash case
} parse_uri_test_case_t;

extern char        puri_in[1024];
extern size_t      puri_in_len;
extern const char *puri_case_name;
extern parse_uri_test_case_t parse_uri_suite[];

void construct_parse_uri_input(const parse_uri_test_case_t *tc);
int  test_parse_uri(const parse_uri_test_case_t *tc);
void run_all_tests_parse_uri(void);

// --- strexread harness (OneWifi lib/common/util.c) ---
#define SXR_NORMAL     0
#define SXR_PROG_NULL  1
#define SXR_ARGV_NULL  2
typedef struct {
	const char *test_name;      // case name
	const char *prog;           // program
	const char *a0, *a1, *a2;   // up to 3 argv entries (NULL-terminated)
	int         mode;           // SXR_NORMAL / SXR_PROG_NULL / SXR_ARGV_NULL
	int         expect_nonnull; // 1 if a buffer should be returned
} strexread_test_case_t;

extern char        sxr_prog[256];
extern size_t      sxr_prog_len;
extern char        sxr_args[8][256];
extern const char *sxr_argv[8];
extern int         sxr_argc;
extern int         sxr_prog_null;
extern int         sxr_argv_null;
extern const char *sxr_case_name;
extern strexread_test_case_t strexread_suite[];

void construct_strexread_input(const strexread_test_case_t *tc);
int  test_strexread(const strexread_test_case_t *tc);
void run_all_tests_strexread(void);

// --- unii_5g_chan2list harness (OneWifi lib/common/util.c) ---
typedef struct {
	const char *test_name;      // case name
	int         chan;           // channel arg
	int         width;          // width arg
	int         expect;         // 1=non-NULL, 0=NULL, -1=suspected crash
} unii_test_case_t;

extern int         unii_chan;
extern int         unii_width;
extern const char *unii_case_name;
extern unii_test_case_t unii_suite[];

void construct_unii_5g_chan2list_input(const unii_test_case_t *tc);
int  test_unii_5g_chan2list(const unii_test_case_t *tc);
void run_all_tests_unii_5g_chan2list(void);

// --- devinfo_get_inet_iface_config harness (OneWifi lib/datapipeline/devinfo.c) ---
#ifndef IP_ADDR_STR_LEN
#define IP_ADDR_STR_LEN  16
#endif
#ifndef MAC_ADDR_STR_LEN
#define MAC_ADDR_STR_LEN 18
#endif
typedef struct {
	char inet_addr[IP_ADDR_STR_LEN];
	char mac_str[MAC_ADDR_STR_LEN];
} devinfo_inet_iface_config_t;

typedef struct {
	const char *test_name;      // case name
	const char *if_name;        // interface name arg
	int         expect_ret;     // expected bool return (1/0)
} devinfo_cfg_test_case_t;

extern char        dgi_ifname[64];
extern size_t      dgi_ifname_len;
extern const char *dgi_case_name;
extern devinfo_cfg_test_case_t devinfo_cfg_suite[];

void construct_devinfo_cfg_input(const devinfo_cfg_test_case_t *tc);
int  test_devinfo_cfg(const devinfo_cfg_test_case_t *tc);
void run_all_tests_devinfo_cfg(void);

// --- dpp_mac_str_tmp harness (OneWifi lib/datapipeline/dppline.c) ---
typedef struct {
	const char *test_name;      // case name
	uint8_t     mac[6];         // 6-byte MAC input
	const char *expected;       // expected formatted string
} dpp_mac_test_case_t;

extern uint8_t     dmt_mac[16];
extern const char *dmt_case_name;
extern const char *dmt_expect;
extern dpp_mac_test_case_t dpp_mac_suite[];

void construct_dpp_mac_str_tmp_input(const dpp_mac_test_case_t *tc);
int  test_dpp_mac_str_tmp(const dpp_mac_test_case_t *tc);
void run_all_tests_dpp_mac_str_tmp(void);

// --- osp_unit_dhcpc_hostname_get harness (OneWifi lib/datapipeline/osp_unit_rdk.c) ---
typedef struct {
	const char *test_name;      // case name
	size_t      buffsz;         // output buffer size
	const char *serial;         // stub serial value
	const char *model;          // stub model value
	int         ser_ok;         // serial getter succeeds?
	int         mod_ok;         // model getter succeeds?
	int         expect_ret;     // expected bool return
} osp_hostname_test_case_t;

extern size_t      ohg_buffsz;
extern const char *ohg_case_name;
extern osp_hostname_test_case_t osp_hostname_suite[];

void construct_osp_hostname_input(const osp_hostname_test_case_t *tc);
int  test_osp_hostname(const osp_hostname_test_case_t *tc);
void run_all_tests_osp_hostname(void);

// --- radio_get_name_from_cfg harness (OneWifi lib/datapipeline/dpp_types.h) ---
#define RADIO_IFNAME_LEN 16
#define RADIO_NAME_LEN   32
#define RADIO_TYPE_STR_2G   "2.4G"
#define RADIO_TYPE_STR_5G   "5G"
#define RADIO_TYPE_STR_5GL  "5GL"
#define RADIO_TYPE_STR_5GU  "5GU"
#define RADIO_TYPE_STR_6G   "6G"
typedef enum {
	RADIO_TYPE_NONE = 0,
	RADIO_TYPE_2G,
	RADIO_TYPE_5G,
	RADIO_TYPE_5GL,
	RADIO_TYPE_5GU,
	RADIO_TYPE_6G,
} radio_type_t;
/* minimal radio_entry_t: only the two fields radio_get_name_from_cfg uses */
typedef struct {
	radio_type_t type;
	char         phy_name[RADIO_NAME_LEN];
} radio_entry_t;

typedef struct {
	const char   *test_name;    // case name
	radio_type_t  type;         // radio type
	const char   *phy_name;     // phy name
	int           null_cfg;     // pass cfg = NULL
	int           expect_nonnull; // 1 if a string should be returned
} radio_name_test_case_t;

extern unsigned char rgn_backing[sizeof(radio_entry_t) + 64];
extern size_t        rgn_phy_len;
extern int           rgn_null_cfg;
extern const char   *rgn_case_name;
extern radio_name_test_case_t radio_name_suite[];

void construct_radio_name_input(const radio_name_test_case_t *tc);
int  test_radio_name(const radio_name_test_case_t *tc);
void run_all_tests_radio_name(void);

// --- ds_tree_check_r harness (OneWifi lib/ds/ds_tree.c) ---
typedef struct ds_tree_node ds_tree_node_t;
struct ds_tree_node {
	void           *otn_key;
	int             otn_prop;      /* color: 1=red, 0=black */
	ds_tree_node_t *otn_parent;
	ds_tree_node_t *otn_child[2];
};
typedef struct ds_tree ds_tree_t;
struct ds_tree {
	size_t          ot_cof;
	ds_tree_node_t *ot_root;
	void           *ot_cmp_fn;
	char          *(*ot_str_fn)(ds_tree_node_t *node);
	unsigned        ot_ndel;
};

#define DSC_SINGLE     0
#define DSC_VALID3     1
#define DSC_BLACKVIOL  2
#define DSC_REDVIOL    3
typedef struct {
	const char *test_name;      // case name
	int         kind;           // DSC_* tree shape
	int         expect_ok;      // 1 if check returns >=0 (valid), 0 if -1
} ds_tree_check_test_case_t;

extern ds_tree_node_t dsc_nodes[8];
extern ds_tree_t      dsc_root;
extern const char    *dsc_case_name;
extern ds_tree_check_test_case_t ds_tree_check_suite[];

void construct_ds_tree_check_input(const ds_tree_check_test_case_t *tc);
int  test_ds_tree_check(const ds_tree_check_test_case_t *tc);
void run_all_tests_ds_tree_check(void);

// --- ds_tree_graphviz_r harness (OneWifi lib/ds/ds_tree.c) ---
#define DGV_SINGLE  0
#define DGV_3NODE   1
#define DGV_DEEP    2
typedef struct {
	const char *test_name;      // case name
	int         kind;           // DGV_* tree shape
} ds_tree_gv_test_case_t;

extern ds_tree_node_t dgv_nodes[8];
extern ds_tree_t      dgv_root;
extern const char    *dgv_case_name;
extern ds_tree_gv_test_case_t ds_tree_gv_suite[];

void construct_ds_tree_gv_input(const ds_tree_gv_test_case_t *tc);
int  test_ds_tree_gv(const ds_tree_gv_test_case_t *tc);
void run_all_tests_ds_tree_gv(void);

// --- ds_tree_node_str harness (OneWifi lib/ds/ds_tree.c) ---
typedef struct {
	const char *test_name;      // case name
	void       *key;            // node->otn_key
	int         use_strfn;      // use custom ot_str_fn?
	const char *expect;         // expected substring (NULL = just non-NULL)
} ds_node_str_test_case_t;

extern unsigned char dns_backing[sizeof(ds_tree_node_t) + 64];
extern ds_tree_t     dns_root;
extern int           dns_use_strfn;
extern const char   *dns_case_name;
extern ds_node_str_test_case_t ds_node_str_suite[];

void construct_ds_node_str_input(const ds_node_str_test_case_t *tc);
int  test_ds_node_str(const ds_node_str_test_case_t *tc);
void run_all_tests_ds_node_str(void);

// --- log_dynamic_full_path_get harness (OneWifi lib/log/log.c) ---
typedef struct {
	const char *test_name;      // case name
	int         len;            // buffer length passed to the function
} log_fullpath_test_case_t;

extern int         ldfp_len;
extern const char *ldfp_case_name;
extern log_fullpath_test_case_t log_fullpath_suite[];

void construct_log_fullpath_input(const log_fullpath_test_case_t *tc);
int  test_log_fullpath(const log_fullpath_test_case_t *tc);
void run_all_tests_log_fullpath(void);

// --- log_dynamic_state_handler harness (OneWifi lib/log/log.c) ---
/* libev stand-in types (handler params are unreferenced) */
#ifndef LDS_EV_STUBS
#define LDS_EV_STUBS
struct ev_loop { int dummy; };
typedef struct { int dummy; } ev_stat;
#endif

typedef struct {
	const char *test_name;      // case name
	int         update_ret;     // what log_dynamic_update returns
	int         new_trigger;    // value it writes
	int         trig_value;     // current trigger_value
	int         have_cb;        // install a trigger callback?
	int         expect_cb;      // expect the callback to fire?
} log_state_test_case_t;

extern int lds_update_ret;
extern int lds_new_trigger;
extern int lds_cb_count;
extern const char *lds_case_name;
extern log_state_test_case_t log_state_suite[];

void construct_log_state_input(const log_state_test_case_t *tc);
int  test_log_state(const log_state_test_case_t *tc);
void run_all_tests_log_state(void);

// --- log_dynamic_update harness (OneWifi lib/log/log.c) ---
typedef struct {
	const char *test_name;      // case name
	int         json_ok;        // json_load_file returns non-NULL?
	const char *sev_value;      // severity the parse stub writes
	int         trigger;        // value parse writes to *new_trigger
	int         use_long_name;  // use a >64-char log_name (stress remote_name[64])
	int         expect_ret;     // expected bool return
} log_update_test_case_t;

extern int         ldu_json_ok;
extern const char *ldu_sev_value;
extern int         ldu_parse_trigger;
extern char        ldu_last_local[320];
extern char        ldu_last_remote[320];
extern const char *ldu_case_name;
extern log_update_test_case_t log_update_suite[];

void construct_log_update_input(const log_update_test_case_t *tc);
int  test_log_update(const log_update_test_case_t *tc);
void run_all_tests_log_update(void);

// --- log_meminfo harness (OneWifi lib/log/log.c) ---
typedef struct {
	const char *test_name;      // case name
	int         size;           // buffer size
	int         pos;            // offset (negative = suspected OOB)
	int         expect;         // 1=wrote, 0=early return, -1=suspected crash
} log_meminfo_test_case_t;

extern int         lmi_size;
extern int         lmi_pos;
extern const char *lmi_case_name;
extern log_meminfo_test_case_t log_meminfo_suite[];

void construct_log_meminfo_input(const log_meminfo_test_case_t *tc);
int  test_log_meminfo(const log_meminfo_test_case_t *tc);
void run_all_tests_log_meminfo(void);

// --- log_severity_parse_sink harness (OneWifi lib/log/log.c) ---
typedef struct {
	const char *test_name;      // case name
	const char *input;          // severity string (base token)
	int         fill_len;       // pad to this length (0 = none)
	int         null;           // pass sevstr = NULL
	int         expect_ret;     // expected bool return
} log_sev_test_case_t;

extern char        lsp_in[512];
extern size_t      lsp_in_len;
extern int         lsp_null;
extern const char *lsp_case_name;
extern int         lsp_default_set, lsp_sev_set, lsp_mod_sev_set;
extern log_sev_test_case_t log_sev_suite[];

void construct_log_sev_input(const log_sev_test_case_t *tc);
int  test_log_sev(const log_sev_test_case_t *tc);
void run_all_tests_log_sev(void);

// --- logger_remote_log harness (OneWifi lib/log/log_remote.c) ---
typedef struct logger logger_t;
typedef struct logger_msg {
	char *lm_timestamp;
	char *lm_tag;
	char *lm_text;
	char *lm_module_name; /* used by mlog */
	int   lm_module;      /* used by logger_traceback_log / mlog */
	int   lm_severity;    /* used by logger_traceback_log / mlog */
} logger_msg_t;
/* full logger_t body so mlog's foreach loop compiles (loop runs 0 times) */
typedef void (*logger_fn_t)(logger_t *, logger_msg_t *);
typedef bool (*logger_match_fn_t)(int sev, int module);
struct logger {
	logger_fn_t       logger_fn;
	logger_match_fn_t match_fn;
};

typedef struct {
	const char *test_name;      // case name
	const char *ts;             // timestamp string
	const char *tag;            // tag string
	int         text_fill_len;  // pad text to this length (0 = use text)
	const char *text;           // text string
	int         enabled;        // log_remote_enabled?
	int         expect_send;    // expect qm_conn_send_log to fire?
} logger_remote_test_case_t;

extern char         lrl_ts[64];
extern char         lrl_tag[64];
extern char         lrl_text[4096];
extern size_t       lrl_ts_len, lrl_tag_len, lrl_text_len;
extern logger_msg_t lrl_msg;
extern int          lrl_send_count;
extern const char  *lrl_case_name;
extern logger_remote_test_case_t logger_remote_suite[];

void construct_logger_remote_input(const logger_remote_test_case_t *tc);
int  test_logger_remote(const logger_remote_test_case_t *tc);
void run_all_tests_logger_remote(void);

// --- logger_traceback_log harness (OneWifi lib/log/log_traceback.c) ---
typedef struct {
	const char *test_name;      // case name
	int         module;         // msg->lm_module
	int         severity;       // msg->lm_severity (>4 store, <=4 flush)
	const char *tag;            // msg->lm_tag
	const char *text;           // msg->lm_text
	int         fill;           // pad text to this length (0 = use text)
	int         repeat;         // call the handler this many times
	int         expect_flush;   // expected mlog flush count
} logger_tb_test_case_t;

extern char         ltb_tag[64];
extern char         ltb_text[4096];
extern size_t       ltb_tag_len, ltb_text_len;
extern logger_msg_t ltb_msg;
extern int          ltb_repeat;
extern int          tb_flush_count;
extern const char  *ltb_case_name;
extern logger_tb_test_case_t logger_tb_suite[];

void construct_logger_tb_input(const logger_tb_test_case_t *tc);
int  test_logger_tb(const logger_tb_test_case_t *tc);
void run_all_tests_logger_tb(void);

// --- mlog harness (OneWifi lib/log/log.c) ---
#define MLOG_NORMAL 0
#define MLOG_EMPTY  1
#define MLOG_LONG   2
typedef struct {
	const char *test_name;      // case name
	int         sev;            // severity (0 = disabled)
	int         module;         // module id (>=LAST clamps)
	int         kind;           // MLOG_NORMAL / MLOG_EMPTY / MLOG_LONG
	int         payload_fill;   // %s payload length (MLOG_LONG)
	int         expect_captured;// expect the logger to capture a message
} mlog_test_case_t;

extern int         mlog_captured;
extern char        mlog_captured_text[8300];
extern char        mlog_captured_tag[128];
extern char        mlog_payload[16384];
extern size_t      mlog_payload_len;
extern const char *mlog_case_name;
extern mlog_test_case_t mlog_suite[];

void construct_mlog_input(const mlog_test_case_t *tc);
int  test_mlog(const mlog_test_case_t *tc);
void run_all_tests_mlog(void);

// --- os_file_open harness (OneWifi lib/osa/os_file_ops.c) ---
typedef struct {
	const char *test_name;      // case name
	const char *location;       // directory
	const char *prefix;         // file prefix
	int         pre_fill;       // pad prefix to this length (0 = use prefix)
	int         loc_fill;       // (reserved)
	int         expect_fp;      // expect fopen to succeed (1) or not (0)
} os_file_open_test_case_t;

extern char        ofo_location[256];
extern char        ofo_prefix[256];
extern size_t      ofo_loc_len, ofo_pre_len;
extern const char *ofo_case_name;
extern os_file_open_test_case_t os_file_open_suite[];

void construct_os_file_open_input(const os_file_open_test_case_t *tc);
int  test_os_file_open(const os_file_open_test_case_t *tc);
void run_all_tests_os_file_open(void);

// --- os_name_to_pid harness (OneWifi lib/osa/os_proc.c) ---
#define ONP_SELF     0
#define ONP_LITERAL  1
#define ONP_EMPTY    2
#define ONP_LONG     3
typedef struct {
	const char *test_name;      // case name
	int         which;          // ONP_SELF / ONP_LITERAL / ONP_EMPTY / ONP_LONG
	int         expect_found;   // expect a pid (1) or not (0)
} os_name_pid_test_case_t;

extern char        onp_name[256];
extern size_t      onp_name_len;
extern char        onp_self_comm[64];
extern const char *onp_case_name;
extern os_name_pid_test_case_t os_name_pid_suite[];

void construct_os_name_pid_input(const os_name_pid_test_case_t *tc);
int  test_os_name_pid(const os_name_pid_test_case_t *tc);
void run_all_tests_os_name_pid(void);

// --- os_ipaddr_t / os_macaddr_t (verbatim from OneWifi lib/osa/os_types.h + lib/const/const.h) ---
typedef struct { uint8_t addr[6]; } os_macaddr_t;
typedef struct { uint8_t addr[4]; } os_ipaddr_t;
#define PRI(type)               PRI_ ## type
#define FMT(type, x)            FMT_ ## type (x)
#define PRI_os_macaddr_t        "%02X:%02X:%02X:%02X:%02X:%02X"
#define FMT_os_macaddr_t(x)     (x).addr[0], (x).addr[1], (x).addr[2], (x).addr[3], (x).addr[4], (x).addr[5]
#define PRI_os_ipaddr_t         "%d.%d.%d.%d"
#define FMT_os_ipaddr_t(x)      (x).addr[0], (x).addr[1], (x).addr[2], (x).addr[3]

// --- os_nif_gateway_set / os_nif_gateway_del harnesses (OneWifi lib/osa/os_nif_linux.c) ---
typedef struct {
	const char *test_name;      // case name
	const char *ifname;         // literal ifname (used when fill == 0)
	int         fill;           // >0: ifname = fill x 'w'
	os_ipaddr_t gw;             // gateway address
} os_nif_gw_test_case_t;

extern char        ogd_ifname[256];
extern size_t      ogd_ifname_len;
extern os_ipaddr_t ogd_gw;
extern os_nif_gw_test_case_t os_nif_gateway_del_suite[];
void construct_os_nif_gateway_del_input(const os_nif_gw_test_case_t *tc);
int  test_os_nif_gateway_del(const os_nif_gw_test_case_t *tc);
void run_all_tests_os_nif_gateway_del(void);

extern char        ogs_ifname[256];
extern size_t      ogs_ifname_len;
extern os_ipaddr_t ogs_gw;
extern os_nif_gw_test_case_t os_nif_gateway_set_suite[];
void construct_os_nif_gateway_set_input(const os_nif_gw_test_case_t *tc);
int  test_os_nif_gateway_set(const os_nif_gw_test_case_t *tc);
void run_all_tests_os_nif_gateway_set(void);

// --- os_nif_list_get harness (OneWifi lib/osa/os_nif_linux.c) ---
// Minimal ds_list stub (scaffolding, NOT lib/ds): singly-linked, head insert,
// iterator with remove -- just enough for os_nif_list_get/os_nif_list_free.
typedef struct ds_list_node { struct ds_list_node *next; } ds_list_node_t;
typedef struct { ds_list_node_t *head; size_t cof; } ds_list_t;
typedef struct { ds_list_t *list; ds_list_node_t **prevp; ds_list_node_t *cur; int removed; } ds_list_iter_t;
#define ds_list_init(l, type, member) do { (l)->head = NULL; (l)->cof = offsetof(type, member); } while (0)
static inline void ds_list_insert_head(ds_list_t *l, void *data)
{
	ds_list_node_t *nd = (ds_list_node_t *)((char *)data + l->cof);
	nd->next = l->head; l->head = nd;
}
static inline void *ds_list_icont(ds_list_iter_t *it)
{
	return it->cur ? (void *)((char *)it->cur - it->list->cof) : NULL;
}
static inline void *ds_list_ifirst(ds_list_iter_t *it, ds_list_t *l)
{
	it->list = l; it->prevp = &l->head; it->cur = l->head; it->removed = 0;
	return ds_list_icont(it);
}
static inline void *ds_list_inext(ds_list_iter_t *it)
{
	if (!it->removed) it->prevp = &it->cur->next;
	it->removed = 0; it->cur = *it->prevp;
	return ds_list_icont(it);
}
static inline void ds_list_iremove(ds_list_iter_t *it)
{
	*it->prevp = it->cur->next; it->removed = 1;
}

struct os_nif_list_entry                    // verbatim from lib/osa/os_nif.h
{
    char            le_ifname[64];
    ds_list_node_t  le_node;
};

#define ONLG_REAL        0   // read the real /proc/net/dev
#define ONLG_DATA        1   // use the literal data
#define ONLG_NAME_LEN    2   // one "<arg x 'a'>: 0 0" line
#define ONLG_LONG_LINE   3   // one line of arg chars (longer than buf[256])
#define ONLG_FOPEN_FAIL  4   // fopen returns NULL
#define ONLG_MANY        5   // arg interface lines (pool exhaustion when > slots)
typedef struct {
	const char *test_name;      // case name
	int         kind;           // ONLG_*
	const char *data;           // literal content for ONLG_DATA
	int         arg;            // length / count for NAME_LEN / LONG_LINE / MANY
	int         expect_ret;     // expected return of os_nif_list_get (1 = true)
	int         expect_count;   // expected entries (-1 = any >= 1)
} os_nif_list_get_test_case_t;

#define ONLG_POOL_SLOTS  128
#define ONLG_SLOT_PAD    64     // poisoned bytes after each entry
extern unsigned char onlg_pool[ONLG_POOL_SLOTS][sizeof(struct os_nif_list_entry) + ONLG_SLOT_PAD];
extern int           onlg_pool_used;
extern char          onlg_data[16384];
extern size_t        onlg_data_len;
extern int           onlg_use_real, onlg_fopen_fail;
extern os_nif_list_get_test_case_t os_nif_list_get_suite[];

void construct_os_nif_list_get_input(const os_nif_list_get_test_case_t *tc);
int  test_os_nif_list_get(const os_nif_list_get_test_case_t *tc);
void run_all_tests_os_nif_list_get(void);

// --- os_nif_macaddr_from_str harness (OneWifi lib/osa/os_nif_linux.c) ---
typedef struct {
	const char *test_name;      // case name
	const char *str;            // input MAC string (used when fill == 0)
	int         fill;           // >0: input = fill chars of "a:a:a:..."
	int         expect_ret;     // expected return (1 = true)
} os_nif_macaddr_test_case_t;

extern char   onm_str[256];
extern size_t onm_str_len;
extern os_nif_macaddr_test_case_t os_nif_macaddr_from_str_suite[];

void construct_os_nif_macaddr_from_str_input(const os_nif_macaddr_test_case_t *tc);
int  test_os_nif_macaddr_from_str(const os_nif_macaddr_test_case_t *tc);
void run_all_tests_os_nif_macaddr_from_str(void);

// --- os_nif_softwds_create harness (OneWifi lib/osa/os_nif_linux.c) ---
typedef struct {
	const char *test_name;      // case name
	const char *ifname;         // literal ifname (used when if_fill == 0)
	int         if_fill;        // >0: ifname = if_fill x 'i'
	const char *parent;         // literal parent (used when par_fill == 0)
	int         par_fill;       // >0: parent = par_fill x 'p'
	int         wrap;           // wrap flag
	int         create_exit;    // exit status the stubbed cmd_log returns for create
	int         expect_ret;     // expected return (1 = true)
} os_nif_softwds_test_case_t;

extern char   osc_ifname[256], osc_parent[256];
extern size_t osc_ifname_len, osc_parent_len;
extern size_t osc_max_cmd_len;
extern int    osc_calls, osc_create_exit;
extern os_nif_softwds_test_case_t os_nif_softwds_create_suite[];

void construct_os_nif_softwds_create_input(const os_nif_softwds_test_case_t *tc);
int  test_os_nif_softwds_create(const os_nif_softwds_test_case_t *tc);
void run_all_tests_os_nif_softwds_create(void);

// --- os_nif_softwds_destroy harness (OneWifi lib/osa/os_nif_linux.c) ---
typedef struct {
	const char *test_name;      // case name
	const char *ifname;         // literal ifname (used when fill == 0)
	int         fill;           // >0: ifname = fill x 'd'
	int         exit_status;    // exit status the stubbed cmd_log returns
	int         expect_ret;     // expected return (1 = true)
} os_nif_softwds_destroy_test_case_t;

extern char   osd_ifname[2048];
extern size_t osd_ifname_len;
extern size_t osd_cmd_len;
extern int    osd_calls, osd_exit;
extern os_nif_softwds_destroy_test_case_t os_nif_softwds_destroy_suite[];

void construct_os_nif_softwds_destroy_input(const os_nif_softwds_destroy_test_case_t *tc);
int  test_os_nif_softwds_destroy(const os_nif_softwds_destroy_test_case_t *tc);
void run_all_tests_os_nif_softwds_destroy(void);

// --- os_pid_to_name harness (OneWifi lib/osa/os_proc.c) ---
#define OPN_SELF  0
#define OPN_NONE  1
typedef struct {
	const char *test_name;      // case name
	int         pid_kind;       // OPN_SELF (getpid) / OPN_NONE (nonexistent pid)
	int         buf_size;       // bytes of proc_name the caller really owns
	int         len;            // len argument passed to os_pid_to_name
	int         expect_ret;     // expected return (0 / -1)
} os_pid_to_name_test_case_t;

extern char opn_name[128];
extern int  opn_pid;
extern os_pid_to_name_test_case_t os_pid_to_name_suite[];

void construct_os_pid_to_name_input(const os_pid_to_name_test_case_t *tc);
int  test_os_pid_to_name(const os_pid_to_name_test_case_t *tc);
void run_all_tests_os_pid_to_name(void);

// --- ovsdb_table_t / ovsdb_cache_row_t (OneWifi lib/ovsdb/ovsdb_table.h) ---
// Subset: only the fields the lib/ovsdb harnesses touch, same names/types.
// js is "void *" here instead of json_t * because common.h is shared with
// log_dynamic_update.cpp, which has its own fake json_t (callers pass a real
// jansson json_t *, which converts implicitly).
typedef char pjs_errmsg_t[128];                                              // lib/pjs/pjs_common.h
typedef bool schema_from_json_t(void *out, void *js, bool update, pjs_errmsg_t err);  // ovsdb_table.h
typedef void schema_mark_changed_t(void *old, void *rec);                    // ovsdb_table.h
typedef void *schema_to_json_t(void *in, pjs_errmsg_t err);                 // ovsdb_table.h (returns json_t *)
#define PJS_OVS_UUID_SZ             37      /* Max OVS UUID size */  // lib/pjs/pjs_common.h
typedef struct
{
    char uuid[PJS_OVS_UUID_SZ];
} ovs_uuid_t;
typedef enum                                                                 // lib/ovsdb/ovsdb_update.h
{
    OVSDB_UPDATE_ERROR = -1,
    OVSDB_UPDATE_NEW,
    OVSDB_UPDATE_MODIFY,
    OVSDB_UPDATE_DEL,
}
ovsdb_update_type_t;
typedef struct ovsdb_update_monitor_s ovsdb_update_monitor_t;
typedef void ovsdb_update_cbk_t(ovsdb_update_monitor_t *self);
struct ovsdb_update_monitor_s                     // json_t * spelled void * (see above)
{
    ovsdb_update_cbk_t     *mon_cb;            /* Update callback */
    void                   *mon_data;          /* User-supplied data, not touched by ovsdb_update_* */
    ovsdb_update_type_t     mon_type;           /* Update type */
    const char             *mon_table;          /* Table that was modified */
    const char             *mon_uuid;           /* UUID of the modified ROW */
    void                   *mon_json_new;       /* JSON message containing the update */
    void                   *mon_json_old;       /* JSON message containing old data */
    void                   *mon_old_rec;
};
#define OVSDB_TABLE_KEY_SIZE 64
#define OVSDB_TABLE_NAME_SIZE 64
typedef struct ovsdb_cache_row
{
    ds_tree_node_t  node; // tree node uuid key
    ds_tree_node_t  node_k; // tree node primary key
    ds_tree_node_t  node_k2; // tree node alternate key2
    int             user_flags;
    char            record[]; // actual values placeholder
} ovsdb_cache_row_t;

typedef struct ovsdb_table
{
    char                    table_name[OVSDB_TABLE_NAME_SIZE];
    int                     schema_size;
    int                     upd_type_offset;
    int                     uuid_offset;
    int                     version_offset;
    int                     key_offset; // primary key, example: if_name
    char                    key_name[OVSDB_TABLE_KEY_SIZE];
    int                     key2_offset; // optional alternate key2, example: radio_config
    char                    key2_name[OVSDB_TABLE_KEY_SIZE];
    schema_from_json_t      *from_json;
    schema_to_json_t        *to_json;
    schema_mark_changed_t   *mark_changed;
    ovsdb_update_monitor_t  monitor;
    char                    **columns; // all schema columns, null term
    bool                    partial_update;
    ovsdb_update_cbk_t      *monitor_callback;
    void                    (*table_callback)(ovsdb_update_monitor_t *self, void *old_rec, void *record);
    // cache:
    void                    (*cache_callback)(ovsdb_update_monitor_t *self,
                                void *old_rec, void *record, struct ovsdb_cache_row *row);
    int                     row_size;
    ds_tree_t               rows; // uuid key
    ds_tree_t               rows_k; // primary key
    ds_tree_t               rows_k2; // alternate key2
} ovsdb_table_t;

// --- _ovsdb_cache_insert_row harness (OneWifi lib/ovsdb/ovsdb_cache.c) ---
typedef struct {
	const char *test_name;      // case name
	int         use_key;        // key_offset >= 0
	int         use_key2;       // key2_offset >= 0
	const char *key;            // literal key (used when key_fill == 0)
	int         key_fill;       // >0: key = key_fill x 'k'
	int         key2_fill;      // >0: key2 = key2_fill x 'z'
	int         uuid_empty;     // 1: empty uuid string
	int         expect_inserts; // expected ds_tree_insert calls
} ovsdb_cache_insert_row_test_case_t;

#define OCI_UUID_OFF   0
#define OCI_KEY_OFF    37
#define OCI_KEY2_OFF   293
#define OCI_SCHEMA_SZ  549
#define OCI_ROWBUF_SZ  (sizeof(ovsdb_cache_row_t) + OCI_SCHEMA_SZ + 64)
extern unsigned char oci_rowbuf[OCI_ROWBUF_SZ];
extern ovsdb_table_t oci_table;
extern int    oci_inserts;
extern size_t oci_last_key_len, oci_msg_len;
extern ovsdb_cache_insert_row_test_case_t ovsdb_cache_insert_row_suite[];

void construct_ovsdb_cache_insert_row_input(const ovsdb_cache_insert_row_test_case_t *tc);
int  test_ovsdb_cache_insert_row(const ovsdb_cache_insert_row_test_case_t *tc);
void run_all_tests_ovsdb_cache_insert_row(void);

// --- onewifi_ovsdb_cache_pre_fetch harness (OneWifi lib/ovsdb/ovsdb_cache.c) ---
typedef struct {
	const char *test_name;      // case name
	int         row_exists;     // find_row_by_key returns a row
	const char *result;         // JSON text tran_call_s returns (NULL = no result, "LONG" = built)
	int         fj_fail;        // from_json fails
	int         key_fill;       // >0: key = key_fill x 'k'
	int         expect_ret;     // expected return (0 / -1)
} ovsdb_cache_pre_fetch_test_case_t;

#define OCP_POOL_SZ  (OCI_ROWBUF_SZ + 256)
extern unsigned char ocp_rowpool[OCP_POOL_SZ];
extern size_t      ocp_calloc_size;
extern int         ocp_row_exists, ocp_freed, ocp_fj_fail;
extern size_t      ocp_perr_len;
extern const char *ocp_result_json;
extern char        ocp_key[256];
extern size_t      ocp_key_len;
extern ovsdb_table_t ocp_table;
extern ovsdb_cache_pre_fetch_test_case_t ovsdb_cache_pre_fetch_suite[];

void construct_ovsdb_cache_pre_fetch_input(const ovsdb_cache_pre_fetch_test_case_t *tc);
int  test_ovsdb_cache_pre_fetch(const ovsdb_cache_pre_fetch_test_case_t *tc);
void run_all_tests_ovsdb_cache_pre_fetch(void);

// --- onewifi_ovsdb_cache_update_cb harness (OneWifi lib/ovsdb/ovsdb_cache.c) ---
#define OCU_UPD_OFF    0
#define OCU_UUID_OFF   4
#define OCU_VER_OFF    41
#define OCU_KEY_OFF    78
#define OCU_SCHEMA_SZ  142
#define OCU_SLOT_SZ    (sizeof(ovsdb_cache_row_t) + OCU_SCHEMA_SZ + 64)
typedef struct {
	const char *test_name;      // case name
	int         mon_type;       // OVSDB_UPDATE_* (or invalid)
	int         has_data;       // mon_data = &table (0 = NULL)
	int         table_ok;       // mon_table matches table_name
	int         cached;         // ds_tree_find returns the cached row
	const char *json_new;       // mon_json_new text ("LONG" = 255-char if_name)
	const char *json_old;       // mon_json_old text
	int         expect_cb;      // cache_callback calls
	int         expect_insert;  // row inserted
	int         expect_free;    // free() calls
} ovsdb_cache_update_cb_test_case_t;

extern unsigned char ocu_pool[2][OCU_SLOT_SZ];
extern int    ocu_cached, ocu_removes, ocu_freed, ocu_cbs, ocu_marks;
extern char   ocu_uuid[64];
extern size_t ocu_uuid_len;
extern ovsdb_table_t ocu_table;
extern ovsdb_update_monitor_t ocu_mon;
extern ovsdb_cache_update_cb_test_case_t ovsdb_cache_update_cb_suite[];

void construct_ovsdb_cache_update_cb_input(const ovsdb_cache_update_cb_test_case_t *tc);
int  test_ovsdb_cache_update_cb(const ovsdb_cache_update_cb_test_case_t *tc);
void run_all_tests_ovsdb_cache_update_cb(void);

// --- onewifi_ovsdb_cache_upsert harness (OneWifi lib/ovsdb/ovsdb_cache.c) ---
#define OCS_SLOT_SZ  OCU_SLOT_SZ
typedef struct {
	const char *test_name;      // case name
	int         no_key;         // key_offset = -1
	int         cached;         // find_row_by_key returns the cached row
	const char *rec_name;       // if_name in the caller record (NULL = 63 x 'n')
	int         tj_fail;        // to_json fails
	int         upsert_ok;      // onewifi_ovsdb_sync_upsert succeeds
	int         db_uuid_fill;   // >0: uuid from db = db_uuid_fill x 'u'
	int         expect_ret;     // expected return (0 / -1)
	int         expect_upserts; // db upsert calls
	int         expect_insert;  // new row inserted
} ovsdb_cache_upsert_test_case_t;

extern unsigned char ocs_pool[2][OCS_SLOT_SZ];
extern char   ocs_rec[OCU_SCHEMA_SZ + 64];
extern int    ocs_cached, ocs_upserts, ocs_asked_uuid, ocs_upsert_ok, ocs_tj_fail;
extern size_t ocs_perr_len;
extern char   ocs_db_uuid[256];
extern ovsdb_table_t ocs_table;
extern ovsdb_cache_upsert_test_case_t ovsdb_cache_upsert_suite[];

void construct_ovsdb_cache_upsert_input(const ovsdb_cache_upsert_test_case_t *tc);
int  test_ovsdb_cache_upsert(const ovsdb_cache_upsert_test_case_t *tc);
void run_all_tests_ovsdb_cache_upsert(void);

// --- onewifi_ovsdb_method_send_s harness (OneWifi lib/ovsdb/ovsdb_sync.c) ---
typedef enum { MT_ECHO, MT_MONITOR, MT_TRANS } ovsdb_mt_t;   // lib/ovsdb/ovsdb.h
typedef struct {
	const char *test_name;      // case name
	int         mt;             // ovsdb_mt_t value (0 echo, 1 monitor, 2 transact, other = unknown)
	const char *reply;          // JSON reply from ovsdb_write_s (NULL = none, "ERR<n>" = error with n-char message)
	int         sock_fill;      // >0: socket path = sock_fill x 's'
	int         expect_result;  // a result object is returned
	int         expect_writes;  // ovsdb_write_s calls
} ovsdb_method_send_s_test_case_t;

extern char        oms_sock[256];
extern size_t      oms_sock_len, oms_sock_seen;
extern int         oms_writes;
extern const char *oms_reply;
extern ovsdb_method_send_s_test_case_t ovsdb_method_send_s_suite[];

void construct_ovsdb_method_send_s_input(const ovsdb_method_send_s_test_case_t *tc);
int  test_ovsdb_method_send_s(const ovsdb_method_send_s_test_case_t *tc);
void run_all_tests_ovsdb_method_send_s(void);

// --- onewifi_ovsdb_sync_update_one_get_uuid harness (OneWifi lib/ovsdb/ovsdb_sync_api.c) ---
typedef struct {
	const char *test_name;      // case name
	int         where_len;      // encoded JSON length of where (-1 = NULL)
	int         select_count;   // ovsdb_sync_get_uuid_and_count result
	int         update_count;   // onewifi_ovsdb_sync_update_where result
	int         uuid_fill;      // >0: uuid from db = uuid_fill x 'u'
	int         table_fill;     // >0: table name = table_fill x 't'
	int         expect_ret;     // expected return
	int         expect_updates; // update_where calls
} ovsdb_sync_update_one_get_uuid_test_case_t;

extern char   osu_table[256];
extern size_t osu_table_len, osu_table_seen;
extern unsigned char osu_uuidbuf[64];
extern int    osu_select_count, osu_update_count, osu_updates;
extern char   osu_db_uuid[256];
extern ovsdb_sync_update_one_get_uuid_test_case_t ovsdb_sync_update_one_get_uuid_suite[];

void construct_ovsdb_sync_update_one_get_uuid_input(const ovsdb_sync_update_one_get_uuid_test_case_t *tc);
int  test_ovsdb_sync_update_one_get_uuid(const ovsdb_sync_update_one_get_uuid_test_case_t *tc);
void run_all_tests_ovsdb_sync_update_one_get_uuid(void);

// --- onewifi_ovsdb_sync_update_where harness (OneWifi lib/ovsdb/ovsdb_sync_api.c) ---
typedef struct {
	const char *test_name;      // case name
	int         where_len;      // encoded JSON length of where (-1 = NULL)
	const char *result;         // JSON result from tran_call_s (NULL = none)
	int         table_fill;     // >0: table name = table_fill x 't'
	int         expect_ret;     // expected return (count / -1)
} ovsdb_sync_update_where_test_case_t;

extern char        osw_table[256];
extern size_t      osw_table_len, osw_table_seen;
extern int         osw_calls;
extern const char *osw_result;
extern ovsdb_sync_update_where_test_case_t ovsdb_sync_update_where_suite[];

void construct_ovsdb_sync_update_where_input(const ovsdb_sync_update_where_test_case_t *tc);
int  test_ovsdb_sync_update_where(const ovsdb_sync_update_where_test_case_t *tc);
void run_all_tests_ovsdb_sync_update_where(void);

// --- onewifi_ovsdb_sync_upsert_where harness (OneWifi lib/ovsdb/ovsdb_sync_api.c) ---
typedef struct {
	const char *test_name;      // case name
	int         where_len;      // encoded JSON length of where (-1 = NULL)
	int         update_count;   // onewifi_ovsdb_sync_update_one_get_uuid result
	int         insert_ok;      // onewifi_ovsdb_sync_insert succeeds
	int         use_uuid;       // pass a uuid output (0 = NULL)
	int         uuid_fill;      // >0: uuid from db = uuid_fill x 'u'
	int         table_fill;     // >0: table name = table_fill x 't'
	int         expect_ret;     // expected return (1 = true)
	int         expect_inserts; // insert calls
} ovsdb_sync_upsert_where_test_case_t;

extern char   osp_table[256];
extern size_t osp_table_len, osp_table_seen;
extern unsigned char osp_uuidbuf[64];
extern int    osp_update_count, osp_insert_ok, osp_updates, osp_inserts;
extern char   osp_db_uuid[256];
extern ovsdb_sync_upsert_where_test_case_t ovsdb_sync_upsert_where_suite[];

void construct_ovsdb_sync_upsert_where_input(const ovsdb_sync_upsert_where_test_case_t *tc);
int  test_ovsdb_sync_upsert_where(const ovsdb_sync_upsert_where_test_case_t *tc);
void run_all_tests_ovsdb_sync_upsert_where(void);

// --- onewifi_ovsdb_table_filter_row harness (OneWifi lib/ovsdb/ovsdb_table.c) ---
#define OTF_MAX_COLS  63
#define OTF_STR_SZ    2048
typedef struct {
	const char *test_name;      // case name
	int         has_row;        // pass a row (0 = NULL)
	int         cols_null;      // pass columns = NULL
	const char *op;             // columns[0] ("+", "-", other; NULL = empty argv)
	int         ncols;          // column names after the op
	int         col_len;        // >0: each column = col_len x 'c'
	int         expect_which;   // '+', '-' or 0 (no filter ran)
	int         expect_argc;    // argc given to the filter (-1 = not called)
} ovsdb_table_filter_row_test_case_t;

extern char  otf_strs[OTF_MAX_COLS][OTF_STR_SZ];
extern char *otf_argv[OTF_MAX_COLS + 1];
extern int   otf_ncols;
extern int   otf_which, otf_argc;
extern size_t otf_str_len;
extern ovsdb_table_filter_row_test_case_t ovsdb_table_filter_row_suite[];

void construct_ovsdb_table_filter_row_input(const ovsdb_table_filter_row_test_case_t *tc);
int  test_ovsdb_table_filter_row(const ovsdb_table_filter_row_test_case_t *tc);
void run_all_tests_ovsdb_table_filter_row(void);

// --- onewifi_ovsdb_table_from_json harness (OneWifi lib/ovsdb/ovsdb_table.c) ---
typedef struct {
	const char *test_name;      // case name
	const char *json;           // row JSON (NULL = jrow NULL, "LONG" = long values)
	int         expect_ret;     // expected return (1 = true)
} ovsdb_table_from_json_test_case_t;

extern char   otj_rec[OCU_SCHEMA_SZ + 64];
extern ovsdb_table_t otj_table;
extern size_t otj_perr_len;
extern int    otj_calls;
extern ovsdb_table_from_json_test_case_t ovsdb_table_from_json_suite[];

void construct_ovsdb_table_from_json_input(const ovsdb_table_from_json_test_case_t *tc);
int  test_ovsdb_table_from_json(const ovsdb_table_from_json_test_case_t *tc);
void run_all_tests_ovsdb_table_from_json(void);

// --- onewifi_ovsdb_table_monitor_columns harness (OneWifi lib/ovsdb/ovsdb_table.c) ---
#define OTM_MAX_COLS  63
#define OTM_STR_SZ    2048
typedef struct {
	const char *test_name;      // case name
	int         cols_null;      // columns = NULL
	int         kind;           // 1 = schema cols, 2 = {_version, if_name}, 3 = col_len x 'c'
	int         ncols;          // requested columns
	int         col_len;        // kind 3: length of each column
	int         monitor_ok;     // monitor API succeeds
	int         expect_ret;     // expected return (1 = true)
	int         expect_which;   // 'A' = update_monitor (ALL), 'C' = update_monitor_ex
	int         expect_partial; // table->partial_update after the call
	int         expect_colc;    // colc given to update_monitor_ex
} ovsdb_table_monitor_columns_test_case_t;

extern char  otm_strs[OTM_MAX_COLS][OTM_STR_SZ];
extern char *otm_argv[OTM_MAX_COLS + 1];
extern char  otm_schema_strs[4][16];
extern char *otm_schema_argv[8];
extern int   otm_ncols, otm_which, otm_colc, otm_monitor_ok;
extern size_t otm_tmp_len;
extern ovsdb_table_t otm_table;
extern ovsdb_table_monitor_columns_test_case_t ovsdb_table_monitor_columns_suite[];

void construct_ovsdb_table_monitor_columns_input(const ovsdb_table_monitor_columns_test_case_t *tc);
int  test_ovsdb_table_monitor_columns(const ovsdb_table_monitor_columns_test_case_t *tc);
void run_all_tests_ovsdb_table_monitor_columns(void);

// --- onewifi_ovsdb_table_monitor_filter harness (OneWifi lib/ovsdb/ovsdb_table.c) ---
#define OTF2_MAX  63
typedef struct {
	const char *test_name;      // case name
	int         schema_n;       // number of schema columns in table->columns
	int         filter_null;    // filter = NULL
	const char *filter;         // space-separated filter argv (NULL = empty argv {NULL}, "EMPTYOP" = {""})
	int         expect_null;    // monitor_columns got columns == NULL
	int         expect_count;   // columns given to monitor_columns
	int         expect_version; // "_version" among them
} ovsdb_table_monitor_filter_test_case_t;

extern char  otf2_schema_strs[OTF2_MAX][16];
extern char *otf2_schema_argv[OTF2_MAX + 1];
extern char  otf2_filter_strs[OTF2_MAX][16];
extern char *otf2_filter_argv[OTF2_MAX + 1];
extern int   otf2_schema_n, otf2_filter_n;
extern int   otf2_called, otf2_got_null, otf2_got_count, otf2_has_version;
extern ovsdb_table_t otf2_table;
extern ovsdb_table_monitor_filter_test_case_t ovsdb_table_monitor_filter_suite[];

void construct_ovsdb_table_monitor_filter_input(const ovsdb_table_monitor_filter_test_case_t *tc);
int  test_ovsdb_table_monitor_filter(const ovsdb_table_monitor_filter_test_case_t *tc);
void run_all_tests_ovsdb_table_monitor_filter(void);

// --- onewifi_ovsdb_table_to_json harness (OneWifi lib/ovsdb/ovsdb_table.c) ---
typedef struct {
	const char *test_name;      // case name
	int         kind;           // 0 empty record, 1 normal, 2 fields at full size
	int         fail;           // to_json fails
	int         expect_obj;     // a JSON object is returned
} ovsdb_table_to_json_test_case_t;

extern char   ott_rec[OCU_SCHEMA_SZ + 64];
extern ovsdb_table_t ott_table;
extern size_t ott_perr_len;
extern int    ott_calls, ott_fail;
extern ovsdb_table_to_json_test_case_t ovsdb_table_to_json_suite[];

void construct_ovsdb_table_to_json_input(const ovsdb_table_to_json_test_case_t *tc);
int  test_ovsdb_table_to_json(const ovsdb_table_to_json_test_case_t *tc);
void run_all_tests_ovsdb_table_to_json(void);

// --- onewifi_ovsdb_table_update_cb harness (OneWifi lib/ovsdb/ovsdb_table.c) ---
typedef struct {
	const char *test_name;      // case name
	int         mon_type;       // OVSDB_UPDATE_* (or invalid)
	int         has_data;       // mon_data = &table (0 = NULL)
	int         table_ok;       // mon_table matches table_name
	int         partial;        // table->partial_update
	const char *json_new;       // mon_json_new ("LONG" = 255-char if_name)
	const char *json_old;       // mon_json_old
	int         uuid_ok;        // mon_uuid matches the row uuid
	int         expect_cb;      // table_callback calls
	int         expect_marks;   // mark_changed calls
} ovsdb_table_update_cb_test_case_t;

extern int    otu_cbs, otu_marks, otu_last_type;
extern size_t otu_last_name_len;
extern char   otu_uuid[64];
extern size_t otu_uuid_len;
extern ovsdb_table_t otu_table;
extern ovsdb_update_monitor_t otu_mon;
extern ovsdb_table_update_cb_test_case_t ovsdb_table_update_cb_suite[];

void construct_ovsdb_table_update_cb_input(const ovsdb_table_update_cb_test_case_t *tc);
int  test_ovsdb_table_update_cb(const ovsdb_table_update_cb_test_case_t *tc);
void run_all_tests_ovsdb_table_update_cb(void);

// --- onewifi_ovsdb_tran_comment harness (OneWifi lib/ovsdb/ovsdb_method.c) ---
#define OTC_BUF_SZ  2048
typedef struct {
	const char *test_name;      // case name
	int         comment_null;   // ovsdb_comment = NULL
	int         comment_len;    // 2 = "em", else N x 'c'
	int         oper;           // ovsdb_tro_t value
	int         where_kind;     // 0 NULL, 1 one triple, 2 row not array, 3 non-string, 4 30 x 100-char
	int         expect_ret;     // expected return (1 = true)
	int         expect_appended;// comment op appended to js_array
} ovsdb_tran_comment_test_case_t;

extern char  otc_comment_buf[OTC_BUF_SZ];
extern char *ovsdb_comment;
extern ovsdb_tran_comment_test_case_t ovsdb_tran_comment_suite[];

void construct_ovsdb_tran_comment_input(const ovsdb_tran_comment_test_case_t *tc);
int  test_ovsdb_tran_comment(const ovsdb_tran_comment_test_case_t *tc);
void run_all_tests_ovsdb_tran_comment(void);

// --- onewifi_ovsdb_update_changed harness (OneWifi lib/ovsdb/ovsdb_update.c) ---
#define OUC_SLOT_SZ   256     // = sizeof(v_old) / sizeof(v_new)
#define OUC_SLOT_PAD  64
#define OUC_STR_SZ    64
typedef struct {
	const char *test_name;      // case name
	int         mon_type;       // OVSDB_UPDATE_* (or invalid)
	int         old_kind;       // 0 field absent in old, 1 in both, 2 missing in new, 3 array value
	int         val_len;        // string length / array elements
	int         expect_changed; // expected return
	int         expect_old;     // v_old length (-1 = any < 256)
	int         expect_new;     // v_new length (-1 = any < 256)
} ovsdb_update_changed_test_case_t;

extern char   oucg_slot[2][OUC_SLOT_SZ + OUC_SLOT_PAD];
extern size_t oucg_len[2];
extern int    oucg_next;
extern char   ouc_field[OUC_STR_SZ];
extern char   ouc_table[OUC_STR_SZ];
extern ovsdb_update_monitor_t ouc_mon;
extern ovsdb_update_changed_test_case_t ovsdb_update_changed_suite[];

void construct_ovsdb_update_changed_input(const ovsdb_update_changed_test_case_t *tc);
int  test_ovsdb_update_changed(const ovsdb_update_changed_test_case_t *tc);
void run_all_tests_ovsdb_update_changed(void);

// --- ovsdb_get_update_result_count_off harness (OneWifi lib/ovsdb/ovsdb_sync_api.c) ---
#define OGU_SLOT_SZ   8192    // = sizeof(dumps_static_buf)
#define OGU_ERR_SZ    256     // = sizeof(errstr)
#define OGU_SLOT_PAD  64
#define OGU_STR_SZ    64
typedef struct {
	const char *test_name;      // case name
	int         kind;           // result shape (see construct file)
	int         offset;         // offset argument
	int         expect_count;   // expected return
	int         expect_errlen;  // errstr length (-1 = errstr path not taken)
} ovsdb_get_update_result_count_off_test_case_t;

extern char   ogug_slot[OGU_SLOT_SZ + OGU_SLOT_PAD];
extern char   ogug_slot_err[OGU_ERR_SZ + OGU_SLOT_PAD];
extern size_t ogug_errstr_len;
extern int    ogug_calls;
extern char   ogu_table[OGU_STR_SZ];
extern char   ogu_oper[OGU_STR_SZ];
extern ovsdb_get_update_result_count_off_test_case_t ovsdb_get_update_result_count_off_suite[];

void construct_ovsdb_get_update_result_count_off_input(const ovsdb_get_update_result_count_off_test_case_t *tc);
int  test_ovsdb_get_update_result_count_off(const ovsdb_get_update_result_count_off_test_case_t *tc);
void run_all_tests_ovsdb_get_update_result_count_off(void);

// --- ovsdb_sync_get_uuid_and_count harness (OneWifi lib/ovsdb/ovsdb_sync_api.c) ---
#define OGC_SLOT_SZ   128     // = WHERE_STR_SIZE (where_str)
#define OGC_SLOT_PAD  64
#define OGC_STR_SZ    64
typedef struct {
	const char *test_name;      // case name
	int         uuid_null;      // uuid argument NULL
	int         rows;           // select result shape (-1 NULL, see construct file)
	int         where_len;      // -1 where NULL, 0 small, else dump length
	int         expect_count;   // expected return
	int         expect_uuid_len;// uuid length after call (-1 = uuid NULL)
	int         expect_where;   // where_str length (-1 = any < 128)
} ovsdb_sync_get_uuid_and_count_test_case_t;

extern char   ogc_slot[OGC_SLOT_SZ + OGC_SLOT_PAD];
extern size_t ogc_where_len;
extern void  *ogc_rows;
extern char   ogc_uuid_buf[sizeof(ovs_uuid_t) + 64];
extern char   ogc_table[OGC_STR_SZ];
extern char   ogc_sock[OGC_STR_SZ];
extern ovsdb_sync_get_uuid_and_count_test_case_t ovsdb_sync_get_uuid_and_count_suite[];

void construct_ovsdb_sync_get_uuid_and_count_input(const ovsdb_sync_get_uuid_and_count_test_case_t *tc);
int  test_ovsdb_sync_get_uuid_and_count(const ovsdb_sync_get_uuid_and_count_test_case_t *tc);
void run_all_tests_ovsdb_sync_get_uuid_and_count(void);

// --- pgctrl_command harness (OneWifi lib/pktgen/pktgen.c) ---
#define PGC_SLOT_SZ   512     // = BUF_LEN_MAX (cmd)
#define PGC_SLOT_PAD  64
#define PGC_STR_SZ    4096
typedef struct {
	const char *test_name;      // case name
	int         kind;           // 0 "start\n", 1 "%s", 2 "add_device %s@%d\n"
	int         arg_len;        // %s argument length
	int         path_len;       // 0 = pgctrl path, else N x 'p'
	int         open_fail;      // open() fails
	int         write_fail;     // write() fails
	int         expect_ret;     // expected return
	int         expect_out;     // bytes written
} pgctrl_command_test_case_t;

extern char   pgc_slot[PGC_SLOT_SZ + PGC_SLOT_PAD];
extern char   pgc_out[PGC_SLOT_SZ + PGC_SLOT_PAD];
extern size_t pgc_out_len, pgc_open_path_len;
extern int    pgc_vs_ret, pgc_open_fail, pgc_write_fail;
extern char   pgc_file[PGC_STR_SZ];
extern char   pgc_fmt[PGC_STR_SZ];
extern char   pgc_arg[PGC_STR_SZ];
extern pgctrl_command_test_case_t pgctrl_command_suite[];

void construct_pgctrl_command_input(const pgctrl_command_test_case_t *tc);
int  test_pgctrl_command(const pgctrl_command_test_case_t *tc);
void run_all_tests_pgctrl_command(void);

// --- onewifi_pktgen_is_running harness (OneWifi lib/pktgen/pktgen.c) ---
#define PGR_SLOT_SZ   512     // = BUF_LEN_MAX (str, run_if)
#define PGR_SLOT_PAD  64
#define PGR_DATA_SZ   8192
typedef struct {
	const char *test_name;      // case name
	int         kind;           // file content shape (see construct file)
	int         if_len;         // kind 5: interface name length
	int         fopen_fail;     // fopen() fails
	int         expect_ret;     // expected return
	int         expect_if;      // run_if length
} pktgen_is_running_test_case_t;

extern char   pgr_data[PGR_DATA_SZ];
extern size_t pgr_data_len;
extern int    pgr_fopen_fail;
extern char   pgr_slot_str[PGR_SLOT_SZ + PGR_SLOT_PAD];
extern char   pgr_slot_if[PGR_SLOT_SZ + PGR_SLOT_PAD];
extern size_t pgr_str_len, pgr_if_len;
extern pktgen_is_running_test_case_t pktgen_is_running_suite[];

void construct_pktgen_is_running_input(const pktgen_is_running_test_case_t *tc);
int  test_pktgen_is_running(const pktgen_is_running_test_case_t *tc);
void run_all_tests_pktgen_is_running(void);

// --- pktgen_configure harness (OneWifi lib/pktgen/pktgen.c) ---
#define PGF_SLOT_SZ   4096    // = PATH_MAX (dev_path)
#define PGF_SLOT_PAD  64
#define PGF_STR_SZ    16384
typedef struct {
	const char *test_name;      // case name
	int         if_len;         // 5 = "wlan0", else N x 'i'
	int         mac_len;        // 17 = real MAC, else N x 'm'
	int         fail_at;        // pgctrl call number that fails (0 = none)
	int         expect_ret;     // expected return
	int         expect_calls;   // pgctrl_command calls
	int         expect_dev;     // dev_path length (0 = not built)
} pktgen_configure_test_case_t;

extern char   pgf_slot[PGF_SLOT_SZ + PGF_SLOT_PAD];
extern size_t pgf_dev_len, pgf_max_path;
extern int    pgf_calls, pgf_fail_at;
extern char   pgf_ifname[PGF_STR_SZ];
extern char   pgf_mac[PGF_STR_SZ];
extern pktgen_configure_test_case_t pktgen_configure_suite[];

void construct_pktgen_configure_input(const pktgen_configure_test_case_t *tc);
int  test_pktgen_configure(const pktgen_configure_test_case_t *tc);
void run_all_tests_pktgen_configure(void);

// --- get_app_by_inst harness (OneWifi source/apps/wifi_apps_mgr.c) ---
typedef int wifi_app_inst_t;                 // enum of bit values (include/wifi_base.h)
typedef struct wifi_app wifi_app_t;          // opaque here
typedef struct wifi_apps_mgr {               // subset of source/apps/wifi_apps_mgr.h
	void       *ctrl;
	void       *apps_map;                   // hash_map_t * (defined later in this header)
} wifi_apps_mgr_t;
#define GAI_SLOT_SZ   32      // = sizeof(key_str)
#define GAI_SLOT_PAD  64
typedef struct {
	const char *test_name;      // case name
	int         inst;           // inst argument
	int         expect_found;   // an app is returned
	int         expect_key_len; // key_str length
} get_app_by_inst_test_case_t;

extern char   gai_slot[GAI_SLOT_SZ + GAI_SLOT_PAD];
extern char   gai_key_seen[64];
extern size_t gai_key_len;
extern char   gai_keys[4][32];
extern void  *gai_vals[4];
extern int    gai_nentries;
extern char   gai_mgr_buf[sizeof(wifi_apps_mgr_t) + 64];
extern get_app_by_inst_test_case_t get_app_by_inst_suite[];

void construct_get_app_by_inst_input(const get_app_by_inst_test_case_t *tc);
int  test_get_app_by_inst(const get_app_by_inst_test_case_t *tc);
void run_all_tests_get_app_by_inst(void);

// --- app_register harness (OneWifi source/apps/wifi_apps_mgr.c) ---
typedef char wifi_app_name_t[256];
typedef int (* wifi_app_init_fn_t)(wifi_app_t *app, unsigned int create_flag);
typedef struct {                             // source/apps/wifi_apps_mgr.h (fn types after init_fn as void *)
	wifi_app_inst_t inst;
	unsigned int create_flag;
	unsigned int reg_events_types;
	bool rfc;
	bool enable;
	wifi_app_name_t         desc;
	wifi_app_init_fn_t init_fn;
	void *event_fn;
	void *deinit_fn;
	void *mgmt_frame_hook_fn;
	void *update_fn;
} wifi_app_descriptor_t;
#include <sys/resource.h>
// --- csi analytics shared types (OneWifi source/apps/csi/wifi_csi_analytics.h) ---
#ifndef MAX_MACLIST_SIZE
#define MAX_MACLIST_SIZE 512
#define MAX_MAC_STR_SIZE 18
#endif
typedef struct bus_handle bus_handle_t;   // opaque (csi bus handlers)
typedef struct csi_analytics_info {
	int           pipe_read_fd;
	bool          is_read_oper_thread_enabled;
	unsigned int  csi_session_index;
	bool          is_csi_capture_enabled;
	pthread_mutex_t maclist_lock;
	char          sta_mac[MAX_MACLIST_SIZE];
	int           sta_maclist_sched_id;
	int           csi_analytics_enable_sched_id;
	void         *csi_analytics_map;       // hash_map_t *
} csi_analytics_info_t;

typedef struct { char interface_name[32]; int radio_index; } radio_interface_mapping_t;   // subset (easyconnect)
typedef struct { radio_interface_mapping_t radio_interface_map[8]; bool radio_presence[8]; } wifi_platform_property_t;   // +radio_presence for monitor_enable_instant_msmt
/* minimal em_config_t (policy scalars used by em_init); self-contained to avoid
 * ordering issues with the later radio_metrics_policies_t */
typedef struct {
	struct { int sta_count; } btm_steering_dslw_policy;
	struct { int sta_count; } local_steering_dslw_policy;
	struct { int radio_count; } radio_metrics_policies;
} em_config_t;

typedef struct { double last_score; double last_threshold; int score_log_timer_id; int last_service_state; int iteration_count; char ignite_service_status[32]; } ignite_lq_state_t;   // source/apps/linkquality/wifi_linkquality.h
struct wifi_app {                            // subset: desc first, ctrl last (as in source)
	wifi_app_descriptor_t desc;
	unsigned char         rest[512];        // lock, cond, queue, tid, handle, ... (not touched)
	unsigned char         handle[16];       // app->handle (used by em_init bus_open)
	struct {                                 // data.u.analytics (same layout as analytics_data_t)
		union {
			struct {
				unsigned int minutes_alive;
				unsigned int tick_demultiplexer;
				void        *sta_map;     // hash_map_t *
				struct rusage last_usage;
			} analytics;
			struct {                      // data.u.blaster (subset used by WiFiBlastClient / sample_blaster)
				struct _pktGenFrameCountSamples *frameCountSample;
				unsigned long blaster_start;
			} blaster;
			struct {                      // data.u.cac (subset used by cac_event_exec_timeout)
				void *assoc_req_map;      // hash_map_t *
				void *sta_map;            // hash_map_t *
			} cac;
			struct {                      // data.u.csi (subset used by process_csi / csi_start_fn)
				void *csi_sounding_mac_map;  // hash_map_t *
				int   num_current_sounding;
				struct { int (*csi_start_fn)(wifi_app_t *, int, unsigned char *, int); void (*csi_stop_fn)(wifi_app_t *, int, unsigned char *, int); } csi_fns;
			} csi;
			csi_analytics_info_t csi_analytics;   // data.u.csi_analytics (webconfig_hal_csi_data_apply)
			struct { em_config_t em_config; } em_data;   // data.u.em_data (em_init policy config)
			struct {                      // data.u.levl (subset used by levl functions)
				int max_num_csi_clients;
				int num_current_sounding;
				int sounding_duration;
				int publish_interval;
				void *probe_req_map;          // hash_map_t *
				void *curr_sounding_mac_map;  // hash_map_t *
				void *pending_mac_map;        // hash_map_t *
				struct wifi_app *csi_app;
				bool csi_event_subscribed;
				bool csi_over_fifo;
				int  csi_fd;
				int  paused;
				int  postpone_sched_handler_id;
				pthread_mutex_t lock;
				bool temperature_event_subscribed[3];   // [MAX_NUM_RADIOS] (literal: MAX_NUM_RADIOS is defined later in this header)
				bool lock_initialized;
				int  probe_collector_sched_handler_id;
				struct { int (*csi_start_fn)(void *, unsigned int, unsigned char *, int); int (*csi_stop_fn)(void *, unsigned int, unsigned char *, int); } csi_fns;   // csi_base_app_t (used by levl_init)
			} levl;
			struct { ignite_lq_state_t ignite; } linkquality;   // data.u.linkquality (subset: only .ignite, used by link_quality_init)
		} u;
	} data;
	struct { unsigned char handle[256]; } *ctrl;   // real: wifi_ctrl_t* (needs ->handle for easyconnect_init)
};

/* --- easyconnect_init harness globals (defined in construct_easyconnect_init.cpp) --- */
#define EC_PAD 64
extern int  ec_app_init_ret, ec_app_init_calls;
extern int  ec_bus_reg_ret,  ec_bus_reg_calls, ec_bus_reg_n;
extern char ec_elem0_name[128], ec_elem1_name[128];
extern void *ec_elem1_set_cb;
struct easyconnect_init_test_case { const char *test_name; int app_init_ret; int bus_reg_ret; int want_ret; int want_bus_calls; };
typedef struct easyconnect_init_test_case easyconnect_init_test_case_t;
extern easyconnect_init_test_case_t easyconnect_init_suite[];
void construct_easyconnect_init_input(const easyconnect_init_test_case_t *tc);
void run_all_tests_easyconnect_init(void);

/* --- em_get_radio_index_from_mac harness --- */
#define ERM_PAD 64
typedef struct { unsigned char bssid[6]; struct { struct { unsigned char mld_addr[6]; } common_info; } mld_info; } erm_bss_info_t;   // +mld_info for em_send_action_frame (135)
typedef struct { int radio_index; unsigned int vap_index; union { erm_bss_info_t bss_info; } u; } erm_vap_info_t;
typedef struct { unsigned int num_vaps; erm_vap_info_t vap_array[8]; } wifi_vap_info_map_t;
extern int  erm_num_radios;
extern char erm_mgr_buf[];
extern unsigned char erm_ruuid_buf[];
extern int  erm_vap_present[8];
extern wifi_vap_info_map_t erm_vap_maps[8];
extern int  erm_iface_count;
extern char erm_iface_name[8][32];
extern unsigned char erm_iface_mac[8][6];
struct em_gri_test_case { const char *test_name; int want_ret; };
typedef struct em_gri_test_case em_gri_test_case_t;
extern em_gri_test_case_t em_get_radio_index_from_mac_suite[];
void construct_em_get_radio_index_from_mac_input(const em_gri_test_case_t *tc);
void run_all_tests_em_get_radio_index_from_mac(void);

/* --- em_get_vap_index_from_bssid harness (reuses wifi_vap_info_map_t) --- */
#define EVB_PAD 64
extern int  evb_num_radios;
extern unsigned char evb_bssid_buf[];
extern int  evb_vap_present[8];
extern wifi_vap_info_map_t evb_vap_maps[8];
extern int  evb_mesh_vap[64];   /* evb_mesh_vap[vap_index] != 0 -> isVapSTAMesh true */
struct em_gvb_test_case { const char *test_name; int want_ret; };
typedef struct em_gvb_test_case em_gvb_test_case_t;
extern em_gvb_test_case_t em_get_vap_index_from_bssid_suite[];
void construct_em_get_vap_index_from_bssid_input(const em_gvb_test_case_t *tc);
void run_all_tests_em_get_vap_index_from_bssid(void);

/* --- em_match_radio_index_to_policy_index harness --- */
#define EMM_PAD 64
typedef struct { unsigned char ruid[6]; } emm_radio_policy_t;
typedef struct { int radio_count; emm_radio_policy_t radio_metrics_policy[8]; } radio_metrics_policies_t;
extern char emm_mgr_buf[];
extern char emm_pol_buf[];
extern int  emm_found_index, emm_grifm_calls;
struct em_mri_test_case { const char *test_name; int radio_index; int want_ret; };
typedef struct em_mri_test_case em_mri_test_case_t;
extern em_mri_test_case_t em_match_radio_index_to_policy_index_suite[];
void construct_em_match_radio_index_to_policy_index_input(const em_mri_test_case_t *tc);
void run_all_tests_em_match_radio_index_to_policy_index(void);

/* --- em_client_stats_store harness --- */
#ifndef MAX_NUM_VAP_PER_RADIO
#define MAX_NUM_VAP_PER_RADIO 8
#endif
#ifndef MAX_NUM_RADIOS
#define MAX_NUM_RADIOS 3
#endif
#define ECS_PAD 64
/* shared em_ap_metrics_report_cache: used by em_client_stats_store (117,
 * vap_index/sta_count/client_stats_map) and radio_chan_stats_response (123,
 * radio_metrics + ap_data[].ap_metrics). One global, one unified type. */
typedef struct { unsigned char bssid[6]; unsigned char channel_util; } em_cache_ap_metrics_t;   // subset of ap_metrics_t
typedef struct { int vap_index; em_cache_ap_metrics_t ap_metrics; int sta_count; void *client_stats_map; } ap_metrics_data_t;
typedef struct { unsigned char ruid[6]; unsigned char transmit, receive_self, receive_other, noise; } radio_metrics_t;
typedef struct { int radio_index; radio_metrics_t radio_metrics; ap_metrics_data_t ap_data[MAX_NUM_VAP_PER_RADIO]; } em_ap_radio_report_t;
typedef struct { em_ap_radio_report_t radio_report[MAX_NUM_RADIOS]; } em_ap_metrics_report_cache_t;
extern em_ap_metrics_report_cache_t em_ap_metrics_report_cache;
extern char ecs_dev3_buf[];
extern int  ecs_getvap_null;    /* 1 -> getVapInfo returns NULL */
extern int  ecs_prepopulate;    /* 1 -> pre-put an entry so the update path runs */
struct em_css_test_case { const char *test_name; unsigned int radio_index; unsigned int vap_index; int sta_cnt; int dev3_null; int getvap_null; int prepopulate; int want_ret; };
typedef struct em_css_test_case em_css_test_case_t;
extern em_css_test_case_t em_client_stats_store_suite[];
void construct_em_client_stats_store_input(const em_css_test_case_t *tc);
void run_all_tests_em_client_stats_store(void);
void ecs_store_reset(void);
void ecs_store_prepopulate(const char *key);

/* shared em stats-timestamp type defined after wifi_associated_dev3_t (see below) */

/* --- prepare_sta_lins_metrics_data harness --- */
#ifndef STA_MAX_BSS_ASSOCIATIONS
#define STA_MAX_BSS_ASSOCIATIONS 1
#endif
#define PSL_PAD 64
typedef struct { unsigned char bssid[6]; unsigned int time_delta, est_mac_rate_down, est_mac_rate_up, rcpi; } psl_link_data_t;
typedef struct { int num_bssid; psl_link_data_t assoc_sta_link_metrics_data[STA_MAX_BSS_ASSOCIATIONS]; } psl_link_t;
typedef struct { unsigned char bssid[6]; int last_data_downlink_rate, last_data_uplink_rate, utilization_receive, utilization_transmit; } psl_ext_data_t;
typedef struct { int num_bssid; psl_ext_data_t assoc_sta_ext_link_metrics_data[STA_MAX_BSS_ASSOCIATIONS]; } psl_ext_t;
typedef struct { int reason_code; unsigned char sta_mac[6]; } psl_err_t;
typedef struct { unsigned char sta_mac[6]; unsigned char client_type[32]; psl_link_t assoc_sta_link_metrics; psl_err_t error_code; psl_ext_t assoc_sta_ext_link_metrics; } per_sta_metrics_t;
typedef struct { unsigned char mac_addr[6]; unsigned char client_type[32]; } sta_client_info_t;   // mac_addr added for handle_sta_client_info (124)
extern char psl_data_buf[];
extern char psl_stats_buf[];
extern int  psl_getvap_null, psl_has_clitype;
struct em_psl_test_case { const char *test_name; int data_null; int stats_null; int getvap_null; int has_clitype; int last_update_nonzero; int want_ret; };
typedef struct em_psl_test_case em_psl_test_case_t;
extern em_psl_test_case_t prepare_sta_lins_metrics_data_suite[];
void construct_prepare_sta_lins_metrics_data_input(const em_psl_test_case_t *tc);
void run_all_tests_prepare_sta_lins_metrics_data(void);
void psl_set_clitype(const char *s);

#define APR_SLOT_SZ     32    // = sizeof(key_str)
#define APR_SLOT_PAD    64
#define APR_POOL_SLOTS  8
#define APR_POOL_PAD    64
typedef struct {
	const char *test_name;      // case name
	int         inst;           // descriptor->inst
	int         rfc;            // descriptor->rfc
	int         already;        // get_app_by_inst finds it
	int         malloc_fail;    // malloc returns NULL
	int         expect_key_len; // key put in the map (0 = none)
	int         expect_put;     // hash_map_put called
	int         expect_init;    // init_fn calls
} app_register_test_case_t;

extern char   apr_slot[APR_SLOT_SZ + APR_SLOT_PAD];
extern unsigned char apr_pool[APR_POOL_SLOTS][sizeof(wifi_app_t) + APR_POOL_PAD];
extern int    apr_pool_used, apr_malloc_fail, apr_already, apr_rfc_calls, apr_init_calls;
extern char   apr_key_seen[64];
extern size_t apr_key_len;
extern void  *apr_put_data;
extern char   apr_desc_buf[sizeof(wifi_app_descriptor_t) + 64];
extern char   apr_mgr_buf[sizeof(wifi_apps_mgr_t) + 64];
extern app_register_test_case_t app_register_suite[];

void construct_app_register_input(const app_register_test_case_t *tc);
int  test_app_register(const app_register_test_case_t *tc);
void run_all_tests_app_register(void);

// --- source/apps/analytics types (subsets, OneWifi include/wifi_base.h + wifi_analytics.h) ---
#include <sys/resource.h>
typedef struct {                                                    // subset of the HAL wifi_associated_dev3_t
	unsigned char cli_MACAddress[6];                                // first field in wifi_hal_ap.h
	int           cli_RSSI;
	bool          cli_MLDEnable;                                    // wifi_hal_generic.h
	unsigned long cli_LastDataDownlinkRate;                         // (fields below used by sample_blaster)
	unsigned long cli_LastDataUplinkRate;
	int           cli_SNR;
	unsigned int  cli_Retransmissions;
	unsigned int  cli_MaxDownlinkRate;
	unsigned int  cli_MaxUplinkRate;
	unsigned long cli_DataFramesSentAck;
	unsigned long cli_PacketsSent;
	unsigned long cli_DataFramesSentNoAck;
	char          cli_OperatingStandard[64];
	char          cli_OperatingChannelBandwidth[64];
} wifi_associated_dev3_t;
/* shared em stats-timestamp type (used by em_client_stats_store + prepare_sta_lins_metrics_data) */
typedef struct { wifi_associated_dev3_t associated_dev3; struct timespec last_update_time; } wifi_associated_dev3_timestamp_t;
typedef struct {
	unsigned int            good_rssi_time;
	unsigned int            bad_rssi_time;
	unsigned int            rapid_reconnects;
	wifi_associated_dev3_t  dev_stats;
	unsigned char           sta_mac[6];       // (used by sample_blaster)
	bool                    assoc_link;
} sta_data_t;

/* --- assoc_client_response harness (uses sta_data_t above) --- */
#ifndef BSS_MAX_NUM_STATIONS
#define BSS_MAX_NUM_STATIONS 100
#endif
#define ACR_PAD 64
typedef struct {
	sta_data_t   assoc_stats[BSS_MAX_NUM_STATIONS];
	bool         threshold_hit[BSS_MAX_NUM_STATIONS];
	unsigned int hit_count;
	size_t       stat_array_size;
} client_assoc_data_t;
typedef struct {
	client_assoc_data_t client_assoc_data[MAX_NUM_VAP_PER_RADIO];
	unsigned int assoc_stats_vap_presence_mask;
	unsigned int req_stats_vap_mask;
} client_assoc_stats_t;
extern client_assoc_stats_t client_assoc_stats[MAX_NUM_RADIOS];
extern char  acr_mgr_buf[];
extern char  acr_resp_buf[];
extern void *acr_stat_pointer;
extern int   acr_vap_array_index;   /* convert_vap_name_to_array_index returns this */
extern int   acr_convert_name_ok;   /* convert_vap_index_to_name success */
extern int   acr_ready_calls;
struct em_acr_test_case { const char *test_name; unsigned int radio_index; unsigned int vap_index; int stat_array_size; int convert_name_ok; int vap_array_index; int req_mask_set; int want_ret; int expect_crash; };
typedef struct em_acr_test_case em_acr_test_case_t;
extern em_acr_test_case_t assoc_client_response_suite[];
void construct_assoc_client_response_input(const em_acr_test_case_t *tc);
void run_all_tests_assoc_client_response(void);
typedef struct {
	unsigned int            primary_radio_channel;
	char                    channel_bandwidth[64];
	int                     NoiseFloor;
	int                     channelUtil;
	int                     channelInterference;
	int                     RadioActivityFactor;              // (used by printBlastMetricData)
	int                     CarrierSenseThreshold_Exceeded;
	char                    ChannelsInUse[64];
	char                    frequency_band[64];
	unsigned int            radio_Temperature;                // (used by radio_temperature_response)
} radio_data_t;
typedef struct {
	unsigned int    ap_index;
	mac_address_t   sta_mac;
} analytics_sta_info_t;
typedef struct {
	unsigned int    minutes_alive;
	unsigned int    tick_demultiplexer;
	void           *sta_map;          // hash_map_t *
	struct rusage   last_usage;
} analytics_data_t;

// --- device_statistics_info harness (OneWifi source/apps/analytics/wifi_analytics.c) ---
#define DS_TM_SZ        128   // tm_str
#define DS_MAC_SZ       32    // client_mac
#define DS_TMP_SZ       128   // temp_str
#define DS_STA_SZ       256   // sta_stats_str
#define DS_PAD          64
#define DS_MAX_STA      8
#define DS_NO_STATS_AP  99
typedef struct {
	const char *test_name;      // case name
	int         minutes;        // data->minutes_alive
	int         radios;         // getNumberRadios()
	int         fail_idx;       // radio whose stats fail (-1 = none)
	int         bw_len;         // channel_bandwidth length
	int         nsta;           // stations in sta_map
	int         no_stats;       // station 1 has no stats
	int         extreme;        // INT_MIN / UINT_MAX counters
	int         big_cpu;        // huge rusage delta
} device_statistics_info_test_case_t;

extern char   ds_slot_tm[DS_TM_SZ + DS_PAD];
extern char   ds_slot_mac[DS_MAC_SZ + DS_PAD];
extern char   ds_slot_128[DS_TMP_SZ + DS_PAD];
extern char   ds_slot_256[DS_STA_SZ + DS_PAD];
extern size_t ds_tm_len, ds_mac_len, ds_tmp_len, ds_sta_len;
extern int    ds_num_radios, ds_radio_fail_idx, ds_radio_calls, ds_nsta, ds_iter;
extern char   ds_bw[64];
extern sta_data_t ds_sta_data[DS_MAX_STA];
extern unsigned char ds_sta_pool[DS_MAX_STA][sizeof(analytics_sta_info_t) + DS_PAD];
extern char   ds_data_buf[sizeof(analytics_data_t) + DS_PAD];
extern device_statistics_info_test_case_t device_statistics_info_suite[];

void construct_device_statistics_info_input(const device_statistics_info_test_case_t *tc);
int  test_device_statistics_info(const device_statistics_info_test_case_t *tc);
void run_all_tests_device_statistics_info(void);

// --- analytics_event_hal_sta_conn_status harness (OneWifi source/apps/analytics/wifi_analytics.c) ---
typedef enum {                               // rdkb-halif-wifi include/wifi_hal_generic.h (same order)
	wifi_connection_status_disabled,
	wifi_connection_status_disconnected,
	wifi_connection_status_connected,
	wifi_connection_status_ap_not_found
} wifi_connection_status_t;
typedef struct {                             // subset of rdk_sta_data_t
	struct { int connect_status; int vap_index; } stats;
	struct { unsigned char bssid[6]; } bss_info;
} rdk_sta_data_t;
#define SCS_SLOT_SZ  128     // = sizeof(temp_str)
#define SCS_PAD      64
typedef struct {
	const char *test_name;      // case name
	int         arg_null;       // arg = NULL
	int         status;         // stats.connect_status
	int         vap_index;      // stats.vap_index
	int         expect_ret;     // expected return
	int         expect_calls;   // snprintf calls
	int         expect_len;     // temp_str length
} analytics_event_hal_sta_conn_status_test_case_t;

extern char   scs_slot[SCS_SLOT_SZ + SCS_PAD];
extern size_t scs_len;
extern int    scs_calls;
extern char   scs_arg_buf[sizeof(rdk_sta_data_t) + SCS_PAD];
extern analytics_event_hal_sta_conn_status_test_case_t analytics_event_hal_sta_conn_status_suite[];

void construct_analytics_event_hal_sta_conn_status_input(const analytics_event_hal_sta_conn_status_test_case_t *tc);
int  test_analytics_event_hal_sta_conn_status(const analytics_event_hal_sta_conn_status_test_case_t *tc);
void run_all_tests_analytics_event_hal_sta_conn_status(void);

// --- analytics_event_hal_assoc_device harness (OneWifi source/apps/analytics/wifi_analytics.c) ---
typedef struct {                             // leading fields of include/wifi_base.h assoc_dev_data_t
	int ap_index;
	wifi_associated_dev3_t dev_stats;
	int reason;
	bool association_link;                   // (used by csi_start_fn)
	unsigned char link_address[6];
} assoc_dev_data_t;
#define AAD_MAC_SZ      32    // = sizeof(client_mac)
#define AAD_TMP_SZ      64    // = sizeof(temp_str)
#define AAD_PAD         64
#define AAD_POOL_SLOTS  4
typedef struct {
	const char *test_name;      // case name
	int         ap_index;       // assoc_data->ap_index
	int         existing;       // station already in sta_map
	int         malloc_fail;    // malloc returns NULL
	int         mac_hi;         // MAC aa:ab:.. (hex letters)
	int         expect_put;     // a new station is put in the map
	int         expect_tmp_len; // temp_str length
} analytics_event_hal_assoc_device_test_case_t;

extern char   aad_slot_mac[AAD_MAC_SZ + AAD_PAD];
extern char   aad_slot_tmp[AAD_TMP_SZ + AAD_PAD];
extern size_t aad_tmp_len;
extern unsigned char aad_pool[AAD_POOL_SLOTS][sizeof(analytics_sta_info_t) + AAD_PAD];
extern int    aad_pool_used, aad_malloc_fail, aad_get_calls;
extern void  *aad_existing;
extern char   aad_existing_key[32];
extern char   aad_put_key[64];
extern void  *aad_put_data;
extern char   aad_arg_buf[sizeof(assoc_dev_data_t) + AAD_PAD];
extern char   aad_apps_buf[sizeof(wifi_app_t) + AAD_PAD];
extern analytics_event_hal_assoc_device_test_case_t analytics_event_hal_assoc_device_suite[];

void construct_analytics_event_hal_assoc_device_input(const analytics_event_hal_assoc_device_test_case_t *tc);
int  test_analytics_event_hal_assoc_device(const analytics_event_hal_assoc_device_test_case_t *tc);
void run_all_tests_analytics_event_hal_assoc_device(void);

// --- analytics_event_hal_disassoc_device harness (OneWifi source/apps/analytics/wifi_analytics.c) ---
#define ADD_MAC_SZ   32    // = sizeof(client_mac)
#define ADD_TMP_SZ   64    // = sizeof(temp_str)
#define ADD_PAD      64
typedef struct {
	const char *test_name;      // case name
	int         ap_index;       // assoc_data->ap_index
	int         reason;         // assoc_data->reason
	int         known;          // station is in sta_map
	int         rm_null;        // hash_map_remove returns NULL
	int         mac_hi;         // MAC aa:ab:.. (hex letters)
	int         expect_removes; // hash_map_remove calls
	int         expect_freed;   // free() called
	int         expect_tmp_len; // temp_str length
} analytics_event_hal_disassoc_device_test_case_t;

extern char   add_slot_mac[ADD_MAC_SZ + ADD_PAD];
extern char   add_slot_tmp[ADD_TMP_SZ + ADD_PAD];
extern size_t add_tmp_len;
extern void  *add_entry, *add_freed;
extern char   add_entry_key[32];
extern char   add_key_seen[64];
extern int    add_remove_calls, add_remove_null;
extern char   add_arg_buf[sizeof(assoc_dev_data_t) + ADD_PAD];
extern char   add_apps_buf[sizeof(wifi_app_t) + ADD_PAD];
extern analytics_event_hal_disassoc_device_test_case_t analytics_event_hal_disassoc_device_suite[];

void construct_analytics_event_hal_disassoc_device_input(const analytics_event_hal_disassoc_device_test_case_t *tc);
int  test_analytics_event_hal_disassoc_device(const analytics_event_hal_disassoc_device_test_case_t *tc);
void run_all_tests_analytics_event_hal_disassoc_device(void);

// --- analytics_event_hal_scan_results harness (OneWifi source/apps/analytics/wifi_analytics.c) ---
typedef struct {                             // include/wifi_base.h (bss[] not used here)
	unsigned int  radio_index;
	unsigned char bss_placeholder[64];      // wifi_bss_info_t bss[MAX_SCANNED_VAPS]
	unsigned int  num;
} scan_results_t;
#define ASR_SLOT_SZ  128     // = sizeof(str)
#define ASR_PAD      64
typedef struct {
	const char  *test_name;     // case name
	int          arg_null;      // arg = NULL
	unsigned int radio_index;   // results->radio_index
	unsigned int num;           // results->num
	int          expect_ret;    // expected return
	int          expect_calls;  // snprintf calls
	int          expect_len;    // str length
} analytics_event_hal_scan_results_test_case_t;

extern char   asr_slot[ASR_SLOT_SZ + ASR_PAD];
extern size_t asr_len;
extern int    asr_calls;
extern char   asr_arg_buf[sizeof(scan_results_t) + ASR_PAD];
extern analytics_event_hal_scan_results_test_case_t analytics_event_hal_scan_results_suite[];

void construct_analytics_event_hal_scan_results_input(const analytics_event_hal_scan_results_test_case_t *tc);
int  test_analytics_event_hal_scan_results(const analytics_event_hal_scan_results_test_case_t *tc);
void run_all_tests_analytics_event_hal_scan_results(void);

// --- analytics_event_hal_channel_change harness (OneWifi source/apps/analytics/wifi_analytics.c) ---
typedef enum {                               // rdkb-halif-wifi wifi_hal_generic.h
	WIFI_EVENT_CHANNELS_CHANGED,
	WIFI_EVENT_DFS_RADAR_DETECTED
} wifi_chan_eventType_t;
typedef enum {                               // rdkb-halif-wifi wifi_hal_radio.h
	WIFI_EVENT_RADAR_DETECTED,
	WIFI_EVENT_RADAR_CAC_FINISHED,
	WIFI_EVENT_RADAR_CAC_ABORTED,
	WIFI_EVENT_RADAR_NOP_FINISHED,
	WIFI_EVENT_RADAR_PRE_CAC_EXPIRED,
	WIFI_EVENT_RADAR_CAC_STARTED
} wifi_radar_eventType_t;
typedef struct {                             // rdk-wifi-hal wifi_hal_rdk_framework.h
	unsigned int           radioIndex;       // wifi_radio_index_t
	wifi_chan_eventType_t  event;
	wifi_radar_eventType_t sub_event;
	unsigned int           channel;
	int                    channelWidth;     // wifi_channelBandwidth_t
	unsigned int           op_class;
} __attribute__((__packed__)) wifi_channel_change_event_t;
#define ACC_SLOT_SZ  128     // = sizeof(desc)
#define ACC_PAD      64
typedef struct {
	const char  *test_name;     // case name
	int          event;         // ch->event
	unsigned int sub_event;     // ch->sub_event
	unsigned int channel;       // ch->channel
	int          bw;            // ch->channelWidth
	unsigned int radio;         // ch->radioIndex
	const char  *expect_prefix; // desc must start with this
} analytics_event_hal_channel_change_test_case_t;

extern char   acc_slot[ACC_SLOT_SZ + ACC_PAD];
extern size_t acc_len;
extern int    acc_calls;
extern char   acc_arg_buf[sizeof(wifi_channel_change_event_t) + ACC_PAD];
extern analytics_event_hal_channel_change_test_case_t analytics_event_hal_channel_change_suite[];

void construct_analytics_event_hal_channel_change_input(const analytics_event_hal_channel_change_test_case_t *tc);
int  test_analytics_event_hal_channel_change(const analytics_event_hal_channel_change_test_case_t *tc);
void run_all_tests_analytics_event_hal_channel_change(void);

// --- analytics_event_hal_potential_misconfiguration harness (OneWifi source/apps/analytics/wifi_analytics.c) ---
typedef struct {                             // source/apps/levl/wifi_levl.h
	unsigned int    max_probe_ttl_cnt;
	char            mac_str[18];         // mac_addr_str_t (typedef appears later in this file)
} __attribute__((__packed__)) probe_ttl_data_t;
#define APM_SLOT_SZ  128     // = sizeof(temp_str)
#define APM_PAD      64
typedef struct {
	const char  *test_name;     // case name
	const char  *mac_str;       // ttl_data->mac_str
	unsigned int count;         // ttl_data->max_probe_ttl_cnt
	int          expect_len;    // temp_str length
} analytics_event_hal_potential_misconfiguration_test_case_t;

extern char   apm_slot[APM_SLOT_SZ + APM_PAD];
extern size_t apm_len;
extern char   apm_arg_buf[sizeof(probe_ttl_data_t) + APM_PAD];
extern analytics_event_hal_potential_misconfiguration_test_case_t analytics_event_hal_potential_misconfiguration_suite[];

void construct_analytics_event_hal_potential_misconfiguration_input(const analytics_event_hal_potential_misconfiguration_test_case_t *tc);
int  test_analytics_event_hal_potential_misconfiguration(const analytics_event_hal_potential_misconfiguration_test_case_t *tc);
void run_all_tests_analytics_event_hal_potential_misconfiguration(void);

// --- analytics_event_wpa3_rfc harness (OneWifi source/apps/analytics/wifi_analytics.c) ---
#define AWR_SLOT_SZ  32      // = sizeof(str)
#define AWR_PAD      64
typedef struct {
	const char *test_name;      // case name
	bool        rfc;            // *(bool *)arg
	const char *expect;         // expected str
} analytics_event_wpa3_rfc_test_case_t;

extern char   awr_slot[AWR_SLOT_SZ + AWR_PAD];
extern size_t awr_len;
extern char   awr_arg_buf[sizeof(bool) + AWR_PAD];
extern analytics_event_wpa3_rfc_test_case_t analytics_event_wpa3_rfc_suite[];

void construct_analytics_event_wpa3_rfc_input(const analytics_event_wpa3_rfc_test_case_t *tc);
int  test_analytics_event_wpa3_rfc(const analytics_event_wpa3_rfc_test_case_t *tc);
void run_all_tests_analytics_event_wpa3_rfc(void);

// --- analytics_event_sta_connect_in_progress harness (OneWifi source/apps/analytics/wifi_analytics.c) ---
typedef struct {                             // subset of HAL wifi_bss_info_t (bssid first, ssid, rssi, ...)
	unsigned char bssid[6];                  // bssid_t
	char          ssid[33];                  // ssid_t
	int           rssi;
	unsigned short caps;
	unsigned int  beacon_int;
	unsigned int  freq;
	unsigned char rest[54];                  // ie[], ie_len, ... snr (not touched)
} __attribute__((packed)) wifi_bss_info_t;
typedef struct scan_result {                 // source/core/services/vap_svc.h
	wifi_bss_info_t external_ap;
	int             radio_freq_band;         // wifi_freq_bands_t
	int             conn_attempt;            // connection_attempt_t
	unsigned int    conn_retry_attempt;
	unsigned int    vap_index;               // wifi_vap_index_t
} __attribute__((packed)) bss_candidate_t;
#define SCP_MAC_SZ   18      // = sizeof(bssid_str) (mac_addr_str_t)
#define SCP_TMP_SZ   512     // = sizeof(temp_str)
#define SCP_PAD      64
typedef struct {
	const char   *test_name;    // case name
	int           arg_null;     // arg = NULL
	unsigned char bssid0;       // first BSSID byte (others +1..+5)
	int           expect_ret;   // expected return
	const char   *expect;       // expected temp_str
} analytics_event_sta_connect_in_progress_test_case_t;

extern char   scp_slot_mac[SCP_MAC_SZ + SCP_PAD];
extern char   scp_slot_tmp[SCP_TMP_SZ + SCP_PAD];
extern size_t scp_tmp_len;
extern int    scp_mac_calls;
extern char   scp_arg_buf[sizeof(bss_candidate_t) + SCP_PAD];
extern analytics_event_sta_connect_in_progress_test_case_t analytics_event_sta_connect_in_progress_suite[];

void construct_analytics_event_sta_connect_in_progress_input(const analytics_event_sta_connect_in_progress_test_case_t *tc);
int  test_analytics_event_sta_connect_in_progress(const analytics_event_sta_connect_in_progress_test_case_t *tc);
void run_all_tests_analytics_event_sta_connect_in_progress(void);

// --- analytics_event_trigger_disconnection_analytics harness (OneWifi source/apps/analytics/wifi_analytics.c) ---
typedef struct {                             // source/core/services/vap_svc.h
	bss_candidate_t *scan_list;
	unsigned int     scan_count;
} __attribute__((packed)) bss_candidate_list_t;
typedef struct {                             // source/core/services/vap_svc.h: real field order up to connected_vap_index
	bss_candidate_list_t candidates_list;
	bss_candidate_t      last_connected_bss;
	bss_candidate_t      new_bss;
	bool                 new_bss_delayed;
	int                  conn_state;         // connection_state_t
	bool                 is_radio_ignored;
	bool                 is_on_channel;
	unsigned int         ignored_radio_index;  // wifi_radio_index_t
	unsigned int         selfheal_status;
	unsigned int         connected_vap_index;
	unsigned char        rest[80];           // last_connected_time ... is_vap_started[] (not touched)
} __attribute__((packed)) vap_svc_ext_t;
#define TDA_MAC_SZ   18      // = sizeof(bssid_str) (mac_addr_str_t)
#define TDA_TMP_SZ   512     // = sizeof(temp_str)
#define TDA_PAD      64
typedef struct {
	const char   *test_name;    // case name
	int           arg_null;     // arg = NULL
	unsigned int  vap_index;    // ext->connected_vap_index
	unsigned char bssid0;       // first BSSID byte (others +1..+5)
	int           expect_ret;   // expected return
	const char   *expect;       // expected temp_str
} analytics_event_trigger_disconnection_analytics_test_case_t;

extern char   tda_slot_mac[TDA_MAC_SZ + TDA_PAD];
extern char   tda_slot_tmp[TDA_TMP_SZ + TDA_PAD];
extern size_t tda_tmp_len;
extern int    tda_mac_calls;
extern char   tda_arg_buf[sizeof(vap_svc_ext_t) + TDA_PAD];
extern analytics_event_trigger_disconnection_analytics_test_case_t analytics_event_trigger_disconnection_analytics_suite[];

void construct_analytics_event_trigger_disconnection_analytics_input(const analytics_event_trigger_disconnection_analytics_test_case_t *tc);
int  test_analytics_event_trigger_disconnection_analytics(const analytics_event_trigger_disconnection_analytics_test_case_t *tc);
void run_all_tests_analytics_event_trigger_disconnection_analytics(void);

// --- analytics_event_udhcp_ip_fail harness (OneWifi source/apps/analytics/wifi_analytics.c) ---
// reuses vap_svc_ext_t from the trigger_disconnection_analytics block above
#define UIF_MAC_SZ   18      // = sizeof(bssid_str) (mac_addr_str_t)
#define UIF_TMP_SZ   512     // = sizeof(temp_str)
#define UIF_PAD      64
typedef struct {
	const char   *test_name;    // case name
	int           arg_null;     // arg = NULL
	unsigned int  vap_index;    // ext->connected_vap_index
	unsigned char bssid0;       // first BSSID byte (others +1..+5)
	int           expect_ret;   // expected return
	const char   *expect;       // expected temp_str
} analytics_event_udhcp_ip_fail_test_case_t;

extern char   uif_slot_mac[UIF_MAC_SZ + UIF_PAD];
extern char   uif_slot_tmp[UIF_TMP_SZ + UIF_PAD];
extern size_t uif_tmp_len;
extern int    uif_mac_calls;
extern char   uif_arg_buf[sizeof(vap_svc_ext_t) + UIF_PAD];
extern analytics_event_udhcp_ip_fail_test_case_t analytics_event_udhcp_ip_fail_suite[];

void construct_analytics_event_udhcp_ip_fail_input(const analytics_event_udhcp_ip_fail_test_case_t *tc);
int  test_analytics_event_udhcp_ip_fail(const analytics_event_udhcp_ip_fail_test_case_t *tc);
void run_all_tests_analytics_event_udhcp_ip_fail(void);

// --- analytics_event_new_bssid harness (OneWifi source/apps/analytics/wifi_analytics.c) ---
// reuses vap_svc_ext_t / bss_candidate_t / wifi_bss_info_t from the blocks above
#define ANB_MAC_SZ   18      // = sizeof(bssid_str) (mac_addr_str_t)
#define ANB_TMP_SZ   512     // = sizeof(temp_str)
#define ANB_PAD      64
typedef struct {
	const char   *test_name;    // case name
	int           arg_null;     // arg = NULL
	unsigned int  vap_index;    // ext->new_bss.vap_index
	unsigned int  freq;         // ext->new_bss.external_ap.freq
	unsigned char bssid0;       // first new_bss BSSID byte (others +1..+5)
	int           expect_ret;   // expected return
	const char   *expect;       // expected temp_str
} analytics_event_new_bssid_test_case_t;

extern char   anb_slot_mac[ANB_MAC_SZ + ANB_PAD];
extern char   anb_slot_tmp[ANB_TMP_SZ + ANB_PAD];
extern size_t anb_tmp_len;
extern int    anb_mac_calls;
extern char   anb_arg_buf[sizeof(vap_svc_ext_t) + ANB_PAD];
extern analytics_event_new_bssid_test_case_t analytics_event_new_bssid_suite[];

void construct_analytics_event_new_bssid_input(const analytics_event_new_bssid_test_case_t *tc);
int  test_analytics_event_new_bssid(const analytics_event_new_bssid_test_case_t *tc);
void run_all_tests_analytics_event_new_bssid(void);

// --- is_blaster_device_associated harness (OneWifi source/apps/blaster/wifi_blaster.c) ---
#ifndef MAC_ADDR_LEN
#define MAC_ADDR_LEN    6                      // include/wifi_base.h
#endif
#ifndef STA_KEY_LEN
#define STA_KEY_LEN     2*MAC_ADDR_LEN + 6     // include/wifi_base.h (= 18, no parentheses, as in source)
#endif
typedef char          sta_key_t[STA_KEY_LEN];
typedef struct {                               // subset of rdk_wifi_vap_info_t (fields used here)
	unsigned int     vap_index;
	pthread_mutex_t *associated_devices_lock;
	void            *associated_devices_map;  // hash_map_t *
} rdk_wifi_vap_info_t;
#define BIB_KEY_SZ   18      // = sizeof(sta_key_t)
#define BIB_PAD      64
typedef struct {
	const char   *test_name;    // case name
	int           no_vap;       // get_wifidb_rdk_vap_info returns NULL
	int           no_map;       // associated_devices_map == NULL
	int           in_map;       // station is in the map
	int           mlo_null;     // is_mlo == NULL
	int           mlo_in;       // *is_mlo before the call
	int           mld;          // sta->dev_stats.cli_MLDEnable
	unsigned char mac0;         // first MAC byte (others +1..+5; 0xff = all ff)
	bool          expect_ret;   // expected return
	int           expect_mlo;   // *is_mlo after the call
} is_blaster_device_associated_test_case_t;

extern char   bib_slot_key[BIB_KEY_SZ + BIB_PAD];
extern size_t bib_key_len;
extern char   bib_key_seen[64];
extern char   bib_sta_key[32];
extern int    bib_vap_lookups, bib_lookup_index;
extern rdk_wifi_vap_info_t *bib_vap;
extern assoc_dev_data_t    *bib_sta;
extern unsigned char bib_mac_buf[MAC_ADDR_LEN + BIB_PAD];
extern char   bib_mlo_buf[sizeof(bool) + BIB_PAD];
extern char   bib_vap_buf[sizeof(rdk_wifi_vap_info_t) + BIB_PAD];
extern char   bib_sta_buf[sizeof(assoc_dev_data_t) + BIB_PAD];
extern is_blaster_device_associated_test_case_t is_blaster_device_associated_suite[];

void construct_is_blaster_device_associated_input(const is_blaster_device_associated_test_case_t *tc);
int  test_is_blaster_device_associated(const is_blaster_device_associated_test_case_t *tc);
void run_all_tests_is_blaster_device_associated(void);

// --- DeviceCpuUtil_DataGet harness (OneWifi source/apps/blaster/wifi_blaster.c) ---
#define DCU_SLOT_SZ  256     // = sizeof(buff)
#define DCU_PAD      64
typedef struct {
	const char  *test_name;     // case name
	const char  *content;       // /proc/stat content (NULL = file missing)
	bool         expect_ret;    // expected return
	unsigned int expect_util;   // expected *util_cpu
} DeviceCpuUtil_DataGet_test_case_t;

extern char dcu_path[64];
extern char dcu_slot[DCU_SLOT_SZ + DCU_PAD];
extern int  dcu_lines;
extern char dcu_util_buf[sizeof(unsigned int) + DCU_PAD];
extern DeviceCpuUtil_DataGet_test_case_t DeviceCpuUtil_DataGet_suite[];

void construct_DeviceCpuUtil_DataGet_input(const DeviceCpuUtil_DataGet_test_case_t *tc);
int  test_DeviceCpuUtil_DataGet(const DeviceCpuUtil_DataGet_test_case_t *tc);
void run_all_tests_DeviceCpuUtil_DataGet(void);

// --- blaster_str_to_mac_bytes harness (OneWifi source/apps/blaster/wifi_blaster.c) ---
#define BSM_KEY_MAX  64
#define BSM_PAD      64
typedef struct {
	const char   *test_name;    // case name
	const char   *key;          // input MAC string
	unsigned char expect[6];    // expected bmac
} blaster_str_to_mac_bytes_test_case_t;

extern char          bsm_key_buf[BSM_KEY_MAX + BSM_PAD];
extern unsigned char bsm_mac_buf[MAC_ADDR_LEN + BSM_PAD];
extern blaster_str_to_mac_bytes_test_case_t blaster_str_to_mac_bytes_suite[];

void construct_blaster_str_to_mac_bytes_input(const blaster_str_to_mac_bytes_test_case_t *tc);
int  test_blaster_str_to_mac_bytes(const blaster_str_to_mac_bytes_test_case_t *tc);
void run_all_tests_blaster_str_to_mac_bytes(void);

// --- active_msmt_log_message harness (OneWifi source/apps/blaster/wifi_blaster.c) ---
typedef enum { BLASTER_INFO_LOG = 0, BLASTER_DEBUG_LOG } blaster_log_level_t;  // wifi_blaster.h
typedef struct { wifi_apps_mgr_t apps_mgr; int network_mode; unsigned int webconfig_state; int webconfig; unsigned char handle[16]; void *sched; } wifi_ctrl_t;   // subset (+ handle, + sched for em_deinit)
typedef struct {                               // stand-in: CCSP trace hooks + ctrl + hal_cap used by blaster
	struct {
		struct {
			void (*CcspTraceInfoRdkb_fn)(const char *, ...);
			void (*CcspTraceDebugRdkb_fn)(const char *, ...);
			void (*CcspTraceErrorRdkb_fn)(const char *, ...);
		} desc;
	} wifi_ccsp;
	wifi_ctrl_t ctrl;
	struct { wifi_platform_property_t wifi_prop; } hal_cap;
	struct {                                  // radio_config[].vaps.rdk_vap_array[].{map,lock}
		struct {
			struct { void *associated_devices_map; pthread_mutex_t *associated_devices_lock; } rdk_vap_array[8];
		} vaps;
		struct { int countryCode; int operatingClass; } oper;
	} radio_config[3];                       /* MAX_NUM_RADIOS; literal to avoid use-before-define */
} wifi_mgr_t;
#define AML_SLOT_SZ  1024    // = sizeof(msg)
#define AML_ARG_MAX  2112    // room for a 2000-char argument
#define AML_PAD      64
typedef struct {
	const char         *test_name;        // case name
	int                 level_idx;        // index into aml_levels[]
	const char         *dst_mac;          // DstMac argument (NULL when big)
	int                 big;              // use a 2000-char argument
	int                 expect_trace;     // trace-hook call count
	const char         *expect_contains;  // prefix the recorded trace must match
} active_msmt_log_message_test_case_t;

extern char   aml_slot[AML_SLOT_SZ + AML_PAD];
extern size_t aml_msg_len;
extern char   aml_dbg_out[4096];
extern char   aml_trace_out[2048];
extern int    aml_trace_calls;
extern char   aml_arg_buf[AML_ARG_MAX + AML_PAD];
extern char   aml_mgr_buf[sizeof(wifi_mgr_t) + AML_PAD];
extern blaster_log_level_t aml_levels[];
extern active_msmt_log_message_test_case_t active_msmt_log_message_suite[];

void construct_active_msmt_log_message_input(const active_msmt_log_message_test_case_t *tc);
int  test_active_msmt_log_message(const active_msmt_log_message_test_case_t *tc);
void run_all_tests_active_msmt_log_message(void);

// --- active_msmt_set_status_desc harness (OneWifi source/apps/blaster/wifi_blaster.c) ---
typedef enum {                               // wifi_blaster.h
	ACTIVE_MSMT_STATUS_SUCCEED      = 0,
	ACTIVE_MSMT_STATUS_CANCELED     = 1,
	ACTIVE_MSMT_STATUS_FAILED       = 2,
	ACTIVE_MSMT_STATUS_BUSY         = 3,
	ACTIVE_MSMT_STATUS_NO_CLIENT    = 4,
	ACTIVE_MSMT_STATUS_WRONG_ARG    = 5,
	ACTIVE_MSMT_STATUS_SLEEP_CLIENT = 6,
	ACTIVE_MSMT_STATUS_UNDEFINED
} active_msmt_status_t;
#define OPER_BUFFER_LEN 64                   // wifi_blaster.h
typedef struct active_msmt_data {            // wifi_blaster.h
	unsigned int   MaxTxRate;
	unsigned int   MaxRxRate;
	int            rssi;
	unsigned long  TxPhyRate;
	unsigned long  RxPhyRate;
	int            SNR;
	int            ReTransmission;
	double         throughput;
	char           Operating_standard[OPER_BUFFER_LEN + 1];
	char           Operating_channelwidth[OPER_BUFFER_LEN + 1];
	mac_address_t  cli_MACAddress;
} active_msmt_data_t;
typedef struct {                             // wifi_blaster.h
	mac_address_t       sta_mac;
	active_msmt_data_t *sta_active_msmt_data;
} blaster_hashmap_t;
#ifndef MAX_NUM_RADIOS
#define MAX_NUM_RADIOS 3
#endif
typedef struct {                             // subset of include/wifi_base.h active_msmt_step_t
	unsigned char SrcMac[13];                // MAC_ADDRESS_LENGTH
	unsigned char DestMac[13];
	unsigned int  StepId;
	int           ApIndex;
	bool          isMLO;
	int           mldApIndex[MAX_NUM_RADIOS - 1];
} active_msmt_step_t;
#define PLAN_ID_LENGTH  38                   // include/wifi_base.h
#define MAX_STEP_COUNT  32                   // include/wifi_base.h
#define MAC_ADDRESS_LENGTH 13                // include/wifi_base.h
typedef struct {                             // subset of include/wifi_base.h active_msmt_t
	bool          ActiveMsmtEnable;
	unsigned int  ActiveMsmtSampleDuration;
	unsigned int  ActiveMsmtPktSize;
	unsigned int  ActiveMsmtNumberOfSamples;
	unsigned char PlanId[PLAN_ID_LENGTH];
	int           StepInstance[MAX_STEP_COUNT];   // active_msmt_step_status_t
	active_msmt_step_t Step[MAX_STEP_COUNT];
	struct { double cpu_one, cpu_five, cpu_fifteen; unsigned int util_cpu, util_mem; } ActiveMsmtResources;
	int           Status;                          // blaster_state_t
	struct { char traceParent[512]; char traceState[512]; } t_header;
	unsigned char blaster_mqtt_topic[256];
} active_msmt_t;
typedef struct {                             // subset of wifi_blaster.h wifi_actvie_msmt_t (fields used by the blaster harnesses)
	pthread_mutex_t      lock;
	active_msmt_t        active_msmt;
	active_msmt_step_t   curStepData;
	active_msmt_data_t  *active_msmt_data;
	active_msmt_status_t status;
	char                 status_desc[512];
	void                *active_msmt_map;    // hash_map_t *
} wifi_actvie_msmt_t;
char *active_msmt_status_to_str(active_msmt_status_t status);
#define ASD_MAC_SZ     13     // = sizeof(mac) = MAC_ADDRESS_LENGTH
#define ASD_DSTMAC_SZ  13     // = sizeof(DestMac) = MAC_ADDRESS_LENGTH
#define ASD_DESC_SZ    512    // = sizeof(status_desc)
#define ASD_PAD        64
typedef struct {
	const char          *test_name;        // case name
	int                  dst_mac_kind;     // 0 raw6, 1 hex12-string, 2 raw6 (NUL at 6)
	const char          *plan_id;          // plan_id string (NULL -> "?:" fallback)
	const char          *msg;              // msg string (NULL -> "?:" fallback)
	active_msmt_status_t status;           // g_active_msmt->status
	const char          *want_desc_prefix; // status_desc must start with this
} active_msmt_set_status_desc_test_case_t;

extern char   asd_slot_mac[ASD_MAC_SZ + ASD_PAD];
extern char   asd_slot_desc[ASD_DESC_SZ + ASD_PAD];
extern size_t asd_mac_len, asd_desc_len;
extern unsigned char asd_mac_buf[ASD_DSTMAC_SZ + ASD_PAD];
extern char   asd_plan_buf[64 + ASD_PAD];
extern char   asd_msg_buf[512 + ASD_PAD];
extern char   asd_mgr_buf[sizeof(wifi_actvie_msmt_t) + ASD_PAD];
extern active_msmt_set_status_desc_test_case_t active_msmt_set_status_desc_suite[];

void construct_active_msmt_set_status_desc_input(const active_msmt_set_status_desc_test_case_t *tc);
int  test_active_msmt_set_status_desc(const active_msmt_set_status_desc_test_case_t *tc);
void run_all_tests_active_msmt_set_status_desc(void);

// --- process_active_msmt_diagnostics harness (OneWifi source/apps/blaster/wifi_blaster.c) ---
#define PAD_KEY_SZ      18     // = sizeof(sta_key_t) = STA_KEY_LEN
#define PAD_PAD         64
#define PAD_MAX_SAMPLES 8
typedef struct {
	const char   *test_name;    // case name
	int           no_map;       // active_msmt_map == NULL
	int           ap_index;     // ap_index argument (-1 = offline)
	unsigned int  samples;      // ActiveMsmtNumberOfSamples
	int           existing;     // station already in the map
	unsigned char mac0;         // first DestMac byte (others +1..+5)
	int           expect_put;   // a new station is put in the map
} process_active_msmt_diagnostics_test_case_t;

extern char   pad_slot_key[PAD_KEY_SZ + PAD_PAD];
extern size_t pad_key_len;
extern char   pad_key_seen[64];
extern char   pad_put_key[64];
extern void  *pad_put_data;
extern void  *pad_existing;
extern char   pad_existing_key[32];
extern int    pad_calls;
extern char   pad_mgr_buf[sizeof(wifi_actvie_msmt_t) + PAD_PAD];
extern char   pad_src_buf[PAD_MAX_SAMPLES * sizeof(active_msmt_data_t) + PAD_PAD];
extern process_active_msmt_diagnostics_test_case_t process_active_msmt_diagnostics_suite[];

void construct_process_active_msmt_diagnostics_input(const process_active_msmt_diagnostics_test_case_t *tc);
int  test_process_active_msmt_diagnostics(const process_active_msmt_diagnostics_test_case_t *tc);
void run_all_tests_process_active_msmt_diagnostics(void);

// --- ActiveMsmtConfValidation harness (OneWifi source/apps/blaster/wifi_blaster.c) ---
#define AMC_SLOT_SZ  256     // = sizeof(msg)
#define AMC_PAD      64
enum {
	AMC_NULL, AMC_VALID, AMC_EMPTY_PLAN, AMC_LONG_PLAN, AMC_BAD_SAMPLES,
	AMC_BAD_DURATION, AMC_BAD_RATIO, AMC_BAD_PKTSIZE, AMC_BAD_STEP_MAC, AMC_PLAN_NO_NUL
};
typedef struct {
	const char *test_name;       // case name
	int         kind;            // AMC_* selector
	int         expect_ret;      // expected return
	const char *expect_err_sub;  // substring the recorded error must contain
} ActiveMsmtConfValidation_test_case_t;

extern char   amc_slot[AMC_SLOT_SZ + AMC_PAD];
extern size_t amc_msg_len;
extern char   amc_last_err[256];
extern int    amc_report_err, amc_report_all, amc_step_invalid;
extern active_msmt_status_t amc_last_status;
extern char   amc_cfg_buf[sizeof(active_msmt_t) + AMC_PAD];
extern ActiveMsmtConfValidation_test_case_t ActiveMsmtConfValidation_suite[];

void construct_ActiveMsmtConfValidation_input(const ActiveMsmtConfValidation_test_case_t *tc);
int  test_ActiveMsmtConfValidation(const ActiveMsmtConfValidation_test_case_t *tc);
void run_all_tests_ActiveMsmtConfValidation(void);

// --- SetActiveMsmtStepDstMac harness (OneWifi source/apps/blaster/wifi_blaster.c) ---
#define SAD_SLOT_SZ  256     // = sizeof(msg)
#define SAD_PAD      64
typedef struct {
	const char   *test_name;    // case name
	int           invalid;      // StepInstance[STEP] = INVALID (early return)
	int           ext_mode;     // network_mode = ext (msg path) vs gw (diag path)
	const char   *dst_mac;      // DstMac input string
	unsigned char expect_mac[6];// expected cfg->Step[STEP].DestMac
} SetActiveMsmtStepDstMac_test_case_t;

extern char   sad_slot[SAD_SLOT_SZ + SAD_PAD];
extern size_t sad_msg_len;
extern char   sad_last_err[256];
extern int    sad_report_err, sad_diag_calls, sad_last_step_status;
extern active_msmt_status_t sad_last_status;
extern char   sad_mgr_buf[sizeof(wifi_actvie_msmt_t) + SAD_PAD];
extern char   sad_wmgr_buf[sizeof(wifi_mgr_t) + SAD_PAD];
extern char   sad_dst_buf[64 + SAD_PAD];
extern SetActiveMsmtStepDstMac_test_case_t SetActiveMsmtStepDstMac_suite[];

void construct_SetActiveMsmtStepDstMac_input(const SetActiveMsmtStepDstMac_test_case_t *tc);
int  test_SetActiveMsmtStepDstMac(const SetActiveMsmtStepDstMac_test_case_t *tc);
void run_all_tests_SetActiveMsmtStepDstMac(void);

// --- SetActiveMsmtStepSrcMac harness (OneWifi source/apps/blaster/wifi_blaster.c) ---
#define SSM_PAD  64
typedef struct {
	const char   *test_name;    // case name
	const char   *src_mac;      // SrcMac input string
	unsigned char expect_mac[6];// expected Step[STEP].SrcMac
} SetActiveMsmtStepSrcMac_test_case_t;

extern char ssm_mgr_buf[sizeof(wifi_actvie_msmt_t) + SSM_PAD];
extern char ssm_src_buf[64 + SSM_PAD];
extern SetActiveMsmtStepSrcMac_test_case_t SetActiveMsmtStepSrcMac_suite[];

void construct_SetActiveMsmtStepSrcMac_input(const SetActiveMsmtStepSrcMac_test_case_t *tc);
int  test_SetActiveMsmtStepSrcMac(const SetActiveMsmtStepSrcMac_test_case_t *tc);
void run_all_tests_SetActiveMsmtStepSrcMac(void);

// --- convert_channel_width_to_str harness (OneWifi source/apps/blaster/wifi_blaster.c) ---
#define CCW_STR_SZ  16
#define CCW_PAD     64
typedef struct {
	const char   *test_name;    // case name
	unsigned int  cw;           // wifi_channelBandwidth_t value
	size_t        len;          // len passed to the function
	const char   *expect;       // expected str
} convert_channel_width_to_str_test_case_t;

extern char ccw_str_buf[CCW_STR_SZ + CCW_PAD];
extern convert_channel_width_to_str_test_case_t convert_channel_width_to_str_suite[];

void construct_convert_channel_width_to_str_input(const convert_channel_width_to_str_test_case_t *tc);
int  test_convert_channel_width_to_str(const convert_channel_width_to_str_test_case_t *tc);
void run_all_tests_convert_channel_width_to_str(void);

// --- convert_variant_to_str harness (OneWifi source/apps/blaster/wifi_blaster.c) ---
#define CVS_GUARD   64    // poisoned bytes placed BEFORE str (to catch str[-1])
#define CVS_STR_SZ  16
#define CVS_PAD     64
typedef struct {
	const char   *test_name;    // case name
	unsigned int  variant;      // wifi_ieee80211Variant_t value
	const char   *expect;       // expected str (valid cases)
	int           underflow;    // 1 = str[-1] underflow expected (bug)
} convert_variant_to_str_test_case_t;

extern char cvs_str_buf[CVS_GUARD + CVS_STR_SZ + CVS_PAD];
extern convert_variant_to_str_test_case_t convert_variant_to_str_suite[];

void construct_convert_variant_to_str_input(const convert_variant_to_str_test_case_t *tc);
int  test_convert_variant_to_str(const convert_variant_to_str_test_case_t *tc);
void run_all_tests_convert_variant_to_str(void);

// --- DeviceMemory_DataGet harness (OneWifi source/apps/blaster/wifi_blaster.c) ---
#define DMG_SLOT_SZ  256     // = sizeof(buf)
#define DMG_PAD      64
typedef struct {
	const char  *test_name;     // case name
	const char  *content;       // /proc/meminfo content (NULL = file missing)
	bool         expect_ret;    // expected return
	unsigned int expect_util;   // expected *util_mem on success
} DeviceMemory_DataGet_test_case_t;

extern char dmg_path[64];
extern char dmg_slot[DMG_SLOT_SZ + DMG_PAD];
extern int  dmg_lines;
extern char dmg_util_buf[sizeof(unsigned int) + DMG_PAD];
extern DeviceMemory_DataGet_test_case_t DeviceMemory_DataGet_suite[];

void construct_DeviceMemory_DataGet_input(const DeviceMemory_DataGet_test_case_t *tc);
int  test_DeviceMemory_DataGet(const DeviceMemory_DataGet_test_case_t *tc);
void run_all_tests_DeviceMemory_DataGet(void);

// --- WiFiBlastClient harness (OneWifi source/apps/blaster/wifi_blaster.c) ---
typedef struct _pktGenFrameCountSamples { unsigned long PacketsSentAck[MAX_NUM_RADIOS]; unsigned long PacketsSentTotal[MAX_NUM_RADIOS]; int WaitAndLatencyInMs; } pktGenFrameCountSamples;  // wifi_blaster.h
#define WBC_MAC_SZ  18    // = sizeof(macStr)
#define WBC_MSG_SZ  256   // = sizeof(msg)
#define WBC_PAD     64
typedef struct {
	const char *test_name;     // case name
	int         app_null;      // get_app_by_inst returns NULL (early return)
	int         ext_mode;      // network_mode ext (msg path) vs gw (diag path)
	int         expect_report; // active_msmt_report_error call count
	int         expect_diag;   // process_active_msmt_diagnostics call count
} WiFiBlastClient_test_case_t;

extern char   wbc_slot_mac[WBC_MAC_SZ + WBC_PAD];
extern char   wbc_slot_msg[WBC_MSG_SZ + WBC_PAD];
extern size_t wbc_mac_len, wbc_msg_len;
extern char   wbc_last_err[256];
extern int    wbc_report_err, wbc_diag_calls, wbc_last_step_status;
extern active_msmt_status_t wbc_last_status;
extern char   wbc_mgr_buf[sizeof(wifi_actvie_msmt_t) + WBC_PAD];
extern char   wbc_wmgr_buf[sizeof(wifi_mgr_t) + WBC_PAD];
extern char   wbc_wctrl_buf[sizeof(wifi_ctrl_t) + WBC_PAD];
extern char   wbc_app_buf[sizeof(wifi_app_t) + WBC_PAD];
extern wifi_app_t *wbc_app;
extern WiFiBlastClient_test_case_t WiFiBlastClient_suite[];

void construct_WiFiBlastClient_input(const WiFiBlastClient_test_case_t *tc);
int  test_WiFiBlastClient(const WiFiBlastClient_test_case_t *tc);
void run_all_tests_WiFiBlastClient(void);

// --- process_request harness (OneWifi source/apps/blaster/wifi_blaster.c) ---
#define PRQ_SLOT_SZ  256   // = sizeof(msg)
#define PRQ_PAD      64
typedef struct {
	const char *test_name;     // case name
	int         ext;           // network_mode ext
	int         health_fail;   // DeviceMemory_DataGet returns false
	int         high_cpu;      // util_cpu over threshold
	int         low_mem;       // util_mem under threshold
	int         conf_invalid;  // ActiveMsmtConfValidation fails (ext only)
	const char *want_msg_sub;  // substring msg must contain ("" = none)
} process_request_test_case_t;

extern char   prq_slot[PRQ_SLOT_SZ + PRQ_PAD];
extern size_t prq_msg_len;
extern char   prq_last_err[256];
extern int    prq_report_all, prq_blast_calls;
extern int    prq_health_fail, prq_high_cpu, prq_conf_invalid, prq_low_mem_force;
extern char   prq_cfg_buf[sizeof(active_msmt_t) + PRQ_PAD];
extern char   prq_mgr_buf[sizeof(wifi_actvie_msmt_t) + PRQ_PAD];
extern char   prq_wmgr_buf[sizeof(wifi_mgr_t) + PRQ_PAD];
extern process_request_test_case_t process_request_suite[];

void construct_process_request_input(const process_request_test_case_t *tc);
int  test_process_request(const process_request_test_case_t *tc);
void run_all_tests_process_request(void);

// --- sample_blaster harness (OneWifi source/apps/blaster/wifi_blaster.c) ---
typedef struct { void *stat_pointer; unsigned int stat_array_size; struct { unsigned int radio_index; unsigned int vap_index; unsigned int app_info; int dwell_time; } args; } wifi_provider_response_t;
#define SB_MSG_SZ   256   // = sizeof(msg)
#define SB_OPER_SZ  65    // = OPER_BUFFER_LEN + 1 (Operating_* fields)
#define SB_PAD      64
#define SB_SAMPLES  4
typedef struct {
	const char *test_name;     // case name
	int         app_null;      // get_app_by_inst returns NULL
	int         radio_err;     // get_radio_index_for_vap_index returns RETURN_ERR
	int         ext;           // network_mode ext
	const char *want_msg_sub;  // substring msg must contain ("" = none)
} sample_blaster_test_case_t;

extern char   sb_slot_msg[SB_MSG_SZ + SB_PAD];
extern char   sb_slot_oper[SB_OPER_SZ + SB_PAD];
extern size_t sb_msg_len;
extern char   sb_last_err[256];
extern int    sb_statusdesc_calls, sb_done_notify, sb_radio_err, sb_calc_throughput;
extern unsigned int sb_num_samples, sb_sample_count;
extern char   sb_wctrl_buf[sizeof(wifi_ctrl_t) + SB_PAD];
extern char   sb_wmgr_buf[sizeof(wifi_mgr_t) + SB_PAD];
extern char   sb_mgr_buf[sizeof(wifi_actvie_msmt_t) + SB_PAD];
extern char   sb_app_buf[sizeof(wifi_app_t) + SB_PAD];
extern char   sb_fcs_buf[SB_SAMPLES * sizeof(pktGenFrameCountSamples) + SB_PAD];
extern char   sb_amd_buf[SB_SAMPLES * sizeof(active_msmt_data_t) + SB_PAD];
extern char   sb_resp_buf[sizeof(wifi_provider_response_t) + SB_PAD];
extern char   sb_stats_buf[4 * sizeof(sta_data_t) + SB_PAD];
extern wifi_app_t *sb_app;
extern sample_blaster_test_case_t sample_blaster_suite[];

void construct_sample_blaster_input(const sample_blaster_test_case_t *tc);
int  test_sample_blaster(const sample_blaster_test_case_t *tc);
void run_all_tests_sample_blaster(void);

// --- printBlastMetricData harness (OneWifi source/apps/blaster/wifi_single_client_msmt.c) ---
typedef enum { single_client_msmt_type_all, single_client_msmt_type_all_per_bssid, single_client_msmt_type_one } single_client_msmt_type_t;
#define PBM_PAD  64
typedef struct {
	const char *test_name;        // case name
	int         gw;               // network_mode gw (PlanId 16) vs ext (36)
	int         null_data;        // staData NULL (error + early return)
	int         expect_info_ge;   // CcspTraceInfo called >=1
	int         expect_err;       // CcspTraceError called
} printBlastMetricData_test_case_t;

extern char pbm_wmgr_buf[sizeof(wifi_mgr_t) + PBM_PAD];
extern char pbm_wctrl_buf[sizeof(wifi_ctrl_t) + PBM_PAD];
extern char pbm_bs_buf[sizeof(wifi_actvie_msmt_t) + PBM_PAD];
extern char pbm_sd_buf[sizeof(blaster_hashmap_t) + PBM_PAD];
extern unsigned int pbm_num_samples, pbm_num_radios;
extern int pbm_info_calls, pbm_debug_calls, pbm_err_calls;
extern printBlastMetricData_test_case_t printBlastMetricData_suite[];

void construct_printBlastMetricData_input(const printBlastMetricData_test_case_t *tc);
int  test_printBlastMetricData(const printBlastMetricData_test_case_t *tc);
void run_all_tests_printBlastMetricData(void);

// --- stream_client_msmt_data harness (OneWifi source/apps/blaster/wifi_single_client_msmt.c) ---
#define SCM_KEY_SZ  18    // = sizeof(sta_key_t) = STA_KEY_LEN
#define SCM_PAD     64
typedef struct {
	const char   *test_name;    // case name
	int           flag;         // ActiveMsmtFlag
	int           mgr_null;     // get_wifi_blaster returns NULL
	int           no_map;       // active_msmt_map NULL
	int           found;        // station in the map
	int           gw;           // network_mode gw (upload) vs ext (pod)
	unsigned char mac0;         // first DestMac byte
	int           expect_up;    // upload_single_client calls
	int           expect_pod;   // pod_upload calls
} stream_client_msmt_data_test_case_t;

extern char   scm_slot_key[SCM_KEY_SZ + SCM_PAD];
extern size_t scm_key_len;
extern char   scm_key_seen[64];
extern char   scm_existing_key[32];
extern void  *scm_existing;
extern int    scm_mgr_null, scm_upload_calls, scm_pod_calls;
extern char   scm_mgr_buf[sizeof(wifi_actvie_msmt_t) + SCM_PAD];
extern char   scm_wctrl_buf[sizeof(wifi_ctrl_t) + SCM_PAD];
extern stream_client_msmt_data_test_case_t stream_client_msmt_data_suite[];

void construct_stream_client_msmt_data_input(const stream_client_msmt_data_test_case_t *tc);
int  test_stream_client_msmt_data(const stream_client_msmt_data_test_case_t *tc);
void run_all_tests_stream_client_msmt_data(void);

// --- cac_print harness (OneWifi source/apps/cac/wifi_cac.c) ---
#define CAC_FMT_MAX  32
#define CAC_ARG_MAX  512
#define CAC_PAD      64
typedef struct {
	const char *test_name;   // case name
	const char *fmt;         // format string
	int         arg_len;     // length of the %s arg (0 = no arg)
	int         overflow;    // 1 = buff[256] overflow expected
} cac_print_test_case_t;

extern char cac_log_path[64];
extern char cac_fmt_buf[CAC_FMT_MAX + CAC_PAD];
extern char cac_arg_buf[CAC_ARG_MAX + CAC_PAD];
extern cac_print_test_case_t cac_print_suite[];

void construct_cac_print_input(const cac_print_test_case_t *tc);
int  test_cac_print(const cac_print_test_case_t *tc);
void run_all_tests_cac_print(void);

// --- telemetry_event_cac harness (OneWifi source/apps/cac/wifi_cac.c) ---
#define TEC_BUFF_SZ  64    // = sizeof(telemetry_buff)
#define TEC_VAL_SZ   128   // = sizeof(telemetry_val)
#define TEC_PAD      64
typedef struct {
	const char *test_name;    // case name
	int         band;         // 1 s5g, 2 o5g, 3 s6g, 4 o6g, 0 none
	const char *deny_type;    // deny_type arg
	const char *deny_reason;  // deny_reason arg
	const char *mac;          // mac arg
	int         null_mac;     // pass mac = NULL
	int         expect_t2;    // t2_event_s_fn call count
} telemetry_event_cac_test_case_t;

extern char   tec_slot_buff[TEC_BUFF_SZ + TEC_PAD];
extern char   tec_slot_val[TEC_VAL_SZ + TEC_PAD];
extern size_t tec_buff_len, tec_val_len;
extern char   tec_t2_marker[128], tec_t2_val[256];
extern int    tec_t2_calls, tec_band;
extern char   tec_type_buf[64 + TEC_PAD];
extern char   tec_reason_buf[64 + TEC_PAD];
extern char   tec_mac_buf[32 + TEC_PAD];
extern telemetry_event_cac_test_case_t telemetry_event_cac_suite[];

void construct_telemetry_event_cac_input(const telemetry_event_cac_test_case_t *tc);
int  test_telemetry_event_cac(const telemetry_event_cac_test_case_t *tc);
void run_all_tests_telemetry_event_cac(void);

// --- cac_event_exec_timeout harness (OneWifi source/apps/cac/wifi_cac.c) ---
typedef struct { unsigned int ap_index; char mac_addr[18]; int num_frames; int rssi_avg; int snr_avg; int uplink_rate_avg; int seconds_alive; } cac_sta_info_t;
#define CET_MAC_SZ  18
#define CET_PAD     64
typedef struct { const char *test_name; int has_assoc; int seconds_alive; unsigned char mac0; int expect_remove; } cac_event_exec_timeout_test_case_t;
extern char   cet_mgr_buf[sizeof(wifi_mgr_t) + CET_PAD];
extern char   cet_slot_mac[CET_MAC_SZ + CET_PAD];
extern void  *cet_first;
extern char   cet_removed_key[64];
extern int    cet_remove_calls;
extern char   cet_apps_buf[sizeof(wifi_app_t) + CET_PAD];
extern cac_event_exec_timeout_test_case_t cac_event_exec_timeout_suite[];
void construct_cac_event_exec_timeout_input(const cac_event_exec_timeout_test_case_t *tc);
int  test_cac_event_exec_timeout(const cac_event_exec_timeout_test_case_t *tc);
void run_all_tests_cac_event_exec_timeout(void);

// --- cac_event_hal_assoc_device harness (OneWifi source/apps/cac/wifi_cac.c) ---
typedef struct { unsigned int ap_index; mac_address_t sta_mac; int rssi_avg; int snr_avg; int uplink_rate_avg; int sampling_count; int sampling_interval; } cac_associated_devices_t;
#define CAD_MAC_SZ  32
#define CAD_TMP_SZ  64
#define CAD_PAD     64
#define CAD_POOL    4
typedef struct { const char *test_name; int hotspot; int vapfail; int cfgfail; int existing; int mallocfail; unsigned char mac0; int expect_ret; int expect_put; } cac_event_hal_assoc_device_test_case_t;
extern char   cad_slot_mac[CAD_MAC_SZ + CAD_PAD];
extern char   cad_slot_tmp[CAD_TMP_SZ + CAD_PAD];
extern size_t cad_tmp_len;
extern char   cad_key_seen[64], cad_put_key[64], cad_existing_key[32];
extern void  *cad_existing, *cad_put_data;
extern int    cad_is_hotspot, cad_vap_fail, cad_cfg_fail, cad_malloc_fail, cad_pool_used;
extern unsigned char cad_pool[CAD_POOL][sizeof(cac_associated_devices_t) + CAD_PAD];
extern char   cad_mgr_buf[sizeof(wifi_mgr_t) + CAD_PAD];
extern char   cad_arg_buf[sizeof(assoc_dev_data_t) + CAD_PAD];
extern char   cad_apps_buf[sizeof(wifi_app_t) + CAD_PAD];
extern cac_event_hal_assoc_device_test_case_t cac_event_hal_assoc_device_suite[];
void construct_cac_event_hal_assoc_device_input(const cac_event_hal_assoc_device_test_case_t *tc);
int  test_cac_event_hal_assoc_device(const cac_event_hal_assoc_device_test_case_t *tc);
void run_all_tests_cac_event_hal_assoc_device(void);

// --- cac_event_hal_disassoc_device harness (OneWifi source/apps/cac/wifi_cac.c) ---
#define CDD_MAC_SZ 32
#define CDD_TMP_SZ 64
#define CDD_PAD    64
typedef struct { const char *test_name; int existing; unsigned char mac0; int reason; int expect_remove; } cac_event_hal_disassoc_device_test_case_t;
extern char   cdd_slot_mac[CDD_MAC_SZ + CDD_PAD];
extern char   cdd_slot_tmp[CDD_TMP_SZ + CDD_PAD];
extern size_t cdd_tmp_len;
extern char   cdd_key_seen[64], cdd_existing_key[32];
extern int    cdd_existing, cdd_remove_calls;
extern char   cdd_arg_buf[sizeof(assoc_dev_data_t) + CDD_PAD];
extern char   cdd_apps_buf[sizeof(wifi_app_t) + CDD_PAD];
extern cac_event_hal_disassoc_device_test_case_t cac_event_hal_disassoc_device_suite[];
void construct_cac_event_hal_disassoc_device_input(const cac_event_hal_disassoc_device_test_case_t *tc);
int  test_cac_event_hal_disassoc_device(const cac_event_hal_disassoc_device_test_case_t *tc);
void run_all_tests_cac_event_hal_disassoc_device(void);

// --- cac_mgmt_frame_hook harness (OneWifi source/apps/cac/wifi_cac.c) ---
#define CMH_VAP_SZ 32
#define CMH_PAD    64
typedef struct { const char *test_name; int hotspot; int type; int vapfail; int cfgfail; const char *rssi; const char *rates; int expect_ret; } cac_mgmt_frame_hook_test_case_t;
extern char cmh_slot_vap[CMH_VAP_SZ + CMH_PAD];
extern char cmh_mgr_buf[sizeof(wifi_mgr_t) + CMH_PAD];
extern int  cmh_is_hotspot, cmh_vap_fail, cmh_cfg_fail;
extern char cmh_rssi[32], cmh_rates[32];
extern cac_mgmt_frame_hook_test_case_t cac_mgmt_frame_hook_suite[];
void construct_cac_mgmt_frame_hook_input(const cac_mgmt_frame_hook_test_case_t *tc);
int  test_cac_mgmt_frame_hook(const cac_mgmt_frame_hook_test_case_t *tc);
void run_all_tests_cac_mgmt_frame_hook(void);

typedef struct { unsigned int ap_index; unsigned char mac_addr[6]; unsigned char link_addr[6]; bool is_mlo; int subscribed_apps; } csi_mac_data_t;  // superset for process_csi + csi_start/stop_fn
typedef struct { unsigned char raw[256]; } wifi_csi_data_t;
#ifndef CSI_HEADER_SIZE
#define CSI_HEADER_SIZE (4 + sizeof(unsigned int) + sizeof(time_t) + (sizeof(unsigned int)) + (1 *((sizeof(unsigned char)*6) + sizeof(unsigned int))))
#endif
typedef struct { unsigned char sta_mac[6]; char header[CSI_HEADER_SIZE]; wifi_csi_data_t csi; } __attribute__((packed)) wifi_csi_dev_t;
typedef struct { bool b_inst_client_enabled; unsigned long u_inst_client_reporting_period; unsigned long u_inst_client_def_reporting_period; unsigned long u_inst_client_def_override_ttl; char mac_address[13]; } instant_measurement_config_t;
typedef struct { union { struct { instant_measurement_config_t harvester; } decoded; } u; } wha_subdoc_data_t;
typedef struct { union { wifi_csi_dev_t *csi; wha_subdoc_data_t *webconfig_data; } u; } wifi_event_t;
// --- process_csi harness (OneWifi source/apps/csi/wifi_csi.c) ---
#define PCS_MAC_SZ 18
#define PCS_PAD    64
typedef struct { const char *test_name; int ctrl_null; int app_null; int have_entry; int is_mlo; unsigned char mac0; int expect_ret; } process_csi_test_case_t;
extern char   pcs_slot_mac[PCS_MAC_SZ + PCS_PAD];
extern char   pcs_key_seen[64];
extern int    pcs_ctrl_null;
extern void  *pcs_entry;
extern wifi_app_t *pcs_app;
extern char   pcs_ctrl_buf[sizeof(wifi_ctrl_t) + PCS_PAD];
extern char   pcs_app_buf[sizeof(wifi_app_t) + PCS_PAD];
extern unsigned char pcs_mac_buf[6 + PCS_PAD];
extern char   pcs_csi_buf[256 + PCS_PAD];
extern process_csi_test_case_t process_csi_suite[];
void construct_process_csi_input(const process_csi_test_case_t *tc);
int  test_process_csi(const process_csi_test_case_t *tc);
void run_all_tests_process_csi(void);

// --- csi_start_fn harness (OneWifi source/apps/csi/wifi_csi.c) ---
#define CSF_MAC_SZ 18
#define CSF_PAD    64
typedef struct { const char *test_name; int app_null; int vap_null; int map_null; int mlo; int evict; int sounding_app; unsigned char mac0; int expect_ret; } csi_start_fn_test_case_t;
extern char   csf_slot_mac[CSF_MAC_SZ + CSF_PAD];
extern char   csf_put_key[64];
extern void  *csf_put_data;
extern int    csf_put_calls, csf_remove_calls;

extern wifi_app_t *csf_app;
extern rdk_wifi_vap_info_t *csf_vap;
extern void  *csf_assoc, *csf_csi_entry, *csf_victim;
extern char   csf_app_buf[sizeof(wifi_app_t) + CSF_PAD];
extern char   csf_vap_buf[sizeof(rdk_wifi_vap_info_t) + CSF_PAD];
extern unsigned char csf_mac_buf[6 + CSF_PAD];
extern csi_start_fn_test_case_t csi_start_fn_suite[];
void construct_csi_start_fn_input(const csi_start_fn_test_case_t *tc);
int  test_csi_start_fn(const csi_start_fn_test_case_t *tc);
void run_all_tests_csi_start_fn(void);

// --- csi_stop_fn harness (OneWifi source/apps/csi/wifi_csi.c) ---
#define CSP_MAC_SZ 18
#define CSP_PAD    64
typedef struct { const char *test_name; int app_null; int map_null; int found; int first_match; int sub_apps; int sounding; unsigned char mac0; int expect_ret; int expect_remove; } csi_stop_fn_test_case_t;
extern char   csp_slot_mac[CSP_MAC_SZ + CSP_PAD];
extern char   csp_key_seen[64];
extern wifi_app_t *csp_app;
extern void  *csp_entry, *csp_first;
extern int    csp_remove_calls;
extern wifi_app_t *csp_app;
extern char   csp_app_buf[sizeof(wifi_app_t) + CSP_PAD];
extern unsigned char csp_mac_buf[6 + CSP_PAD];
extern csi_stop_fn_test_case_t csi_stop_fn_suite[];
void construct_csi_stop_fn_input(const csi_stop_fn_test_case_t *tc);
int  test_csi_stop_fn(const csi_stop_fn_test_case_t *tc);
void run_all_tests_csi_stop_fn(void);


// --- set_bus_csi_sta_maclist harness (OneWifi source/apps/csi/wifi_csi_analytics.c) ---
#define SBM_NAME_SZ 128
#define SBM_PAD     64
typedef struct { const char *test_name; unsigned int session; const char *mac; int fail; int expect_ret; } set_bus_csi_sta_maclist_test_case_t;
extern char   sbm_slot[SBM_NAME_SZ + SBM_PAD];
extern size_t sbm_name_len;
extern char   sbm_name_seen[256], sbm_val_seen[512];
extern int    sbm_set_calls, sbm_fail;
extern char   sbm_info_buf[sizeof(csi_analytics_info_t) + SBM_PAD];
extern char   sbm_bh_buf[16 + SBM_PAD];
extern set_bus_csi_sta_maclist_test_case_t set_bus_csi_sta_maclist_suite[];
void construct_set_bus_csi_sta_maclist_input(const set_bus_csi_sta_maclist_test_case_t *tc);
int  test_set_bus_csi_sta_maclist(const set_bus_csi_sta_maclist_test_case_t *tc);
void run_all_tests_set_bus_csi_sta_maclist(void);

typedef struct { unsigned int rss_check_interval; unsigned int rss_threshold; unsigned int rss_maxlimit; unsigned int heapwalk_duration; unsigned int heapwalk_interval; bool enable; } __attribute__((packed)) memwraptool_config_t;   // include/wifi_base.h
typedef struct { unsigned char clientMac[6]; int max_num_csi_clients; int levl_sounding_duration; int levl_publish_interval; } levl_config_t;   // include/wifi_base.h
typedef struct webconfig_subdoc_decoded_data { void *csi_data_queue; levl_config_t levl; struct { struct { memwraptool_config_t memwraptool; } global_parameters; } config; } webconfig_subdoc_decoded_data_t;
typedef struct { int type; struct { webconfig_subdoc_decoded_data_t decoded; } u; } webconfig_subdoc_data_t;   // subset of include/wifi_webconfig.h
// --- webconfig_hal_csi_data_apply harness (OneWifi source/apps/csi/wifi_csi_analytics.c) ---
#define WHC_MAC_SZ 18
#define WHC_PAD    64
typedef struct { const char *test_name; int null_queue; int nsess; int clients_each; int expect_update; } webconfig_hal_csi_data_apply_test_case_t;
extern char   whc_slot_mac[WHC_MAC_SZ + WHC_PAD];
extern char   whc_result[600];
extern unsigned int whc_count;
extern void  *whc_items[8];
extern int    whc_update_calls, whc_null_queue;
extern char   whc_apps_buf[sizeof(wifi_app_t) + WHC_PAD];
extern char   whc_dec_buf[sizeof(void*) + WHC_PAD];
extern webconfig_hal_csi_data_apply_test_case_t webconfig_hal_csi_data_apply_suite[];
void construct_webconfig_hal_csi_data_apply_input(const webconfig_hal_csi_data_apply_test_case_t *tc);
int  test_webconfig_hal_csi_data_apply(const webconfig_hal_csi_data_apply_test_case_t *tc);
void run_all_tests_webconfig_hal_csi_data_apply(void);

// --- set_bus_csi_sub_enable_status harness (OneWifi source/apps/csi/wifi_csi_analytics.c) ---
#define SES_NAME_SZ 128
#define SES_PAD     64
typedef struct { const char *test_name; unsigned int session; int status; int fail; int expect_ret; } set_bus_csi_sub_enable_status_test_case_t;
extern char   ses_slot[SES_NAME_SZ + SES_PAD];
extern size_t ses_name_len;
extern char   ses_name_seen[256];
extern int    ses_set_calls, ses_fail, ses_last_bool;
extern char   ses_bh_buf[16 + SES_PAD];
extern set_bus_csi_sub_enable_status_test_case_t set_bus_csi_sub_enable_status_suite[];
void construct_set_bus_csi_sub_enable_status_input(const set_bus_csi_sub_enable_status_test_case_t *tc);
int  test_set_bus_csi_sub_enable_status(const set_bus_csi_sub_enable_status_test_case_t *tc);
void run_all_tests_set_bus_csi_sub_enable_status(void);

// --- pipe_read_oper_thread_func harness (OneWifi source/apps/csi/wifi_csi_analytics.c) ---
#define PRT_PATH_SZ 64
#define PRT_PAD     64
typedef struct { const char *test_name; int session; int make_file; int expect_decode; } pipe_read_oper_thread_func_test_case_t;
extern char prt_slot[PRT_PATH_SZ + PRT_PAD];
extern int  prt_decode_calls, prt_process_calls, prt_clean_calls;
extern char prt_app_buf[sizeof(wifi_app_t) + PRT_PAD];
extern pipe_read_oper_thread_func_test_case_t pipe_read_oper_thread_func_suite[];
void construct_pipe_read_oper_thread_func_input(const pipe_read_oper_thread_func_test_case_t *tc);
int  test_pipe_read_oper_thread_func(const pipe_read_oper_thread_func_test_case_t *tc);
void run_all_tests_pipe_read_oper_thread_func(void);

// --- init_bus_subscription harness (OneWifi source/apps/csi/wifi_csi_analytics.c) ---
#define IBS_NAME_SZ 128
#define IBS_PAD     64
typedef struct { const char *test_name; int session; int open_fail; int addrow_fail; int sub_fail; int expect_ret; } init_bus_subscription_test_case_t;
extern char   ibs_slot[IBS_NAME_SZ + IBS_PAD];
extern size_t ibs_name_len;
extern char   ibs_sub_name[256];
extern int    ibs_open_fail, ibs_addrow_fail, ibs_sub_fail, ibs_added_index;
extern int    ibs_close_calls, ibs_sub_calls, ibs_timer_calls;
extern char   ibs_bh_buf[16 + IBS_PAD];
extern char   ibs_app_buf[sizeof(wifi_app_t) + IBS_PAD];
extern init_bus_subscription_test_case_t init_bus_subscription_suite[];
void construct_init_bus_subscription_input(const init_bus_subscription_test_case_t *tc);
int  test_init_bus_subscription(const init_bus_subscription_test_case_t *tc);
void run_all_tests_init_bus_subscription(void);

// --- start_sta_channel_scan harness (OneWifi source/apps/easyconnect/wifi_easyconnect.c) ---
#ifndef EM_MAX_CHANNELS
#define EM_MAX_CHANNELS 64
#define EM_MAX_OPERATING_CLASS 48
#endif
typedef struct { unsigned char operating_class; unsigned int num_channels; unsigned char channels[EM_MAX_CHANNELS]; } operating_class_t;
typedef struct { int perform_fresh_scan; unsigned int num_radios; unsigned char ruid[6]; unsigned int num_operating_classes; operating_class_t operating_classes[EM_MAX_OPERATING_CLASS]; } channel_scan_request_t;
#define SSC_CH_SZ   64
#define SSC_PAD     64
typedef struct { const char *test_name; int match_class; unsigned int num_channels; int expect_overflow; } start_sta_channel_scan_test_case_t;
extern char   ssc_mgr_buf[sizeof(wifi_mgr_t) + SSC_PAD];
extern char   ssc_req_buf[sizeof(channel_scan_request_t) + SSC_PAD];
extern int    ssc_global_op_class;
extern int    ssc_scan_calls, ssc_scan_num;
extern start_sta_channel_scan_test_case_t start_sta_channel_scan_suite[];
void construct_start_sta_channel_scan_input(const start_sta_channel_scan_test_case_t *tc);
int  test_start_sta_channel_scan(const start_sta_channel_scan_test_case_t *tc);
void run_all_tests_start_sta_channel_scan(void);

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

#define MAX_STA 32
int8_t     queue_push(queue_t *q, void *data);
int8_t hash_map_put(hash_map_t *map, char *key, void *data);
void *hash_map_get(hash_map_t *map, const char *key);
void *hash_map_get_first(hash_map_t *map);
void *hash_map_get_next(hash_map_t *map, void *data);

extern unsigned char vendor_elements[];
typedef char em_interface_name_t[32];
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

		//	dm_sta_t();

		dm_sta_t() {}

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
	em_profile_type_max,
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

typedef struct  {
	mac_address_t sta_mac;
	unsigned int tx_bytes;
	unsigned int rx_bytes;
	unsigned int tx_pkts;
	unsigned int rx_pkts;
	unsigned int tx_pkt_errors;
	unsigned int rx_pkt_errors;
	unsigned int retx_cnt;
} __attribute__((__packed__)) em_assoc_sta_traffic_stats_t;

typedef struct {
	// this is of type vendor_ext_attr_id_t for vendor specific attributes
	unsigned char attr_id;
	unsigned char  vendor_data[0];
} __attribute__((__packed__)) em_vendor_data_t;

typedef struct {
	unsigned char  vendor_oui[3];
	unsigned char num;
	em_vendor_data_t  data[0];
} __attribute__((__packed__)) em_vendor_specific_t;

typedef struct {
	bssid_t     bssid;
	unsigned int  time_delta_ms;
	unsigned int  est_mac_data_rate_dl;
	unsigned int  est_mac_data_rate_ul;
	unsigned char rcpi;
}__attribute__((__packed__)) em_assoc_link_metrics_t;

typedef struct {
	mac_address_t sta_mac;
	unsigned char num_bssids;
	em_assoc_link_metrics_t     assoc_link_metrics[0];
}__attribute__((__packed__)) em_assoc_sta_link_metrics_t;

typedef struct {
	bssid_t     bssid;
	unsigned int  last_data_dl_rate;
	unsigned int  last_data_ul_rate;
	unsigned int  util_receive;
	unsigned int  util_transmit;
}__attribute__((__packed__)) em_assoc_ext_link_metrics_t;

typedef struct {
	mac_address_t sta_mac;
	unsigned char num_bssids;
	em_assoc_ext_link_metrics_t assoc_ext_link_metrics[0];
}__attribute__((__packed__)) em_assoc_sta_ext_link_metrics_t;

typedef struct {
	mac_address_t sta_mac;
	bssid_t bssid;
	em_string_t sta_client_type;
	//unsigned char num_bssids;
	//em_assoc_vendor_link_metrics_t assoc_vendor_link_metrics[0];
}__attribute__((__packed__)) em_assoc_sta_vendor_link_metrics_t;

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

typedef enum
{
	WIFI_CHANNELBANDWIDTH_20MHZ = 0x1, /**< 20MHz. */
	WIFI_CHANNELBANDWIDTH_40MHZ = 0x2, /**< 40MHz. */
	WIFI_CHANNELBANDWIDTH_80MHZ = 0x4, /**< 80MHz. */
	WIFI_CHANNELBANDWIDTH_160MHZ = 0x8, /**< 160MHz. */
	WIFI_CHANNELBANDWIDTH_80_80MHZ = 0x10, /**< 80+80MHz. */
	WIFI_CHANNELBANDWIDTH_320MHZ = 0x20 /**< 320MHz. */
} wifi_channelBandwidth_t;

typedef char ssid_t[32];

/* --- em_prepare_scan_response_data harness (uses ssid_t/bssid_t above) --- */
#ifndef EM_MAX_RESULTS
#define EM_MAX_RESULTS 32
#endif
#ifndef EM_MAX_CHANNEL_BW_LEN
#define EM_MAX_CHANNEL_BW_LEN 16
#endif
#define EM_BSS_COLOR_DEFAULT 0
#define EM_SCAN_TYPE_ACTIVE 1
#define EPSR_PAD 64
typedef struct {
	bssid_t        bssid;
	ssid_t         ssid;
	char           signal_strength;
	char           channel_bandwidth[EM_MAX_CHANNEL_BW_LEN];
	unsigned char  bss_load_element_present;
	unsigned char  bss_color;
	unsigned char  channel_utilization;
	unsigned short station_count;
} neighbor_bss_t;
typedef struct {
	unsigned int   operating_class;
	unsigned int   channel;
	unsigned int   scan_status;
	char           time_stamp[32];
	unsigned int   utilization;
	unsigned int   noise;
	unsigned int   num_neighbors;
	unsigned int   aggregate_scan_duration;
	unsigned int   scan_type;
	neighbor_bss_t neighbors[EM_MAX_NEIGHBORS];
} channel_scan_result_t;
typedef struct channel_scan_response_t {
	unsigned char       ruid[6];
	unsigned int        num_results;
	channel_scan_result_t results[EM_MAX_RESULTS];
} channel_scan_response_t;
/* subset of wifi_neighbor_ap2_t (fields the handler reads) */
typedef struct {
	unsigned int  ap_freq;
	char          ap_SSID[64];
	unsigned int  ap_Channel;
	int           ap_ChannelUtilization;
	int           ap_Noise;
	char          ap_BSSID[32];
	int           ap_SignalStrength;
	char          ap_OperatingChannelBandwidth[32];
	unsigned char bss_load_element_present;
	unsigned int  ap_StaCount;
} wifi_neighbor_ap2_t;
extern char  epsr_mgr_buf[];
extern char  epsr_resp_buf[];
extern char  epsr_scanresp_buf[];
extern void *epsr_stat_pointer;
struct em_epsr_test_case { const char *test_name; unsigned int radio_index; int scan_count; int mode; int want_ret; int want_num_results; };
typedef struct em_epsr_test_case em_epsr_test_case_t;
extern em_epsr_test_case_t em_prepare_scan_response_data_suite[];
void construct_em_prepare_scan_response_data_input(const em_epsr_test_case_t *tc);
void run_all_tests_em_prepare_scan_response_data(void);

/* --- em_publish_stats_data harness (uses channel_scan_response_t + wifi_ctrl_t) --- */
#ifndef MAX_EVENT_NAME_SIZE
#define MAX_EVENT_NAME_SIZE 200
#endif
#define EPS_PAD 64
extern char eps_ctrl_buf[];
extern char eps_scanresp_buf[];
extern int  eps_encode_fail, eps_publish_fail;
extern char eps_published_event[256];
extern int  eps_publish_calls;
struct em_eps_test_case { const char *test_name; int encode_fail; int publish_fail; int want_ret; };
typedef struct em_eps_test_case em_eps_test_case_t;
extern em_eps_test_case_t em_publish_stats_data_suite[];
void construct_em_publish_stats_data_input(const em_eps_test_case_t *tc);
void run_all_tests_em_publish_stats_data(void);

/* --- em_process_neighbour_data harness (uses wifi_neighbor_ap2_t + channel_scan_response_t) --- */
#ifndef MAX_LOCAL_SSIDS
#define MAX_LOCAL_SSIDS 16
#endif
#ifndef MAX_SSID_LEN
#define MAX_SSID_LEN 33
#endif
#define EPND_PAD 64
typedef struct { wifi_neighbor_ap2_t base; unsigned char opClass; int score; } neighbor_with_opclass_t;
typedef struct {
	neighbor_with_opclass_t neighbors[16];
	int           ap_index;
	unsigned int  num_neighbors;
	unsigned char sta_mac[6];
	unsigned char dialog_token;
	unsigned char query_reason;
	unsigned char request_mode;
	bool          neighbor_list_present;
} em_btm_req_ctrl_msg_t;
extern char epnd_mgr_buf[];
extern char epnd_resp_buf[];
extern int  epnd_mgr_null, epnd_prepare_fail, epnd_num_results, epnd_num_neighbors;
extern int  epnd_publish_fail, epnd_publish_calls, epnd_vap_ssid_count, epnd_ssid_match_all;
extern int  epnd_push_calls, epnd_stop_calls;
extern bool g_btm_pending_valid;
extern em_btm_req_ctrl_msg_t g_pending_btm;
struct em_epnd_test_case { const char *test_name; int mgr_null; int prepare_fail; int num_results; int num_neighbors; int btm_pending; int ssid_match_all; int vap_ssid_count; int publish_fail; int want_ret; int want_num_neighbors; };
typedef struct em_epnd_test_case em_epnd_test_case_t;
extern em_epnd_test_case_t em_process_neighbour_data_suite[];
void construct_em_process_neighbour_data_input(const em_epnd_test_case_t *tc);
void run_all_tests_em_process_neighbour_data(void);

/* --- radio_chan_stats_response harness (uses wifi_vap_info_map_t + shared cache) --- */
#define RCS_PAD 64
typedef struct {
	unsigned int ch_number;
	int          ch_noise;
	unsigned long long ch_utilization_total, ch_utilization_busy, ch_utilization_busy_tx,
	    ch_utilization_busy_self, ch_utilization_busy_rx, ch_utilization_busy_ext;
} radio_chan_data_t;
typedef struct { wifi_vap_info_map_t vap_map; unsigned int num_vaps; } rcs_vaps_t;
typedef struct { rcs_vaps_t vaps; } rdk_wifi_radio_t;
typedef struct { unsigned long long total, busy, busy_tx, busy_self, busy_rx; unsigned int chan; } em_chan_survey_prev_t;
extern em_chan_survey_prev_t em_chan_survey_prev[MAX_NUM_RADIOS];
extern char rcs_mgr_buf[];
extern char rcs_resp_buf[];
extern void *rcs_stat_pointer;
extern rdk_wifi_radio_t rcs_radio;
extern int  rcs_radio_null;
struct em_rcs_test_case { const char *test_name; int radio_index; int stat_array_size; int num_vaps; int radio_null; int want_ret; };
typedef struct em_rcs_test_case em_rcs_test_case_t;
extern em_rcs_test_case_t radio_chan_stats_response_suite[];
void construct_radio_chan_stats_response_input(const em_rcs_test_case_t *tc);
void run_all_tests_radio_chan_stats_response(void);

/* --- handle_sta_client_info harness (uses sta_client_info_t) --- */
#define HSCI_PAD 64
extern char hsci_sta_buf[];
struct em_hsci_test_case { const char *test_name; int sta_null; int prepopulate; int want_ret; };
typedef struct em_hsci_test_case em_hsci_test_case_t;
extern em_hsci_test_case_t handle_sta_client_info_suite[];
void construct_handle_sta_client_info_input(const em_hsci_test_case_t *tc);
void run_all_tests_handle_sta_client_info(void);
void hsci_store_reset(void);
void hsci_store_prepopulate(const char *key);
void *hsci_store_get(void);

/* --- em_publish_failed_connection harness (uses wifi_ctrl_t) --- */
#define PFC_PAD 64
typedef struct { unsigned char bssid[6]; unsigned char sta_mac[6]; unsigned int status; unsigned int reason; } wifi_em_failed_conn_t;
extern char pfc_ctrl_buf[];
extern char pfc_fc_buf[];
extern int  pfc_publish_fail, pfc_publish_calls;
extern char pfc_published_json[256];
extern char pfc_published_event[128];
struct em_pfc_test_case { const char *test_name; int publish_fail; int want_ret; };
typedef struct em_pfc_test_case em_pfc_test_case_t;
extern em_pfc_test_case_t em_publish_failed_connection_suite[];
void construct_em_publish_failed_connection_input(const em_pfc_test_case_t *tc);
void run_all_tests_em_publish_failed_connection(void);

/* --- em_handle_failed_connection harness (uses wifi_em_failed_conn_t) --- */
#define HFC_PAD 64
typedef struct { int ap_index; unsigned char sta_mac[6]; unsigned int status; unsigned int reason; } sta_fail_data_t;
extern char hfc_arg_buf[];
extern int  hfc_vap_null, hfc_publish_fail, hfc_publish_calls;
struct em_hfc_test_case { const char *test_name; int arg_null; int vap_null; int publish_fail; int want_ret; };
typedef struct em_hfc_test_case em_hfc_test_case_t;
extern em_hfc_test_case_t em_handle_failed_connection_suite[];
void construct_em_handle_failed_connection_input(const em_hfc_test_case_t *tc);
void run_all_tests_em_handle_failed_connection(void);

/* --- em_handle_disassoc_device harness (uses assoc_dev_data_t + shared cache) --- */
#define HDD_PAD 64
extern char hdd_ctrl_buf[];
extern char hdd_mgr_buf[];
extern char hdd_arg_buf[];
extern int  hdd_radio_index, hdd_vap_null, hdd_stats_present, hdd_clitype_present;
struct em_hdd_test_case { const char *test_name; int radio_index; int vap_null; int stats_present; int clitype_present; int vap_in_cache; int want_ret; };
typedef struct em_hdd_test_case em_hdd_test_case_t;
extern em_hdd_test_case_t em_handle_disassoc_device_suite[];
void construct_em_handle_disassoc_device_input(const em_hdd_test_case_t *tc);
void run_all_tests_em_handle_disassoc_device(void);

/* --- em_handle_sta_conn_status harness (uses rdk_sta_data_t + wifi_ctrl_t) --- */
#define HSCS_PAD 64
extern char hscs_ctrl_buf[];
extern char hscs_data_buf[];
extern int  hscs_publish_calls, hscs_last_len;
extern char hscs_published_event[128];
struct em_hscs_test_case { const char *test_name; int data_null; int want_ret; };
typedef struct em_hscs_test_case em_hscs_test_case_t;
extern em_hscs_test_case_t em_handle_sta_conn_status_suite[];
void construct_em_handle_sta_conn_status_input(const em_hscs_test_case_t *tc);
void run_all_tests_em_handle_sta_conn_status(void);

/* --- em_config_channel_scan harness (uses channel_scan_request_t) --- */
#define ECCS_PAD 64
extern char eccs_mgr_buf[];
extern char eccs_req_buf[];
extern int  eccs_mgr_null, eccs_iface_count, eccs_scan_init_calls, eccs_scan_init_radio;
extern char eccs_iface_name[8][32];
extern unsigned char eccs_iface_mac[8][6];
struct em_eccs_test_case { const char *test_name; int data_null; int small_len; int mgr_null; int want_calls; int want_radio; };
typedef struct em_eccs_test_case em_eccs_test_case_t;
extern em_eccs_test_case_t em_config_channel_scan_suite[];
void construct_em_config_channel_scan_input(const em_eccs_test_case_t *tc);
void run_all_tests_em_config_channel_scan(void);

/* --- em_process_beacon_rep harness --- */
#ifndef IEEE80211_HDRLEN
#define IEEE80211_HDRLEN 24
#endif
#ifndef MAX_FRAME_SZ
#define MAX_FRAME_SZ 2048
#endif
#define EPBR_PAD 64
typedef struct { unsigned char dialog_token; size_t size; void *beacon_repo; } wifi_hal_rrm_report_t;
/* minimal 802.11 mgmt/action/rrm model: rrm.variable lands at
 * IEEE80211_HDRLEN + 1 + sizeof(rrm) == min_len (matches the handler). */
struct epbr_rrm    { unsigned char action; unsigned char dialog; unsigned char variable[]; };
struct epbr_action { unsigned char category; union { struct epbr_rrm rrm; } u; };
/* named 24-byte 802.11 header (sa used by em_handle_action_frame); total == IEEE80211_HDRLEN */
struct ieee80211_mgmt {
	unsigned char frame_control[2];
	unsigned char duration[2];
	unsigned char da[6];
	unsigned char sa[6];
	unsigned char bssid[6];
	unsigned char seq_ctrl[2];
	union { struct epbr_action action; } u;
};
extern char epbr_mgmt_buf[];
extern char epbr_rep_buf[];
extern unsigned char epbr_sta_mac[];
extern char epbr_app_buf[];
extern char epbr_appctrl_buf[];
extern int epbr_publish_ret, epbr_publish_calls;
extern unsigned int epbr_last_data_len;
extern size_t epbr_len;
struct em_epbr_test_case { const char *test_name; int data_len; int publish_ret; int want_rc; int want_publish; };
typedef struct em_epbr_test_case em_epbr_test_case_t;
extern em_epbr_test_case_t em_process_beacon_rep_suite[];
void construct_em_process_beacon_rep_input(const em_epbr_test_case_t *tc);
void run_all_tests_em_process_beacon_rep(void);

/* --- em_handle_action_frame harness (uses ieee80211_mgmt + wifi_hal_rrm_report_t) --- */
#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif
#define EHAF_PAD 64
#ifndef RDK_DEV_MODE_TYPE_DEFINED
#define RDK_DEV_MODE_TYPE_DEFINED
typedef enum { rdk_dev_mode_type_gw = 0, rdk_dev_mode_type_ext = 1, rdk_dev_mode_type_em_node = 2, rdk_dev_mode_type_em_colocated_node = 3 } rdk_dev_mode_type_t;
#endif
typedef struct { int ap_index; unsigned int len; } ehaf_frame_t;   /* subset of wifi_frame_t (ap_index + len used) */
typedef struct { ehaf_frame_t frame; unsigned char data[MAX_FRAME_SZ]; } frame_data_t;
extern char ehaf_ctrl_buf[];
extern char ehaf_arg_buf[];
extern int  ehaf_ctrl_null, ehaf_parse_fail, ehaf_process_calls;
struct em_ehaf_test_case { const char *test_name; int arg_null; int ctrl_null; int short_len; int action; int mode; int parse_fail; int want_rc; int want_proc; };
typedef struct em_ehaf_test_case em_ehaf_test_case_t;
extern em_ehaf_test_case_t em_handle_action_frame_suite[];
void construct_em_handle_action_frame_input(const em_ehaf_test_case_t *tc);
void run_all_tests_em_handle_action_frame(void);

/* --- em_handle_connection_status harness --- */
#define EHCS_PAD 64
typedef struct { unsigned char sta_mac[6]; unsigned char bssid[6]; unsigned int status_code; int reason_code_present; unsigned int reason_code; } em_connection_status_event_t;
extern char ehcs_conn_buf[];
extern char ehcs_app_buf[];
extern char ehcs_appctrl_buf[];
extern int  ehcs_publish_fail, ehcs_publish_calls, ehcs_last_len;
extern char ehcs_published_event[128];
struct em_ehcs_test_case { const char *test_name; int app_null; int conn_null; int publish_fail; int want_ret; };
typedef struct em_ehcs_test_case em_ehcs_test_case_t;
extern em_ehcs_test_case_t em_handle_connection_status_suite[];
void construct_em_handle_connection_status_input(const em_ehcs_test_case_t *tc);
void run_all_tests_em_handle_connection_status(void);

/* --- em_send_action_frame harness (uses wifi_vap_info_map_t) --- */
#define ESAF_PAD 64
typedef struct {
	unsigned char bssid[6];
	unsigned int  opClass;
	unsigned int  channel;
	unsigned int  duration;
	int           channelReportPresent;
	struct { unsigned int opClass; } channelReport;
} wifi_BeaconRequest_t;
typedef struct { unsigned char sta_mac[6]; wifi_BeaconRequest_t data; } beacon_query_params_t;
/* named esaf_radio_oper_t (NOT wifi_radio_operationParam_t, which is a local
 * typedef in start_sta_channel_scan.cpp / WiFiBlastClient.cpp) */
typedef struct { unsigned int countryCode; unsigned int operatingClass; unsigned int channel; } esaf_radio_oper_t;
extern char esaf_mgr_buf[];
extern char esaf_query_buf[];
extern int  esaf_num_radios, esaf_vap_present[8], esaf_radio_index, esaf_radio_null, esaf_country_fail, esaf_send_fail, esaf_send_calls;
extern wifi_vap_info_map_t esaf_vap_maps[8];
extern esaf_radio_oper_t esaf_radio_oper;
struct em_esaf_test_case { const char *test_name; int radio_null; int country_fail; int send_fail; int bssid_sel; int want_rc; };
typedef struct em_esaf_test_case em_esaf_test_case_t;
extern em_esaf_test_case_t em_send_action_frame_suite[];
void construct_em_send_action_frame_input(const em_esaf_test_case_t *tc);
void run_all_tests_em_send_action_frame(void);

/* --- em_init harness (uses wifi_app_t + em_config_t) --- */
#define EMI_PAD 64
extern char emi_app_buf[];
extern char emi_appctrl_buf[];
extern int  emi_app_init_ret, emi_bus_open_fail, emi_bus_reg_fail;
extern int  emi_reg_calls, emi_reg_num, emi_cache_init_calls;
extern char emi_elem0_name[128];
struct em_emi_test_case { const char *test_name; int app_init_ret; int bus_open_fail; int bus_reg_fail; int want_ret; };
typedef struct em_emi_test_case em_emi_test_case_t;
extern em_emi_test_case_t em_init_suite[];
void construct_em_init_input(const em_emi_test_case_t *tc);
void run_all_tests_em_init(void);

/* --- em_deinit harness (uses wifi_ctrl_t + sta_client_info_t) --- */
#define EDI_PAD 64
extern char edi_ctrl_buf[];
extern int  edi_destroy_calls;
void edi_store_build(int n);
struct em_edi_test_case { const char *test_name; int num_entries; int want_ret; };
typedef struct em_edi_test_case em_edi_test_case_t;
extern em_edi_test_case_t em_deinit_suite[];
void construct_em_deinit_input(const em_edi_test_case_t *tc);
void run_all_tests_em_deinit(void);

/* --- is_harvester_device_associated harness (uses rdk_wifi_vap_info_t + sta_key_t) --- */
#define IHD_PAD 64
#define IHD_KEY_SZ STA_KEY_LEN
extern rdk_wifi_vap_info_t *ihd_vap;
extern int   ihd_vap_lookups, ihd_lookup_index, ihd_key_len;
extern assoc_dev_data_t *ihd_sta;
extern char  ihd_sta_key[64];
extern char  ihd_key_seen[64];
extern char  ihd_slot_key[];
extern unsigned char ihd_mac_buf[];
struct harv_ihd_test_case { const char *test_name; int vap_null; int map_null; int sta_present; bool want; };
typedef struct harv_ihd_test_case harv_ihd_test_case_t;
extern harv_ihd_test_case_t is_harvester_device_associated_suite[];
void construct_is_harvester_device_associated_input(const harv_ihd_test_case_t *tc);
void run_all_tests_is_harvester_device_associated(void);

/* --- process_instant_msmt_monitor harness (uses wifi_provider_response_t + sta_data_t) --- */
#ifndef MIN_MAC_LEN
#define MIN_MAC_LEN 12
#endif
#define PIM_PAD 64
#define PIM_STATS_SZ (8 * sizeof(sta_data_t) + PIM_PAD)   /* size of pim_stats_buf */
/* radio_data_t comes from above (line ~1907) */
typedef struct { int ap_index; unsigned char sta_mac[6]; bool active; } pim_inst_msmt_t;
typedef struct {
	int  count;
	int  maxCount;
	int  instantDefOverrideTTL;
	bool instntMsmtenable;
	void *radio_data[MAX_NUM_RADIOS];
	char instantMac[32];
	pim_inst_msmt_t inst_msmt;
	int  poll_period;
	int  inst_msmt_id;
	int  instantPollPeriod;
	pthread_mutex_t queue_lock;
	pthread_cond_t cond;
} harvester_ctx_t;
/* wifi_monitor_data_t: minimal (only u.msg.data is touched) */
typedef struct { union { struct { unsigned char data[MAX_FRAME_SZ]; } msg; } u; } wifi_monitor_data_t;
extern harvester_ctx_t g_harvester_module;
extern char pim_resp_buf[];
extern char pim_stats_buf[];
extern int  pim_num_radios, pim_devstats_fail, pim_stop_calls, pim_upload_calls;
struct em_pim_test_case { const char *test_name; int count; int maxCount; int nstats; int match; int want_stop; int want_upload; };
typedef struct em_pim_test_case em_pim_test_case_t;
extern em_pim_test_case_t process_instant_msmt_monitor_suite[];
void construct_process_instant_msmt_monitor_input(const em_pim_test_case_t *tc);
void run_all_tests_process_instant_msmt_monitor(void);

/* --- process_instant_msmt_stop harness --- */
#define PIMS_PAD 64
#define PIMS_SINK_SZ (16 + PIMS_PAD)
extern int  pims_num_radios, pims_cfg_push, pims_ctrl_push, pims_ctrl_len, pims_mon_push;
extern char pims_sink[];
struct em_pims_test_case { const char *test_name; int inst_msmt_id; int want_ctrl_push; };
typedef struct em_pims_test_case em_pims_test_case_t;
extern em_pims_test_case_t process_instant_msmt_stop_suite[];
void construct_process_instant_msmt_stop_input(const em_pims_test_case_t *tc);
void run_all_tests_process_instant_msmt_stop(void);

/* --- process_instant_msmt_start harness --- */
#define PIST_PAD 64
#define PIST_SINK_SZ (16 + PIST_PAD)
extern int  pist_cfg_push, pist_ctrl_push, pist_ctrl_len, pist_mon_push;
extern char pist_sink[];
struct em_pist_test_case { const char *test_name; int ttl; int poll; int want_maxcount; };
typedef struct em_pist_test_case em_pist_test_case_t;
extern em_pist_test_case_t process_instant_msmt_start_suite[];
void construct_process_instant_msmt_start_input(const em_pist_test_case_t *tc);
void run_all_tests_process_instant_msmt_start(void);

/* --- monitor_enable_instant_msmt harness --- */
#define MEN_PAD 64
extern char men_mgr_buf[];
extern unsigned char men_mac_buf[];
extern int  men_num_vaps, men_found_vap, men_assoc_checks, men_start_calls, men_stop_calls;
struct em_men_test_case { const char *test_name; int active; int enable; int mac_match; int found_vap; int want_start; int want_stop; };
typedef struct em_men_test_case em_men_test_case_t;
extern em_men_test_case_t monitor_enable_instant_msmt_suite[];
void construct_monitor_enable_instant_msmt_input(const em_men_test_case_t *tc);
void run_all_tests_monitor_enable_instant_msmt(void);

/* --- harvester_str_to_mac_bytes harness --- */
#define HSM_PAD 64
#define HSM_KEY_SZ (64 + HSM_PAD)
extern char hsm_key_buf[];
extern unsigned char hsm_bmac_buf[];
struct harv_hsm_test_case { const char *test_name; const char *key; int expect_changed; unsigned char expect[6]; };
typedef struct harv_hsm_test_case harv_hsm_test_case_t;
extern harv_hsm_test_case_t harvester_str_to_mac_bytes_suite[];
void construct_harvester_str_to_mac_bytes_input(const harv_hsm_test_case_t *tc);
void run_all_tests_harvester_str_to_mac_bytes(void);

typedef struct {
	bssid_t bssid;
	ssid_t  ssid;
	signed char signal_strength;
	wifi_channelBandwidth_t bandwidth;
	unsigned char bss_color;
	unsigned char channel_util;
	unsigned short sta_count;
} em_neighbor_t;

typedef struct {
	// Vap Index is constant. Any modification will not be reflected in OneWifi.
	unsigned int vap_index;
	// Vap Mode is constant. Any modification will not be reflected in OneWifi.
	em_vap_mode_t vap_mode;
	em_bss_id_t     id;
	em_interface_t  bssid;
	em_interface_t  ruid;
	ssid_t  ssid;
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
	em_short_string_t     fronthaul_akm[EM_MAX_AKMS];
	unsigned char   num_backhaul_akms;
	em_short_string_t     backhaul_akm[EM_MAX_AKMS];
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
	em_short_string_t mesh_sta_passphrase;
	unsigned int vlan_id;
	mac_address_t   mld_mac;
	mac_address_t   sta_mac;

	// Extra vendor information elements for the BSS
	// @note Don't manually allocate, use the helper functions to add/remove elements
	unsigned char vendor_elements[WIFI_AP_MAX_VENDOR_IE_LEN];
	size_t vendor_elements_len;
	bool    connect_status;
} em_bss_info_t;

// Forward declaration
class dm_sta_t;
#define GLOBAL_NET_ID "OneWifiMesh"

class dm_device_t{
	public:
		em_profile_type_t m_peer_profile = em_profile_type_reserved;
		em_profile_type_t get_peer_profile() const { return m_peer_profile; }
		void set_peer_profile(em_profile_type_t profile) { m_peer_profile = profile; }
		unsigned char *get_dev_interface_mac() { return m_device_info.intf.mac; }
		em_device_info_t    m_device_info;
		em_device_info_t *get_device_info(void) { return &m_device_info; }
};

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

typedef struct {
    em_long_string_t    id;
    unsigned short    num_of_devices;
    em_long_string_t    timestamp;
    em_interface_t    ctrl_id; // CM MAC
    unsigned char    num_mscs_disallowed_sta;
    em_string_t     mscs_disallowed_sta[EM_MSCS_DISALLOWED_STA];
    unsigned char    num_scs_disallowed_sta;
    em_string_t     scs_disallowed_sta[EM_SCS_DISALLOWED_STA];
    em_interface_t    colocated_agent_id; // Colocated Agent AL MAC
        em_media_type_t media;
} em_network_info_t;

typedef enum {
        em_scanner_type_radio = 1,
        em_scanner_type_sta,
} em_scanner_type_t;

typedef struct {
    em_long_string_t    net_id;
        mac_address_t   dev_mac;
        mac_address_t scanner_mac;
    unsigned char op_class;
    unsigned char channel;
        em_scanner_type_t       scanner_type;
} em_scan_result_id_t;

typedef struct {
        em_scan_result_id_t     id;
        unsigned char scan_status;
        em_long_string_t timestamp;
    unsigned char util;
    unsigned char noise;
        unsigned short num_neighbors;
        em_neighbor_t   neighbor[EM_MAX_NEIGHBORS];
    unsigned int  aggr_scan_duration;
    unsigned char scan_type;
} em_scan_result_t;

class dm_scan_result_t {
public:
    em_scan_result_t    m_scan_result;

    char *map_key;
};

typedef struct {
    mac_address_t ruid;
    unsigned char op_class;
    unsigned char channel;
    unsigned char scan_status;
    unsigned char timestamp_len;
    char timestamp[0];
}__attribute__((__packed__)) em_channel_scan_result_t;

typedef struct {
    mac_address_t sta_mac;
    unsigned char channel;
    unsigned char op_class;
    unsigned char rcpi;
    unsigned int  time_delta;
} em_unassoc_sta_metric_entry_t;

typedef struct {
    mac_address_t sta_mac;
    unsigned char channel;
    unsigned int  time_delta;
    unsigned char rcpi;
}__attribute__((__packed__)) em_unassoc_sta_metric_t;

class dm_network_t {
public:
    em_network_info_t   m_net_info;

public:
        int init();
	unsigned char *get_controller_interface_mac() { return m_net_info.ctrl_id.mac; }
};

typedef struct {
    em_long_string_t    id;
    ssid_t  ssid;
    em_long_string_t    pass_phrase;
    unsigned char   num_bands;
    em_short_string_t    band[EM_MAX_BANDS];
    bool    enable;
    unsigned char   num_akms;
    em_short_string_t akm[EM_MAX_AKMS];
    em_string_t suite_select;
    bool    advertisement;
    em_string_t mfp;
    mac_address_t   mobility_domain;
    unsigned char   num_hauls;
    em_haul_type_t haul_type[EM_MAX_HAUL_TYPES];
    em_string_t auth_type;
    unsigned short vlan_id;
} em_network_ssid_info_t;

typedef enum {
	em_freq_band_24,    //IEEE-1905-1-2013 table 6-23
	em_freq_band_5,
	em_freq_band_60,
	em_freq_band_6,     // Extended for 6GHz Band
	em_freq_band_unknown
} em_freq_band_t;

#define EM_MAX_OPCLASS 64

typedef enum {
    em_op_class_type_none,
    em_op_class_type_current,
    em_op_class_type_capability,
    em_op_class_type_cac_available,
    em_op_class_type_cac_non_occ,
    em_op_class_type_cac_active,
    em_op_class_type_preference,
    em_op_class_type_anticipated,
    em_op_class_type_scan_param,
    em_op_class_type_selection,
} em_op_class_type_t;

typedef struct {
    mac_address_t  ruid;
    em_op_class_type_t  type;
    unsigned int 	op_class;
} em_op_class_id_t;

typedef struct {
    em_op_class_id_t    id;
    unsigned int op_class;
    unsigned int    num_channels;
    unsigned int    channels[EM_MAX_CHANNELS_IN_LIST];
} em_op_class_info_t;

class dm_op_class_t {
	public:
		em_op_class_info_t m_op_class_info;
};

class dm_network_ssid_t{
	public:
                em_network_ssid_info_t    m_network_ssid_info;
};

class dm_easy_mesh_t {
	public:
		dm_network_t    m_network;
		hash_map_t          *m_sta_map = NULL;
		unsigned int    m_num_bss;
		unsigned int        m_num_net_ssids;
		dm_network_ssid_t   m_network_ssid[EM_MAX_NET_SSIDS];
		dm_bss_t    m_bss[EM_MAX_BSSS];
		hash_map_t              *m_scan_result_map = NULL;
		unsigned int m_num_unassoc_sta_metrics;
		em_unassoc_sta_metric_entry_t  m_unassoc_sta_metrics[EM_MAX_UNASSOC_STA];
		unsigned int 	m_num_opclass = 0;
		dm_op_class_t m_op_class[EM_MAX_OPCLASS];
	public:
		unsigned int get_num_op_class() { return m_num_opclass; }
		static em_freq_band_t get_freq_band_by_op_class(int op_class);
		static char *macbytes_to_string(mac_address_t mac, char *string);

		void set_db_cfg_param(db_cfg_type_t cfg_type, const char *criteria);

		dm_device_t m_device;
		dm_device_t *get_device() { return &m_device; }

		em_device_info_t *get_device_info(void) { return m_device.get_device_info(); }

		bool    m_colocated;

		bool get_colocated(void) { return m_colocated; }

		unsigned int m_num_ap_mld;
		unsigned int m_num_assoc_sta_mld;
		em_bss_info_t *get_bsta_bss_info() { return NULL; }

		dm_sta_t *find_sta(mac_address_t sta_mac, bssid_t bssid);

		//  ADD THIS LINE
		dm_sta_t *insert_sta(mac_address_t sta_mac, bssid_t bssid);

		em_bss_info_t *get_bss_info_with_mac(mac_address_t mac);

		dm_sta_t *get_first_sta(mac_address_t sta_mac);

		dm_sta_t *get_next_sta(mac_address_t sta_mac, dm_sta_t *psta);

		unsigned char *get_controller_interface_mac() { return m_network.get_controller_interface_mac(); }

		unsigned char *get_agent_al_interface_mac() { return m_device.get_dev_interface_mac(); }

		unsigned char *get_ctrl_al_interface_mac() { return m_network.get_controller_interface_mac(); }

		static int get_interfaces_list(em_interface_t interfaces[], unsigned int *num_interfaces);

		static int name_from_mac_address(const mac_address_t *mac, char *ifname);

		bool is_ssid_match(const ssid_t  &ssid);

		unsigned int get_num_bss() { return m_num_bss; }

		void set_num_bss(unsigned int num) { m_num_bss = num; }

		dm_bss_t *get_bss(unsigned int index) { return &m_bss[index]; }

		dm_bss_t *get_bss(mac_address_t radio, mac_address_t bss);

		// REQUIRED MEMBER
		hash_map_t *m_sta_assoc_map;
		em_db_cfg_param_t   m_db_cfg_param;
	        
		dm_scan_result_t *find_matching_scan_result(em_scan_result_id_t *id);
	
		dm_scan_result_t *create_new_scan_result(em_scan_result_id_t *id);

		std::vector<dm_scan_result_t*> m_scan_result_list;

		void clear_scan_results();
 
		~dm_easy_mesh_t();
		// Constructor
		dm_easy_mesh_t() {
			m_sta_assoc_map = NULL;
			m_num_bss = 0;
			m_num_net_ssids = 0;
			m_num_ap_mld = 0;
			m_num_assoc_sta_mld = 0;
			m_colocated = false;
			memset(&m_db_cfg_param, 0, sizeof(m_db_cfg_param));
			m_db_cfg_param.db_cfg_type = db_cfg_type_none;
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

		int handle_bsta_cap_report(unsigned char *buff, unsigned int len);

		int handle_bsta_radio_cap(unsigned char *buff, unsigned int len);

		int handle_client_info(unsigned char *buff, unsigned int len);

		int process_single_tlv_in_1905_message(unsigned char *buff, unsigned int len, em_tlv_type_t tlv_type, int (em_capability_t::*handler)(unsigned char*, unsigned int));

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

typedef struct {
    unsigned char   num;
    unsigned char   service[EM_MAX_SERVICE];
} __attribute__((__packed__)) em_supported_service_t;

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

	static bool parse_profile_tlv(const unsigned char *value, uint16_t value_len, em_profile_type_t *profile);

	bool get_supported_service(em_supported_service_t *svc);

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

typedef struct {
    mac_address_t bssid;
    unsigned char  ssid_len;
    char  ssid[0];
} __attribute__((__packed__)) em_ap_operational_bss_t;

typedef struct {
    mac_address_t ruid;
    unsigned char     bss_num;
    em_ap_operational_bss_t  bss[0];
} __attribute__((__packed__)) em_ap_op_bss_radio_t;

/* Only ruid (first field upstream) is read by em_msg_t::get_radio_id() */
typedef struct {
    mac_address_t   ruid;
} __attribute__((__packed__)) em_ap_radio_basic_cap_t;

typedef struct {
    mac_address_t   ruid;
} __attribute__((__packed__)) em_ap_radio_advanced_cap_t;

typedef struct {
    mac_address_t  ruid;
} __attribute__((__packed__)) em_ap_ht_cap_t;

typedef struct {
    mac_address_t  ruid;
} __attribute__((__packed__)) em_ap_vht_cap_t;

typedef struct {
    mac_address_t  ruid;
} __attribute__((__packed__)) em_ap_he_cap_t;

typedef struct {
    unsigned char    radios_num;
    em_ap_op_bss_radio_t   radios[0];
} __attribute__((__packed__)) em_ap_op_bss_t;

typedef enum {
	em_service_type_ctrl,
	em_service_type_agent,
	em_service_type_cli,
	em_service_type_none
} em_service_type_t;

class em_t;
class em_mgr_t;

class em_configuration_t {
	friend class test_em_configuration_t;
	friend class em_configuration_ap_op_bss_test_t;

		int handle_topology_response(unsigned char *buff, unsigned int len);
		void handle_ap_vendor_operational_bss(unsigned char *value, unsigned int len);
		int handle_bss_configuration_report(unsigned char *buff, unsigned int len);
		int handle_bsta_radio_cap(unsigned char *buff, unsigned int len);
		int handle_ap_mld_config_tlv(unsigned char *buff, unsigned int len);
		int handle_assoc_sta_mld_conf_rep_tlv(unsigned char *buff, unsigned int len);
		em_profile_type_t get_peer_profile(const mac_address_t al_mac);
		void set_peer_profile(const mac_address_t al_mac, em_profile_type_t profile);
		dm_easy_mesh_t *get_peer_dm(const mac_address_t al_mac);

	        int handle_ap_operational_bss(unsigned char *buff, unsigned int len);
	public:
		static em_wsc_msg_type_t get_wsc_msg_type(unsigned char *tlvs, unsigned int len) { return em_wsc_msg_type_m1; }
		virtual ~em_configuration_t() {}
		virtual dm_easy_mesh_t *get_data_model() = 0;
		virtual em_mgr_t *get_mgr() { return NULL; }
		virtual em_service_type_t get_service_type() { return em_service_type_ctrl; }

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

typedef enum {
    em_bus_event_type_none,
    em_bus_event_type_chirp,
    em_bus_event_type_reset,
    em_bus_event_type_dev_test,
    em_bus_event_type_set_dev_test,
    em_bus_event_type_get_network,
    em_bus_event_type_get_device,
    em_bus_event_type_remove_device,
    em_bus_event_type_get_radio,
    em_bus_event_type_get_ssid,
    em_bus_event_type_set_ssid,
    em_bus_event_type_get_channel,
    em_bus_event_type_set_channel,
    em_bus_event_type_scan_channel,
    em_bus_event_type_scan_result,
    em_bus_event_type_channel_select,
    em_bus_event_type_get_bss,
    em_bus_event_type_get_sta,
    em_bus_event_type_steer_sta,
    em_bus_event_type_disassoc_sta,
    em_bus_event_type_get_policy,
    em_bus_event_type_set_policy,
    em_bus_event_type_btm_sta,
    em_bus_event_type_start_dpp,
    em_bus_event_type_dev_init,
    em_bus_event_type_cfg_renew,
    em_bus_event_type_radio_config,
    em_bus_event_type_vap_config,
    em_bus_event_type_sta_list,
    em_bus_event_type_ap_cap_query,
    em_bus_event_type_client_cap_query,
    em_bus_event_type_listener_stop,
    em_bus_event_type_dm_commit,
    em_bus_event_type_m2_tx,
    em_bus_event_type_topo_sync,
    em_bus_event_type_onewifi_private_cb,
    em_bus_event_type_onewifi_mesh_sta_cb,
    em_bus_event_type_onewifi_radio_cb,
    em_bus_event_type_m2ctrl_configuration,
    em_bus_event_type_sta_assoc,
    em_bus_event_type_channel_pref_query,
    em_bus_event_type_channel_sel_req,
    em_bus_event_type_sta_link_metrics,
    em_bus_event_type_set_radio,
    em_bus_event_type_bss_tm_req,
    em_bus_event_type_btm_response,
        em_bus_event_type_channel_scan_params,
    em_bus_event_type_get_mld_config,
    em_bus_event_type_mld_reconfig,
    em_bus_event_type_beacon_query,
    em_bus_event_type_beacon_report,
    em_bus_event_type_recv_wfa_action_frame,
    em_bus_event_type_recv_gas_frame,
    em_bus_event_type_get_sta_client_type,
    em_bus_event_type_assoc_status,
    em_bus_event_type_ap_metrics_report,
    em_bus_event_type_bss_info,
    em_bus_event_type_get_reset,
    em_bus_event_type_recv_csa_beacon_frame,
    em_bus_event_type_bsta_cap_req,
    em_bus_event_type_link_quality_report,
    em_bus_event_type_client_assoc_ctrl_req,
    em_bus_event_type_unassoc_sta_query,
    em_bus_event_type_unassoc_sta_link_metrics_query,
    em_bus_event_type_unassoc_sta_result,
    em_bus_event_type_failed_conn,

    em_bus_event_type_max
} em_bus_event_type_t;

typedef struct {
        mac_address_t ruid;
        unsigned int num_op_classes;
        struct {
                unsigned char op_class;
                unsigned int num_channels;
                unsigned char   channels[EM_MAX_CHANNELS_IN_LIST];
        } op_class[EM_MAX_OP_CLASS];
} em_scan_params_t;

typedef struct {
    mac_address_t al_mac;
} em_cmd_unassoc_sta_query_params_t;

typedef enum {
    em_network_node_data_type_invalid,
    em_network_node_data_type_false,
    em_network_node_data_type_true,
    em_network_node_data_type_null,
    em_network_node_data_type_number,
    em_network_node_data_type_string,
    em_network_node_data_type_obj,
    em_network_node_data_type_array_obj,
    em_network_node_data_type_array_str,
    em_network_node_data_type_array_num,
    em_network_node_data_type_raw,
} em_network_node_data_type_t;

typedef struct {
    bool collapsed;
    unsigned int orig_node_ctr;
    unsigned int node_ctr;
    unsigned int node_pos;
} em_node_display_info_t;

typedef struct em_network_node {
    em_long_string_t   key;
    em_node_display_info_t      display_info;
    em_network_node_data_type_t type;
    em_long_string_t    value_str;
    unsigned int        value_int;
    unsigned int        num_children;
    struct em_network_node     *child[EM_MAX_DM_CHILDREN];
} em_network_node_t;

typedef struct {
    unsigned char num_element_id;
    unsigned char element_list[6];
}__attribute__((__packed__)) em_beacon_element_list_t;

typedef struct {
    unsigned char ap_channel_rprt_len;
    unsigned char ap_channel_op_class;
    unsigned char ap_channel_list[EM_MAX_CHANNELS_IN_LIST];
}__attribute__((__packed__)) em_beacon_ap_channel_rprt_t;

typedef struct {
    mac_address_t sta_mac_addr;
    unsigned char op_class;
    unsigned char channel_num;
    bssid_t bssid;
    unsigned char rprt_detail;
    unsigned char ssid_len;
    ssid_t ssid;
    unsigned char num_ap_channel_rprt;
    em_beacon_ap_channel_rprt_t ap_channel_rprt[EM_MAX_NEIGHBORS];
    em_beacon_element_list_t element_list;
}__attribute__((__packed__)) em_beacon_metrics_query_t;

typedef em_scan_params_t em_cmd_scan_params_t;
typedef em_beacon_metrics_query_t em_cmd_beacon_metrics_param_t;

typedef struct {
    unsigned int num_args;
    em_long_string_t args[EM_CLI_MAX_ARGS];
    em_long_string_t fixed_args;
} em_cmd_args_t;

typedef struct {
    mac_address_t       sta_mac;
    bssid_t     source;
    bssid_t     target;
    unsigned int        request_mode;
    bool        disassoc_imminent;
    bool        btm_abridged;
    bool        link_removal_imminent;
    unsigned int        steer_opportunity_win;
    unsigned int    btm_disassociation_timer;
    unsigned int        target_op_class;
    unsigned int        target_channel;
} em_cmd_steer_params_t;

typedef struct {
    bssid_t     source;
    mac_address_t       sta_mac;
    unsigned char status_code;
    bssid_t     target;
} em_cmd_btm_report_params_t;

typedef struct {
    mac_address_t       sta_mac;
    bssid_t     bssid;
    unsigned int disassoc_time;
    unsigned int reason;
    bool        silent;
} em_disassoc_params_t;

typedef struct {
    unsigned int num;
    em_disassoc_params_t        params[MAX_STA_TO_DISASSOC];
} em_cmd_disassoc_params_t;

typedef struct {
    int num_radios;
    mac_address_t   ruid[EM_MAX_RADIO_PER_AGENT];
    bool sta_link_metrics_include;
    bool sta_traffic_stats_include;
    bool wifi6_status_report_include;
} __attribute__((__packed__)) em_cmd_ap_metrics_rprt_params_t;

typedef struct {
    union {
        em_cmd_args_t   args;
        em_cmd_steer_params_t   steer_params;
        em_cmd_btm_report_params_t  btm_report_params;
        em_cmd_disassoc_params_t        disassoc_params;
                em_cmd_scan_params_t    scan_params;
        em_cmd_ap_metrics_rprt_params_t ap_metrics_params;
        em_cmd_unassoc_sta_query_params_t unassoc_sta_query_params;
        em_cmd_beacon_metrics_param_t beacon_metrics_params;
    } u;
        em_network_node_t *net_node;
} em_cmd_params_t;

class em_mgr_t {
	public:
		em_t *get_al_node() { return NULL; }
		dm_easy_mesh_t *get_data_model(const char *net_id, const unsigned char *al_mac = NULL) { return NULL; }
		void io_process(em_bus_event_type_t type, unsigned char *data, unsigned int len, em_cmd_params_t *params = NULL);
};

inline void em_mgr_t::io_process(em_bus_event_type_t type,
                                 unsigned char *data,
                                 unsigned int len,
                                 em_cmd_params_t *params)
{
    (void)type;
    (void)data;
    (void)len;
    (void)params;
}

inline unsigned char *get_radio_interface_mac()
{
    static unsigned char mac[sizeof(mac_address_t)] = {0};
    return mac;
}

class em_t : public em_configuration_t {
	public:
		em_t() {}
		em_t(em_interface_t *ruid, em_freq_band_t band, dm_easy_mesh_t *dm, em_mgr_t *mgr,
				em_profile_type_t profile, em_service_type_t type, bool is_al_em = false)
		{
			memcpy(&m_ruid, ruid, sizeof(em_interface_t));
			m_service_type = type;
			m_profile_type = profile;
			m_data_model = dm;
			m_mgr = mgr;
		}

		bool m_ssid_mismatch = false;
		void set_ssid_mismatch(bool mismatch) { m_ssid_mismatch = mismatch; }
		em_service_type_t   m_service_type;
		dm_easy_mesh_t*  m_data_model;

		int m_fd;

		em_interface_t  m_ruid;

		em_sm_t  m_sm;

		em_mgr_t        *m_mgr;

		em_mgr_t *get_mgr() override { return m_mgr; }

		em_service_type_t   get_service_type() override { return m_service_type; }

		void set_state(em_state_t state) {  m_sm.set_state(state); }

		int set_bp_filter();

		int send_frame(unsigned char *buff, unsigned int len, bool multicast = false);

		unsigned char   *get_radio_interface_mac() { return m_ruid.mac; }

		unsigned char *get_al_interface_mac() { return (m_service_type == em_service_type_agent) ?
            m_data_model->get_agent_al_interface_mac():m_data_model->get_ctrl_al_interface_mac(); }

		unsigned char *get_peer_mac() { return (m_service_type == em_service_type_ctrl) ? m_data_model->get_agent_al_interface_mac():m_data_model->get_controller_interface_mac(); }

		em_profile_type_t   m_profile_type;

		em_profile_type_t   get_profile_type() { return m_profile_type; }

		dm_easy_mesh_t *get_data_model() override { return m_data_model; }
	       
};

static em_t m_sm;

inline void set_state(em_state_t state)
{
	m_sm.set_state(state);
}

class dm_bss_t;

typedef struct {
	bssid_t bssid;
	unsigned char channel_util;
	unsigned short num_sta;
	unsigned char reserved : 4;
	unsigned char est_service_params_VI_bit : 1;
	unsigned char est_service_params_VO_bit : 1;
	unsigned char est_service_params_BK_bit : 1;
	unsigned char est_service_params_BE_bit : 1;
	unsigned char est_service_params_BE[3];
	unsigned char est_service_params_BK[3];
	unsigned char est_service_params_VO[3];
	unsigned char est_service_params_VI[3];
} __attribute__((__packed__)) em_ap_metric_t;

typedef struct {
    unsigned char op_class;
    unsigned char num_channels;
    unsigned char channel_list[0];
} __attribute__((__packed__)) em_channel_scan_req_op_class_t;

typedef struct {
    unsigned char reserved : 7;
    unsigned char perform_fresh_scan : 1;
    unsigned char num_radios;
    mac_address_t ruid;
    unsigned char num_op_classes;
        em_channel_scan_req_op_class_t op_class[0];
}__attribute__((__packed__)) em_channel_scan_req_t;

class em_metrics_t {

	virtual dm_easy_mesh_t *get_data_model() = 0;
	virtual em_profile_type_t get_profile_type() = 0;

	public:
	int handle_assoc_sta_traffic_stats(unsigned char *buff, bssid_t bssid);
	int handle_ap_metrics_response(unsigned char *buff, unsigned int len);
	int handle_ap_metrics_tlv(unsigned char *buff, bssid_t bssid);
	int handle_assoc_sta_link_metrics_tlv(unsigned char *buff, unsigned int tlv_len);
	int handle_assoc_sta_ext_link_metrics_tlv(unsigned char *buff, unsigned int tlv_len);
	int handle_assoc_sta_vendor_link_metrics_tlv(unsigned char *buff, unsigned int len);
	int handle_beacon_metrics_query(unsigned char *buff, unsigned int len);
	virtual int send_frame(unsigned char *buff, unsigned int len, bool multicast = false) = 0;
	int send_beacon_metrics_query_ack(mac_address_t sta_mac, unsigned short msg_id, unsigned char reason);
	int handle_unassoc_sta_link_metrics_tlv(unsigned char *buff, unsigned int tlv_len);
	virtual em_mgr_t *get_mgr() = 0;
};	

class em_channel_t {
	std::unique_ptr<em_scan_params_t> m_last_scan_req;
	bool                              m_last_scan_req_valid;
public:
	int send_1905_ack_message(unsigned short msg_id, bool ack_from);
	int handle_channel_scan_req(unsigned char *buff, unsigned int len);
	short create_channel_scan_req_tlv(unsigned char *buff);
	virtual em_freq_band_t get_band() { return em_freq_band_24; }
	int handle_channel_scan_rprt(unsigned char *buff, unsigned int len);
	virtual dm_easy_mesh_t *get_data_model() = 0;
	virtual em_mgr_t *get_mgr() = 0;
	virtual int send_frame(unsigned char *buff, unsigned int len, bool multicast = false) = 0;
	void fill_scan_result(dm_scan_result_t *scan_res, em_channel_scan_result_t *res, unsigned char *start, unsigned char *end);

};

/* --- instant_msmt_macAddr harness --- */
#define IAM_PAD 64
#define IAM_MAC_SZ (64 + IAM_PAD)
extern char iam_mgr_buf[];
extern char iam_mac_buf[];
extern int  iam_num_vaps, iam_found_vap, iam_assoc_checks;
struct harv_iam_test_case { const char *test_name; const char *mac; int found_vap; int want_ap; int want_found; unsigned char want_mac[6]; };
typedef struct harv_iam_test_case harv_iam_test_case_t;
extern harv_iam_test_case_t instant_msmt_macAddr_suite[];
void construct_instant_msmt_macAddr_input(const harv_iam_test_case_t *tc);
void run_all_tests_instant_msmt_macAddr(void);

/* --- webconfig_harvester_apply harness --- */
#define WHA_PAD 64
extern char wha_wd_buf[];     /* wha_subdoc_data_t + WHA_PAD */
extern int  wha_rep_calls, wha_def_calls, wha_ttl_calls, wha_mac_calls, wha_en_calls;
extern unsigned char wha_en_mac[6];
extern int  wha_en_val;
struct harv_wha_test_case { const char *test_name; const char *mac; int enabled; unsigned char want_mac[6]; };
typedef struct harv_wha_test_case harv_wha_test_case_t;
extern harv_wha_test_case_t webconfig_harvester_apply_suite[];
void construct_webconfig_harvester_apply_input(const harv_wha_test_case_t *tc);
void run_all_tests_webconfig_harvester_apply(void);

/* --- levl_csi_status_publish harness --- */
#define LCSP_PAD 64
extern unsigned char lcsp_mac_buf[];
extern char lcsp_pub_name[256], lcsp_pub_value[256];
extern int  lcsp_publish_calls, lcsp_publish_fail;
struct lv_lcsp_test_case { const char *test_name; unsigned char mac[6]; unsigned int status; int publish_fail; int want_ret; const char *want_value; };
typedef struct lv_lcsp_test_case lv_lcsp_test_case_t;
extern lv_lcsp_test_case_t levl_csi_status_publish_suite[];
void construct_levl_csi_status_publish_input(const lv_lcsp_test_case_t *tc);
void run_all_tests_levl_csi_status_publish(void);

/* --- schedule_from_pending_map_locked harness --- */
#define LSP_PAD 64
typedef struct { int sched_handler_id; mac_address_t mac_addr; unsigned int ap_index; int request_count; int duration; int interval; struct timeval last_time_publish; } levl_sched_data_t;
extern char lsp_app_buf[];
extern levl_sched_data_t *lsp_entries[8];
extern int  lsp_n, lsp_sched_calls, lsp_sched_ap, lsp_sched_dur, lsp_sched_int;
extern unsigned char lsp_sched_mac[6];
struct lv_lsp_test_case { const char *test_name; int n; unsigned char mac5[3]; int num_cur; int max_cli; int null_mode; int want_ret; int want_sched; int want_ap; int want_remaining; };
typedef struct lv_lsp_test_case lv_lsp_test_case_t;
extern lv_lsp_test_case_t schedule_from_pending_map_locked_suite[];
void construct_schedule_from_pending_map_locked_input(const lv_lsp_test_case_t *tc);
void lsp_free_entries(void);
void run_all_tests_schedule_from_pending_map_locked(void);

/* --- get_max_probe_ttl_cnt harness --- */
#define GMT_PAD 64
#define GMT_FILE_SZ 512
extern char gmt_file_buf[];      /* backing store of the fmemopen'ed ttl file (GMT_FILE_SZ + GMT_PAD) */
extern size_t gmt_file_len;
extern int gmt_have_file;
struct lv_gmt_test_case { const char *test_name; const char *content; int repeat; int have_file; unsigned int want; };
typedef struct lv_gmt_test_case lv_gmt_test_case_t;
extern lv_gmt_test_case_t get_max_probe_ttl_cnt_suite[];
void construct_get_max_probe_ttl_cnt_input(const lv_gmt_test_case_t *tc);
void run_all_tests_get_max_probe_ttl_cnt(void);

/* --- apps_probe_req_frame_event harness --- */
#define LPR_PAD 64
extern char lpr_app_buf[];    /* struct wifi_app + LPR_PAD */
extern char lpr_msg_buf[];    /* frame_data_t + LPR_PAD (caller-owned msg) */
extern int  lpr_count_override;
void lpr_setup(const char *key, int preexist, int pre_ap);
int  lpr_result(char *key_out, size_t key_sz, int *update_calls, int *first_ap);
void lpr_teardown(void);
struct lv_lpr_test_case { const char *test_name; int map_null; int count_override; int preexist; int pre_ap; int msg_ap; int want_frames; int want_first_ap; int want_update; const char *want_key; };
typedef struct lv_lpr_test_case lv_lpr_test_case_t;
extern lv_lpr_test_case_t apps_probe_req_frame_event_suite[];
void construct_apps_probe_req_frame_event_input(const lv_lpr_test_case_t *tc);
void run_all_tests_apps_probe_req_frame_event(void);

/* --- apps_auth_frame_event harness --- */
#define AAF_PAD 64
extern char aaf_app_buf[];
extern char aaf_msg_buf[];
extern char aaf_sent_ns[256];
extern int  aaf_send_calls;
struct lv_aaf_test_case { const char *test_name; int ap_index; const char *want_ns; };
typedef struct lv_aaf_test_case lv_aaf_test_case_t;
extern lv_aaf_test_case_t apps_auth_frame_event_suite[];
void construct_apps_auth_frame_event_input(const lv_aaf_test_case_t *tc);
void run_all_tests_apps_auth_frame_event(void);

/* --- apps_assoc_req_frame_event harness --- */
#define AAR_PAD 64
#define AAR_MAX_SENDS 4
extern char aar_app_buf[];
extern char aar_msg_buf[];
extern char aar_sent_ns[AAR_MAX_SENDS][64];
extern int  aar_send_calls;
void aar_setup(const char *key, int n_frames, const int *aps);
int  aar_remaining(void);
void aar_teardown(void);
struct lv_aar_test_case { const char *test_name; int n_frames; int aps[2]; int msg_ap; int want_sends; const char *want_ns0; const char *want_ns1; int want_remaining; };
typedef struct lv_aar_test_case lv_aar_test_case_t;
extern lv_aar_test_case_t apps_assoc_req_frame_event_suite[];
void construct_apps_assoc_req_frame_event_input(const lv_aar_test_case_t *tc);
void run_all_tests_apps_assoc_req_frame_event(void);

/* --- apps_reassoc_req_frame_event harness --- */
#define ARF_PAD 64
extern char arf_app_buf[];
extern char arf_msg_buf[];
extern char arf_sent_ns[256];
extern int  arf_send_calls;
struct lv_arf_test_case { const char *test_name; int ap_index; const char *want_ns; };
typedef struct lv_arf_test_case lv_arf_test_case_t;
extern lv_arf_test_case_t apps_reassoc_req_frame_event_suite[];
void construct_apps_reassoc_req_frame_event_input(const lv_arf_test_case_t *tc);
void run_all_tests_apps_reassoc_req_frame_event(void);

/* --- process_levl_sounding_timeout harness --- */
#define LST_PAD 64
typedef struct { mac_address_t mac_addr; int ap_index; } timeout_data_t;
extern char lst_ctrl_buf[];
extern char lst_app_buf[];
extern char lst_csi_buf[];
extern timeout_data_t *lst_tdata;
extern int  lst_null_ctrl, lst_null_app;
extern int  lst_pub_calls, lst_pub_status, lst_sched_calls, lst_stop_calls, lst_stop_ap;
extern unsigned char lst_pub_mac[6], lst_stop_mac[6];
void lst_set_slot(const unsigned char *mac, int ap_index);
int  lst_slot_present(void);
struct lv_lst_test_case { const char *test_name; int null_tdata; int null_ctrl; int null_app; int null_csi; int null_map; int slot; int want_ret; int want_stop; int want_pub; int want_sched; };
typedef struct lv_lst_test_case lv_lst_test_case_t;
extern lv_lst_test_case_t process_levl_sounding_timeout_suite[];
void construct_process_levl_sounding_timeout_input(const lv_lst_test_case_t *tc);
void run_all_tests_process_levl_sounding_timeout(void);

/* --- schedule_mac_for_sounding_locked harness --- */
#define LSM_PAD 64
extern unsigned char lsm_mac_buf[];
extern char lsm_ctrl_buf[];
extern char lsm_app_buf[];
extern char lsm_csi_buf[];
extern char lsm_curr_token, lsm_pend_token;
extern void *lsm_owned[8];
extern int  lsm_n_owned;
extern void *lsm_last_tdata_expect;
extern char lsm_last_key[64];
extern int  lsm_null_app, lsm_dup, lsm_curr_count, lsm_curr_put, lsm_pend_put, lsm_sched_calls, lsm_sched_ret;
extern int  lsm_pub_calls, lsm_pub_status[4], lsm_start_calls, lsm_stop_calls, lsm_start_ret;
void lsm_cleanup(void);
struct lv_lsm_test_case { const char *test_name; int null_app; int subscribed; int null_csi; int null_map; int dup; int paused; int curr_count; int max_clients; int start_ret; int sched_ret; int want_ret; int want_curr_put; int want_pend_put; int want_start; int want_stop; int want_pub; int want_sched; };
typedef struct lv_lsm_test_case lv_lsm_test_case_t;
extern lv_lsm_test_case_t schedule_mac_for_sounding_locked_suite[];
void construct_schedule_mac_for_sounding_locked_input(const lv_lsm_test_case_t *tc);
void run_all_tests_schedule_mac_for_sounding_locked(void);

/* --- levl_csi_publish harness --- */
#define LCP_PAD 64
#define LCP_SINK_SZ (CSI_HEADER_SIZE + sizeof(wifi_csi_data_t) + 16)
extern unsigned char lcp_mac_buf[];
extern char lcp_csi_buf[];
extern char lcp_ctrl_buf[];
extern char lcp_app_buf[];
extern unsigned char lcp_sink[];
extern char lcp_pub_name[128];
extern unsigned int lcp_pub_len, lcp_write_len;
extern int  lcp_pub_calls, lcp_open_calls, lcp_write_calls, lcp_open_ret, lcp_null_app;
struct lv_lcp_test_case { const char *test_name; int fifo; int fd; int open_ret; int null_app; int want_pub; int want_open; int want_write; int want_hdr; };
typedef struct lv_lcp_test_case lv_lcp_test_case_t;
extern lv_lcp_test_case_t levl_csi_publish_suite[];
void construct_levl_csi_publish_input(const lv_lcp_test_case_t *tc);
void run_all_tests_levl_csi_publish(void);

/* --- process_levl_csi harness --- */
#define LPC_PAD 64
extern char lpc_app_buf[];
extern char lpc_csi_buf[];
extern int  lpc_pub_calls, lpc_drop_on_publish;
extern long lpc_entry_secs_before;
void lpc_set_slot(const unsigned char *mac, int interval, long last_pub_offset_secs);
int  lpc_slot_updated(void);
void lpc_free_slot(void);
struct lv_lpc_test_case { const char *test_name; int map_null; int slot; int interval; long last_off; int drop; int want_ret; int want_pub; int want_updated; };
typedef struct lv_lpc_test_case lv_lpc_test_case_t;
extern lv_lpc_test_case_t process_levl_csi_suite[];
void construct_process_levl_csi_input(const lv_lpc_test_case_t *tc);
void run_all_tests_process_levl_csi(void);

/* --- levl_disassoc_device_event harness --- */
#define LDS_PAD 64
extern char lds_ctrl_buf[];
extern char lds_app_buf[];
extern char lds_csi_buf[];
extern char lds_data_buf[];
extern int  lds_null_app;
extern int  lds_pub_calls, lds_pub_status, lds_stop_calls, lds_stop_ap, lds_cancel_calls, lds_cancel_id, lds_freearg_calls;
extern unsigned char lds_pub_mac[6], lds_stop_mac[6];
void lds_set_slots(const unsigned char *mac, int curr, int sched_id, int pend);
int  lds_curr_present(void);
int  lds_pend_present(void);
struct lv_lds_test_case { const char *test_name; int null_data; int null_app; int null_csi; int null_curr_map; int null_pend_map; int curr; int sched_id; int pend; int num_sounding; int want_stop; int want_pub; int want_cancel; int want_freearg; int want_nsnd; int want_cur_left; int want_pend_left; };
typedef struct lv_lds_test_case lv_lds_test_case_t;
extern lv_lds_test_case_t levl_disassoc_device_event_suite[];
void construct_levl_disassoc_device_event_input(const lv_lds_test_case_t *tc);
void run_all_tests_levl_disassoc_device_event(void);

/* --- levl_event_webconfig_set_data harness --- */
#define LSE_PAD 64
extern char lse_apps_buf[];
extern char lse_doc_buf[];
extern int  lse_ap_ret, lse_sched_calls, lse_sched_ap, lse_sched_dur, lse_sched_int;
extern unsigned char lse_sched_mac[6];
struct lv_lse_test_case { const char *test_name; int type_levl; int max_clients; int dur; int interval; int mac_set; int ap_ret; int init_dur; int init_int; int want_max; int want_dur; int want_int; int want_sched; };
typedef struct lv_lse_test_case lv_lse_test_case_t;
extern lv_lse_test_case_t levl_event_webconfig_set_data_suite[];
void construct_levl_event_webconfig_set_data_input(const lv_lse_test_case_t *tc);
void run_all_tests_levl_event_webconfig_set_data(void);

/* --- process_csi_stop_levl_locked harness --- */
#define LCS_PAD 64
extern char lcs_ctrl_buf[];
extern char lcs_app_buf[];
extern char lcs_csi_buf[];
extern int  lcs_null_ctrl;
extern int  lcs_pub_calls, lcs_pub_status, lcs_stop_calls, lcs_cancel_calls, lcs_cancel_id, lcs_freearg_calls;
extern levl_sched_data_t *lcs_curr[4];
extern int  lcs_n;
extern char *lcs_pend_keys[4];
extern levl_sched_data_t *lcs_pend_vals[4];
extern int  lcs_pend_n;
void lcs_set_entries(int n, int sched_id);
int  lcs_curr_count(void);
int  lcs_pend_count(void);
int  lcs_pend_ok(void);
struct lv_lcs_test_case { const char *test_name; int null_ctrl; int null_app; int null_map; int n; int sched_id; int want_ret; int want_stop; int want_pub; int want_cancel; int want_curr; int want_pend; };
typedef struct lv_lcs_test_case lv_lcs_test_case_t;
extern lv_lcs_test_case_t process_csi_stop_levl_locked_suite[];
void construct_process_csi_stop_levl_locked_input(const lv_lcs_test_case_t *tc);
void run_all_tests_process_csi_stop_levl_locked(void);

/* --- radio_temperature_response harness --- */
#define LRT_PAD 64
extern char lrt_ctrl_buf[];
extern char lrt_app_buf[];
extern char lrt_resp_buf[];
extern char lrt_stat_buf[];
extern int  lrt_null_ctrl, lrt_null_app, lrt_publish_fail;
extern int  lrt_pub_calls, lrt_pub_type;
extern unsigned int lrt_pub_value;
extern char lrt_pub_name[128];
struct lv_lrt_test_case { const char *test_name; int null_ctrl; int null_app; unsigned int radio_index; int n; unsigned int temp; int pub_fail; int want_ret; int want_pub; const char *want_name; };
typedef struct lv_lrt_test_case lv_lrt_test_case_t;
extern lv_lrt_test_case_t radio_temperature_response_suite[];
void construct_radio_temperature_response_input(const lv_lrt_test_case_t *tc);
void run_all_tests_radio_temperature_response(void);

/* --- levl_get_handler harness --- */
#define LGH_PAD 64
#define LGH_NAME_MAX 400
extern char lgh_ctrl_buf[];
extern char lgh_app_buf[];
extern char lgh_pdata_buf[];      /* raw_data_t + LGH_PAD (type is local to the handler: size in LGH_PDATA_SZ) */
extern char lgh_name_buf[];       /* event_name copy, exactly strlen+1, poisoned tail */
extern size_t lgh_name_len;       /* strlen+1 of the name in lgh_name_buf */
extern int  lgh_null_ctrl, lgh_null_app, lgh_malloc_fail, lgh_null_name;
#define LGH_PDATA_SZ 24           /* sizeof(raw_data_t): int + union(8) + size_t -> 24 on LP64 */
struct lv_lgh_test_case { const char *test_name; int null_ctrl; int null_app; int null_name; int malloc_fail; const char *name; int max_clients; int duration; int want_ret; int want_type; unsigned int want_u32; const char *want_str; };
typedef struct lv_lgh_test_case lv_lgh_test_case_t;
extern lv_lgh_test_case_t levl_get_handler_suite[];
void construct_levl_get_handler_input(const lv_lgh_test_case_t *tc);
void run_all_tests_levl_get_handler(void);

/* --- levl_set_handler harness --- */
#define LSH_PAD 64
#define LSH_NAME_MAX 400
#define LSH_STR_MAX 64
#define LSH_PDATA_SZ 24           /* sizeof(raw_data_t) on LP64 */
extern char lsh_pdata_buf[];      /* raw_data_t out/in param + LSH_PAD */
extern char lsh_name_buf[];       /* event_name, exactly strlen+1, poisoned tail */
extern size_t lsh_name_len;
extern char lsh_str_buf[];        /* the string value, exactly strlen+1, poisoned tail */
extern size_t lsh_str_len;
extern int  lsh_malloc_fail, lsh_push_calls;
extern levl_config_t lsh_pushed;
struct lv_lsh_test_case { const char *test_name; const char *name; int data_type; const char *str; unsigned int u32; int malloc_fail; int want_ret; int want_push; int check_mac; int want_max; int want_dur; int want_int; };
typedef struct lv_lsh_test_case lv_lsh_test_case_t;
extern lv_lsh_test_case_t levl_set_handler_suite[];
void construct_levl_set_handler_input(const lv_lsh_test_case_t *tc);
void run_all_tests_levl_set_handler(void);

/* --- levl_init harness --- */
#define LLI_PAD 64
extern char lli_app_buf[];
extern char lli_csi_buf[];
extern char lli_ctrl_buf[];
extern int  lli_app_init_ret, lli_null_ctrl, lli_null_csi, lli_map_fail_at, lli_mkfifo_err, lli_bus_open_ret, lli_bus_reg_ret;
extern int  lli_radios, lli_vaps;
extern int  lli_app_init_calls, lli_map_calls, lli_sched_calls, lli_mkfifo_calls, lli_open_calls, lli_reg_calls, lli_mutex_init_calls;
extern int  lli_reg_n, lli_reg_names_ok, lli_reg_rows0, lli_reg_rows10;
extern char lli_reg_first[128], lli_reg_last[128];
extern int  lli_sched_period;
extern char lli_map_tokens[8];   /* distinct non-NULL tokens handed out by hash_map_create */
struct lv_lli_test_case { const char *test_name; int app_init_ret; int null_ctrl; int null_csi; int map_fail_at; int mkfifo_err; int bus_open_ret; int bus_reg_ret; int radios; int vaps; int lock_inited; int want_ret; int want_reg; int want_inited; };
typedef struct lv_lli_test_case lv_lli_test_case_t;
extern lv_lli_test_case_t levl_init_suite[];
void construct_levl_init_input(const lv_lli_test_case_t *tc);
void run_all_tests_levl_init(void);

/* --- link_quality_init harness --- */
#define LQI_PAD 64
extern char lqi_app_buf[];
extern char lqi_ctrl_buf[];       /* 256-byte handle stand-in + LQI_PAD */
extern int  lqi_app_init_ret, lqi_bus_open_ret, lqi_bus_reg_ret;
extern int  lqi_app_init_calls, lqi_open_calls, lqi_reg_calls, lqi_reg_n, lqi_reg_type, lqi_reg_fmt;
extern char lqi_reg_name[128], lqi_open_name[64];
extern void *lqi_reg_handle;
struct lv_lqi_test_case { const char *test_name; int app_init_ret; int bus_open_ret; int bus_reg_ret; int want_ret; int want_open; int want_reg; int want_state_reset; };
typedef struct lv_lqi_test_case lv_lqi_test_case_t;
extern lv_lqi_test_case_t link_quality_init_suite[];
void construct_link_quality_init_input(const lv_lqi_test_case_t *tc);
void run_all_tests_link_quality_init(void);

/* --- shared bus / levl / linkquality types and constants (used by the levl_*, radio_temperature_response, link_quality_init and memwraptool harnesses) --- */
#ifndef LV_OWN_BUS_TYPES      /* older harness files that carry their own local bus types define this before including common.h */
typedef enum { bus_error_success = 0, bus_error_general = 1, bus_error_invalid_input = 2, bus_error_out_of_resources = 3 } bus_error_t;
typedef enum { bus_element_type_table = 1, bus_element_type_method = 2, bus_element_type_event = 3, bus_element_type_property = 4 } bus_element_type_t;
typedef enum { slow_speed = 0 } bus_speed_t;
typedef enum { bus_data_type_none = 0, bus_data_type_string = 3, bus_data_type_uint32 = 7, bus_data_type_bytes = 10, bus_data_type_object = 11 } bus_data_type_t;
typedef struct { int data_type; union { uint32_t u32; void *bytes; } raw_data; size_t raw_data_len; } raw_data_t;
typedef struct { int unused; } bus_user_data_t;
typedef struct {
    void *get_handler, *set_handler, *table_add_row_handler,
         *table_remove_row_handler, *event_sub_handler, *method_handler;
} bus_callback_table_t;
typedef struct {
    bus_data_type_t data_format;
    bool            data_permission;
    long int        min_data_range;
    long int        max_data_range;
    uint32_t        num_of_str_validation;
    char          **str_validation;
} data_model_properties_t;
typedef struct bus_data_element {
    char                   *full_name;
    bus_element_type_t      type;
    bus_callback_table_t    cb_table;
    bus_speed_t             bus_speed;
    uint32_t                num_of_table_row;
    data_model_properties_t data_model_prop;
} bus_data_element_t;
typedef struct {
    bus_error_t (*bus_open_fn)(void *handle, const char *component);
    bus_error_t (*bus_reg_data_element_fn)(void *handle, bus_data_element_t *elems, uint32_t num);
    bus_error_t (*bus_event_publish_fn)(void *handle, const char *name, raw_data_t *data);
} wifi_bus_desc_t;
#endif /* LV_OWN_BUS_TYPES */
typedef int wifi_event_subtype_t;
#ifndef WIFI_APPS
#define WIFI_APPS 0
#endif
#ifndef WIFI_CTRL
#define WIFI_CTRL 0
#endif
#ifndef WIFI_WEBCONFIG
#define WIFI_WEBCONFIG 0
#endif
#ifndef ZERO_TABLE
#define ZERO_TABLE 0
#endif
#ifndef RETURN_OK
#define RETURN_OK  0
#endif
#ifndef RETURN_ERR
#define RETURN_ERR (-1)
#endif
#ifndef FALSE
#define FALSE 0
#endif
#ifndef TRUE
#define TRUE 1
#endif
#ifndef wifi_app_inst_levl
#define wifi_app_inst_levl 5
#endif
#ifndef wifi_app_inst_csi
#define wifi_app_inst_csi 4096
#endif
#ifndef webconfig_subdoc_type_levl
#define webconfig_subdoc_type_levl 5
#endif
#ifndef MAX_LEVL_CSI_CLIENTS
#define MAX_LEVL_CSI_CLIENTS 5
#endif
#ifndef DEFAULT_SOUNDING_DURATION_MS
#define DEFAULT_SOUNDING_DURATION_MS 2000
#endif
#ifndef MIN_LEVL_PUBLISH_INTERVAL_MS
#define MIN_LEVL_PUBLISH_INTERVAL_MS 100
#endif
#ifndef MIN_LEVL_SOUNDING_DURATION_MS
#define MIN_LEVL_SOUNDING_DURATION_MS 1000
#endif
#ifndef APPS_FRAME_EXEC_TIMEOUT_PERIOD
#define APPS_FRAME_EXEC_TIMEOUT_PERIOD (30 * 60)
#endif
#ifndef CSI_LEVL_PIPE
#define CSI_LEVL_PIPE "/tmp/csi_levl_pipe"
#endif
#ifndef MIN_MAC_LEN
#define MIN_MAC_LEN 12
#endif
#define WIFI_EVENTS_VAP_TABLE               "Device.WiFi.Events.VAP.{i}."
#define WIFI_ANALYTICS_FRAME_EVENTS         "Device.WiFi.Events.VAP.{i}.Frames.Mgmt"
#define WIFI_ANALYTICS_DATA_EVENTS          "Device.WiFi.Events.VAP.{i}.Frames.Data"
#define WIFI_LEVL_CLIENTMAC                 "Device.WiFi.X_RDK_CSI_LEVL.clientMac"
#define WIFI_LEVL_NUMBEROFENTRIES           "Device.WiFi.X_RDK_CSI_LEVL.maxNumberCSIClients"
#define WIFI_LEVL_CSI_DATA                  "Device.WiFi.X_RDK_CSI_LEVL.data"
#define WIFI_LEVL_CSI_DATAFIFO              "Device.WiFi.X_RDK_CSI_LEVL.datafifo"
#define WIFI_LEVL_SOUNDING_DURATION         "Device.WiFi.X_RDK_CSI_LEVL.Duration"
#define WIFI_LEVL_CSI_STATUS                "Device.WiFi.X_RDK_CSI_LEVL.soundingStatus"
#define WIFI_LEVL_CSI_MAC_DATA              "Device.WiFi.X_RDK_CSI_LEVL.clientMacData"
#define RADIO_LEVL_TEMPERATURE_TABLE        "Device.WiFi.Events.Radio.{i}."
#define RADIO_LEVL_TEMPERATURE_EVENT        "Device.WiFi.Events.Radio.{i}.Temperature"
#define WIFI_QUALITY_LINKREPORT             "Device.WiFi.LinkReport"
/* construct_levl_get_handler / construct_levl_set_handler case-table helpers */
#define LGH_P   "Device.WiFi.X_RDK_CSI_LEVL."
#define LGH_L199 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define LGH_L250 LGH_L199 "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
#define LGH_STR 3
#define LGH_U32 7

/* --- analyze_client_assoc harness (unified-wifi-mesh src/ctrl/dm_easy_mesh_ctrl.cpp) --- */
#ifndef MAX_STA_LIST
#define MAX_STA_LIST 20
#endif
#ifndef EM_MAX_CMD
#define EM_MAX_CMD 16
#endif
#ifndef EM_PARSE_NO_ERR
#define EM_PARSE_NO_ERR 0
#endif
#ifndef EM_PARSE_ERR_GEN
#define EM_PARSE_ERR_GEN EM_PARSE_NO_ERR - 1
#endif
#define AC_BUF_MAX 8192
#define AC_PAD 64
#define AC_EVT_SZ (sizeof(em_bus_event_t) + AC_BUF_MAX + AC_PAD)
typedef struct {
    mac_address_t bssid;
    unsigned char assoc_control;
    unsigned short validity_period;
    unsigned char sta_count;
    mac_address_t sta_list[MAX_STA_LIST];
} em_cmd_client_assoc_params_t;
typedef struct {
    char name[64];
    char buff[0];
} __attribute__((__packed__)) em_subdoc_info_t;
typedef struct {
    int type;
    unsigned int data_len;
    union { em_subdoc_info_t subdoc; } u;
} em_bus_event_t;
typedef struct {
    const char *test_name;
    const char *json;          /* NULL -> generated by gen */
    int gen;                   /* 1: 21 STAs, 2: 20 STAs, 3: 5000-char BSSID, 4: 3000-char STA entry */
    int expect_num;            /* return value: 1 accept, 0 reject, -1 parse error */
    unsigned char bssid[6];
    unsigned char assoc;
    unsigned short vp;
    unsigned char sta_count;
    unsigned char sta0[6];
} ac_test_case_t;
extern ac_test_case_t analyze_client_assoc_suite[];
extern em_cmd_client_assoc_params_t ac_last_params;
extern int ac_cmd_created;
extern char ac_evt_buf[AC_EVT_SZ];
extern void *ac_pcmd_buf[];
int ac_invoke(em_bus_event_t *evt, void **pcmd);
void construct_analyze_client_assoc_input(const ac_test_case_t *tc);
void run_all_tests_analyze_client_assoc(void);

/* --- analyze_beacon_metrics_query harness: real-size types in namespace abq (common.h's
 *     em_beacon_element_list_t has element_list[6]; the real source has EM_MAX_ELEMENT_IDS=32) --- */
namespace abq {
#define ABQ_MAX_ELEMENT_IDS 32
#define ABQ_BUF_MAX 16384
#define ABQ_PAD 64
typedef struct {
    unsigned char num_element_id;
    unsigned char element_list[ABQ_MAX_ELEMENT_IDS];
}__attribute__((__packed__)) em_beacon_element_list_t;
typedef struct {
    unsigned char ap_channel_rprt_len;
    unsigned char ap_channel_op_class;
    unsigned char ap_channel_list[EM_MAX_CHANNELS_IN_LIST];
}__attribute__((__packed__)) em_beacon_ap_channel_rprt_t;
typedef struct {
    mac_address_t sta_mac_addr;
    unsigned char op_class;
    unsigned char channel_num;
    bssid_t bssid;
    unsigned char rprt_detail;
    unsigned char ssid_len;
    ssid_t ssid;
    unsigned char num_ap_channel_rprt;
    em_beacon_ap_channel_rprt_t ap_channel_rprt[EM_MAX_NEIGHBORS];
    em_beacon_element_list_t element_list;
}__attribute__((__packed__)) em_beacon_metrics_query_t;
typedef em_beacon_metrics_query_t em_cmd_beacon_metrics_param_t;
typedef struct {
    union { em_cmd_beacon_metrics_param_t beacon_metrics_params; } u;
} em_cmd_params_t;   /* net_node omitted: the stub copies params by value and the guard below must stay unread */
typedef struct {
    char name[64];
    char buff[0];
} __attribute__((__packed__)) em_subdoc_info_t;
typedef struct {
    int type;
    char lead[(8 - (4 + sizeof(em_cmd_params_t)) % 8) % 8];   /* makes params END on an 8-byte granule so the guard starts exactly there */
    em_cmd_params_t params;
    char guard[64];                /* stand-in for the fields after params in the real struct; runner poisons it */
    unsigned int data_len;
    union { em_subdoc_info_t subdoc; } u;
} em_bus_event_t;
typedef struct {
    const char *test_name;
    const char *json;          /* NULL -> generated by gen */
    int gen;
    int expect_num;            /* 1 accept, 0 reject */
    unsigned char sta_mac[6];
    unsigned char op_class;
    unsigned char channel;
    unsigned char bssid[6];
    unsigned char rd;
    unsigned char ssid_len;
    unsigned char num_apc;
    unsigned char num_el;
} test_case_t;
extern test_case_t suite[];
extern em_cmd_beacon_metrics_param_t last_params;
extern int cmd_created;
extern char evt_buf[];
extern void *pcmd_buf[];
int invoke(em_bus_event_t *evt, void **pcmd);
void construct_input(const test_case_t *tc);
}
#define ABQ_EVT_SZ (sizeof(abq::em_bus_event_t) + ABQ_BUF_MAX + ABQ_PAD)
void run_all_tests_analyze_beacon_metrics_query(void);

/* --- cmd_channelselect harness (unified-wifi-mesh src/ctrl/dm_easy_mesh_ctrl.cpp), namespace ccs --- */
namespace ccs {
#define CCS_MAXP 140
#define CCS_VAL_SZ 384
#define CCS_PAD 64
#ifndef BUS_MAX_NAME_LENGTH
#define BUS_MAX_NAME_LENGTH 128
#endif
typedef enum {
    bus_error_success = 0, bus_error_general = 1, bus_error_invalid_input = 2,
    bus_error_out_of_resources = 4, bus_error_invalid_method = 22, bus_error_invalid_namespace = 25
} bus_error_t;
typedef enum { bus_data_type_string = 1, bus_data_type_int8, bus_data_type_uint8, bus_data_type_int16,
               bus_data_type_uint16, bus_data_type_int32, bus_data_type_uint32 } bus_data_type_t;
typedef union { int8_t i8; uint8_t u8; int16_t i16; uint16_t u16; int32_t i32; uint32_t u32; void *bytes; } raw_data_format_t;
typedef struct { bus_data_type_t data_type; raw_data_format_t raw_data; unsigned int raw_data_len; } raw_data_t;
typedef struct bus_data_prop {
    uint32_t name_len;
    char name[BUS_MAX_NAME_LENGTH];
    bool is_data_set;
    bus_error_t status;
    raw_data_t value;
    struct bus_data_prop *next_data;
} bus_data_prop_t;
typedef struct {
    const char *name;     /* property name */
    int kind;             /* 0 string, 1 int32, 2 uint8, 3 string with explicit len (embedded NUL) */
    const char *s;
    int i;
    int len;              /* kind 3: raw_data_len */
} prop_spec_t;
typedef struct {
    const char *test_name;
    const char *method;   /* NULL passes a NULL method_name */
    int gen;              /* 1: 32 classes, 2: 300-char channel list */
    int radio_band;       /* 0 = 5G default */
    bool no_props;        /* input_params == NULL */
    prop_spec_t props[10];
    int expect_rc;
    const char *json_has; /* substring expected in the JSON sent to io_process (accept cases) */
    bool crash;           /* expected to abort: run in a forked child */
} test_case_t;
extern test_case_t suite[];
extern char method_buf[256 + CCS_PAD];
extern bus_data_prop_t props_buf[];
extern char val_buf[][CCS_VAL_SZ + CCS_PAD];
extern int num_props;
extern int io_calls;
extern char io_json[];
extern char last_status[];
extern int g_radio_band;
bus_error_t invoke(const char *method, const bus_data_prop_t *in, bus_data_prop_t **out);
void construct_input(const test_case_t *tc);
}
void run_all_tests_cmd_channelselect(void);

/* --- cmd_setssid harness (unified-wifi-mesh src/ctrl/dm_easy_mesh_ctrl.cpp), namespace css --- */
namespace css {
#define CSS_VAL_SZ 128
#define CSS_PAD 64
#define CSS_CFG_SZ 4096
typedef struct {
    const char *name;     /* property name */
    int kind;             /* 0 string, 1 int32, 5 string of `len` copies of s[0] */
    const char *s;
    int i;
    int len;
} prop_spec_t;
typedef struct {
    const char *test_name;
    int cfg;              /* config JSON returned by get_config: see construct file */
    bool no_props;        /* input_params == NULL */
    bool no_out;          /* output_params == NULL */
    bool ctrl_null;       /* em_ctrl instance missing */
    prop_spec_t props[8];
    int expect_rc;
    const char *json_has; /* substring expected in the JSON sent to io_process (accept cases) */
    const char *json_not; /* substring that must NOT be in it */
} test_case_t;
extern test_case_t suite[];
extern ccs::bus_data_prop_t props_buf[];
extern char val_buf[][CSS_VAL_SZ + CSS_PAD];
extern char cfg_store[CSS_CFG_SZ + CSS_PAD];
extern int num_props;
extern int io_calls;
extern char io_json[];
extern char last_status[];
extern const char *cfg_json;
void set_ctrl(bool present);
void construct_input(const test_case_t *tc);
ccs::bus_error_t invoke(const ccs::bus_data_prop_t *in, ccs::bus_data_prop_t **out);
}
void run_all_tests_cmd_setssid(void);
