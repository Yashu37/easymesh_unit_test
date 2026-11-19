/* main of src/validation_test.cpp harness types (namespace vmn). Own header, kept out of common.h so `make` stays incremental. */
#ifndef VALIDATION_MAIN_H
#define VALIDATION_MAIN_H
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "common.h"

namespace vmn {
#define VMN_GUARD 128
#define MAX_EM_BUFF_SZ 1024
#define EM_CONF 0
/* em_util_info_print formats its arguments like the real one (so a %s of buff is really evaluated) and drops the text */
static inline void em_util_info_print(int module, const char *fmt, ...) { char sink[4096]; va_list a; va_start(a, fmt); vsnprintf(sink, sizeof(sink), fmt, a); va_end(a); }
/* message / profile types used by main (values only need to be distinct) */
typedef enum { em_msg_type_none = 0,
    em_msg_type_1905_ack,
    em_msg_type_1905_decrypt_fail,
    em_msg_type_1905_encap_eapol,
    em_msg_type_1905_rekey_req,
    em_msg_type_agent_list,
    em_msg_type_anticipated_channel_pref,
    em_msg_type_anticipated_channel_usage_rprt,
    em_msg_type_ap_cap_query,
    em_msg_type_ap_cap_rprt,
    em_msg_type_ap_metrics_query,
    em_msg_type_ap_metrics_rsp,
    em_msg_type_assoc_sta_link_metrics_query,
    em_msg_type_assoc_sta_link_metrics_rsp,
    em_msg_type_assoc_status_notif,
    em_msg_type_autoconf_renew,
    em_msg_type_autoconf_resp,
    em_msg_type_autoconf_search,
    em_msg_type_beacon_metrics_query,
    em_msg_type_beacon_metrics_rsp,
    em_msg_type_bh_sta_cap_query,
    em_msg_type_bh_sta_cap_rprt,
    em_msg_type_bh_steering_req,
    em_msg_type_bh_steering_rsp,
    em_msg_type_bss_config_req,
    em_msg_type_bss_config_res,
    em_msg_type_bss_config_rsp,
    em_msg_type_cac_req,
    em_msg_type_cac_term,
    em_msg_type_channel_pref_query,
    em_msg_type_channel_pref_rprt,
    em_msg_type_channel_scan_req,
    em_msg_type_channel_scan_rprt,
    em_msg_type_channel_sel_req,
    em_msg_type_channel_sel_rsp,
    em_msg_type_chirp_notif,
    em_msg_type_client_assoc_ctrl_req,
    em_msg_type_client_cap_query,
    em_msg_type_client_cap_rprt,
    em_msg_type_client_disassoc_stats,
    em_msg_type_client_steering_btm_rprt,
    em_msg_type_client_steering_req,
    em_msg_type_combined_infra_metrics,
    em_msg_type_direct_encap_dpp,
    em_msg_type_dpp_bootstrap_uri_notif,
    em_msg_type_dpp_cce_ind,
    em_msg_type_err_rsp,
    em_msg_type_failed_conn,
    em_msg_type_higher_layer_data,
    em_msg_type_link_metric_query,
    em_msg_type_link_metric_resp,
    em_msg_type_map_policy_config_req,
    em_msg_type_op_channel_rprt,
    em_msg_type_proxied_encap_dpp,
    em_msg_type_qos_mgmt_notif,
    em_msg_type_reconfig_trigger,
    em_msg_type_steering_complete,
    em_msg_type_svc_prio_req,
    em_msg_type_topo_disc,
    em_msg_type_topo_notif,
    em_msg_type_topo_query,
    em_msg_type_topo_resp,
    em_msg_type_topo_vendor,
    em_msg_type_tunneled,
    em_msg_type_unassoc_sta_link_metrics_query,
    em_msg_type_unassoc_sta_link_metrics_rsp,
    em_msg_type_max } em_msg_type_t;
typedef enum { em_profile_type_none = 0, em_profile_type_1 = 1, em_profile_type_2 = 2, em_profile_type_3 = 3 } em_profile_type_t;

/* stand-in for em_testValidation_t (src/validation_test.cpp + inc/em_test_validation.h): every test_* builder writes g_build_len bytes
 * into the caller's buff (a non-zero pattern ending in the three zero bytes of the EOM TLV, like the real builders) and returns that
 * size; test_validation records its arguments and reads sz bytes of buff the way the real em_msg_t parser does. */
extern int g_build_len; extern int g_builder; extern int g_calls; extern int g_vtype; extern int g_vprofile; extern unsigned int g_vsz; extern unsigned int g_vsum; extern int g_vi;
int do_build(int id, unsigned char *buff, int i, unsigned int len);
class em_testValidation_t {
public:
    em_testValidation_t(unsigned char *buff, unsigned int &len);
    ~em_testValidation_t();
    void test_validation(em_msg_type_t type, em_profile_type_t profile, unsigned char *buff, unsigned int sz);
    int test_1905_ack(unsigned char *buff, int i, unsigned int len) { return do_build(1, buff, i, len); }
    int test_agent_list(unsigned char *buff, int i, unsigned int len) { return do_build(2, buff, i, len); }
    int test_anticipated_channel_pref(unsigned char *buff, int i, unsigned int len) { return do_build(3, buff, i, len); }
    int test_anticipated_channel_usage_rprt(unsigned char *buff, int i, unsigned int len) { return do_build(4, buff, i, len); }
    int test_ap_cap_query(unsigned char *buff, int i, unsigned int len) { return do_build(5, buff, i, len); }
    int test_ap_cap_rprt(unsigned char *buff, int i, unsigned int len) { return do_build(6, buff, i, len); }
    int test_ap_metrics_query(unsigned char *buff, int i, unsigned int len) { return do_build(7, buff, i, len); }
    int test_ap_metrics_rsp(unsigned char *buff, int i, unsigned int len) { return do_build(8, buff, i, len); }
    int test_assoc_status_notif(unsigned char *buff, int i, unsigned int len) { return do_build(9, buff, i, len); }
    int test_autoconfig_renew(unsigned char *buff, int i, unsigned int len) { return do_build(10, buff, i, len); }
    int test_autoconfig_resp_msg(unsigned char *buff, int i, unsigned int len) { return do_build(11, buff, i, len); }
    int test_autoconfig_search_msg(unsigned char *buff, int i, unsigned int len) { return do_build(12, buff, i, len); }
    int test_beacon_metrics_query(unsigned char *buff, int i, unsigned int len) { return do_build(13, buff, i, len); }
    int test_beacon_metrics_rsp(unsigned char *buff, int i, unsigned int len) { return do_build(14, buff, i, len); }
    int test_bh_sta_cap_query(unsigned char *buff, int i, unsigned int len) { return do_build(15, buff, i, len); }
    int test_bh_sta_cap_rprt(unsigned char *buff, int i, unsigned int len) { return do_build(16, buff, i, len); }
    int test_bh_steering_req(unsigned char *buff, int i, unsigned int len) { return do_build(17, buff, i, len); }
    int test_bh_steering_rsp(unsigned char *buff, int i, unsigned int len) { return do_build(18, buff, i, len); }
    int test_bss_config_req(unsigned char *buff, int i, unsigned int len) { return do_build(19, buff, i, len); }
    int test_bss_config_res(unsigned char *buff, int i, unsigned int len) { return do_build(20, buff, i, len); }
    int test_bss_config_rsp(unsigned char *buff, int i, unsigned int len) { return do_build(21, buff, i, len); }
    int test_cac_req(unsigned char *buff, int i, unsigned int len) { return do_build(22, buff, i, len); }
    int test_cac_term(unsigned char *buff, int i, unsigned int len) { return do_build(23, buff, i, len); }
    int test_channel_pref_query(unsigned char *buff, int i, unsigned int len) { return do_build(24, buff, i, len); }
    int test_channel_pref_rprt(unsigned char *buff, int i, unsigned int len) { return do_build(25, buff, i, len); }
    int test_channel_scan_req(unsigned char *buff, int i, unsigned int len) { return do_build(26, buff, i, len); }
    int test_channel_scan_rprt(unsigned char *buff, int i, unsigned int len) { return do_build(27, buff, i, len); }
    int test_channel_sel_req(unsigned char *buff, int i, unsigned int len) { return do_build(28, buff, i, len); }
    int test_channel_sel_rsp(unsigned char *buff, int i, unsigned int len) { return do_build(29, buff, i, len); }
    int test_chirp_notif(unsigned char *buff, int i, unsigned int len) { return do_build(30, buff, i, len); }
    int test_client_assoc_ctrl_req(unsigned char *buff, int i, unsigned int len) { return do_build(31, buff, i, len); }
    int test_client_cap_query(unsigned char *buff, int i, unsigned int len) { return do_build(32, buff, i, len); }
    int test_client_cap_rprt(unsigned char *buff, int i, unsigned int len) { return do_build(33, buff, i, len); }
    int test_client_disassoc_stats(unsigned char *buff, int i, unsigned int len) { return do_build(34, buff, i, len); }
    int test_client_steering_btm_rprt(unsigned char *buff, int i, unsigned int len) { return do_build(35, buff, i, len); }
    int test_client_steering_req(unsigned char *buff, int i, unsigned int len) { return do_build(36, buff, i, len); }
    int test_combined_infra_metrics(unsigned char *buff, int i, unsigned int len) { return do_build(37, buff, i, len); }
    int test_direct_encap_dpp(unsigned char *buff, int i, unsigned int len) { return do_build(38, buff, i, len); }
    int test_dpp_bootstrap_uri_notif(unsigned char *buff, int i, unsigned int len) { return do_build(39, buff, i, len); }
    int test_dpp_cce_ind(unsigned char *buff, int i, unsigned int len) { return do_build(40, buff, i, len); }
    int test_err_rsp(unsigned char *buff, int i, unsigned int len) { return do_build(41, buff, i, len); }
    int test_failed_conn(unsigned char *buff, int i, unsigned int len) { return do_build(42, buff, i, len); }
    int test_higher_layer_data(unsigned char *buff, int i, unsigned int len) { return do_build(43, buff, i, len); }
    int test_i1905_decrypt_fail(unsigned char *buff, int i, unsigned int len) { return do_build(44, buff, i, len); }
    int test_i1905_encap_eapol(unsigned char *buff, int i, unsigned int len) { return do_build(45, buff, i, len); }
    int test_i1905_rekey_req(unsigned char *buff, int i, unsigned int len) { return do_build(46, buff, i, len); }
    int test_link_metric_query(unsigned char *buff, int i, unsigned int len) { return do_build(47, buff, i, len); }
    int test_link_metric_resp(unsigned char *buff, int i, unsigned int len) { return do_build(48, buff, i, len); }
    int test_op_channel_rprt(unsigned char *buff, int i, unsigned int len) { return do_build(49, buff, i, len); }
    int test_policy_config_req(unsigned char *buff, int i, unsigned int len) { return do_build(50, buff, i, len); }
    int test_proxied_encap_dpp(unsigned char *buff, int i, unsigned int len) { return do_build(51, buff, i, len); }
    int test_qos_mgmt_notif(unsigned char *buff, int i, unsigned int len) { return do_build(52, buff, i, len); }
    int test_reconfig_trigger(unsigned char *buff, int i, unsigned int len) { return do_build(53, buff, i, len); }
    int test_sta_link_metrics_query(unsigned char *buff, int i, unsigned int len) { return do_build(54, buff, i, len); }
    int test_sta_link_metrics_rsp(unsigned char *buff, int i, unsigned int len) { return do_build(55, buff, i, len); }
    int test_steering_complete(unsigned char *buff, int i, unsigned int len) { return do_build(56, buff, i, len); }
    int test_svc_prio_req(unsigned char *buff, int i, unsigned int len) { return do_build(57, buff, i, len); }
    int test_topo_disc(unsigned char *buff, int i, unsigned int len) { return do_build(58, buff, i, len); }
    int test_topo_notif(unsigned char *buff, int i, unsigned int len) { return do_build(59, buff, i, len); }
    int test_topo_query(unsigned char *buff, int i, unsigned int len) { return do_build(60, buff, i, len); }
    int test_topo_resp(unsigned char *buff, int i, unsigned int len) { return do_build(61, buff, i, len); }
    int test_topo_vendor(unsigned char *buff, int i, unsigned int len) { return do_build(62, buff, i, len); }
    int test_tunneled(unsigned char *buff, int i, unsigned int len) { return do_build(63, buff, i, len); }
    int test_unassoc_sta_link_metrics_query(unsigned char *buff, int i, unsigned int len) { return do_build(64, buff, i, len); }
    int test_unassoc_sta_link_metrics_rsp(unsigned char *buff, int i, unsigned int len) { return do_build(65, buff, i, len); }
};
/* the scripted stdin: main's scanf() reads these values in order; when they run out scanf returns EOF and leaves its argument alone */
extern int *g_script; extern int g_script_n; extern int g_script_pos;
int vmn_scanf(const char *fmt, ...);

typedef struct {
    const char *test_name;
    int n_inputs;            /* how many of the three values (type, profile, success/failure) stdin provides */
    int user_type, user_profile, user_i;
    int build_len;           /* bytes every builder writes into buff (<= 1024) */
    int sweep;               /* 1: run every message type with the given profile and compare */
    int expect_calls;        /* calls of test_validation (0: main must refuse an invalid selection) */
    bool crash;
} test_case_t;
extern test_case_t suite[];
extern const int g_type_of_case[68];   /* user_type -> em_msg_type_t as main assigns it (0 = invalid) */
extern const int g_builder_of_case[68];
void construct_input(const test_case_t *tc);
void invoke(void);
void teardown(void);
}
void run_all_tests_validation_main(void);
#endif
