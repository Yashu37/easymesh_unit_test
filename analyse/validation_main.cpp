/*
 * HANDLER: main (src/validation_test.cpp)
 *
 * Copied verbatim from unified-wifi-mesh (develop @ 1ba9529): main() of the interactive message validation tool, renamed vmn_main with
 * a macro. Local arrays: unsigned char buff[MAX_EM_BUFF_SZ]. scanf is redirected to a scripted stdin (vmn_scanf), and em_testValidation_t
 * is a stand-in (see validation_main.h): the real builders / em_msg_t need the full OneWifi headers. main itself needs no data model,
 * only the three integers it reads. The only edit to the copied body is an explicit `return 0;` at the end (main returns 0 implicitly,
 * the renamed copy is an ordinary function).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "validation_main.h"

namespace vmn {
int g_build_len = 0; int g_builder = 0; int g_calls = 0; int g_vtype = -1; int g_vprofile = -1; unsigned int g_vsz = 0; unsigned int g_vsum = 0; int g_vi = -1;
int *g_script = NULL; int g_script_n = 0; int g_script_pos = 0;

int vmn_scanf(const char *fmt, ...)
{
    va_list a; va_start(a, fmt); int *p = va_arg(a, int *); va_end(a);
    if (g_script_pos >= g_script_n) return EOF;
    *p = g_script[g_script_pos++]; return 1;
}
int do_build(int id, unsigned char *buff, int i, unsigned int len)
{
    g_builder = id; g_vi = i;
    for (int k = 0; k < g_build_len; k++) buff[k] = (unsigned char)(k % 251 + 1);
    for (int k = (g_build_len > 3 ? g_build_len - 3 : 0); k < g_build_len; k++) buff[k] = 0;    /* EOM TLV: type 0, length 0 */
    return g_build_len;
}
em_testValidation_t::em_testValidation_t(unsigned char *buff, unsigned int &len) { len = 0; }
em_testValidation_t::~em_testValidation_t() {}
void em_testValidation_t::test_validation(em_msg_type_t type, em_profile_type_t profile, unsigned char *buff, unsigned int sz)
{
    g_calls++; g_vtype = (int)type; g_vprofile = (int)profile; g_vsz = sz; g_vsum = 0;
    for (unsigned int k = 0; k < sz; k++) g_vsum += buff[k];     /* the real em_msg_t reads sz bytes of buff */
}
const int g_type_of_case[68] = {0, vmn::em_msg_type_autoconf_search, vmn::em_msg_type_autoconf_resp, 0, 0, vmn::em_msg_type_topo_disc, vmn::em_msg_type_topo_notif, vmn::em_msg_type_topo_query, vmn::em_msg_type_topo_resp, vmn::em_msg_type_topo_vendor, vmn::em_msg_type_link_metric_query, vmn::em_msg_type_link_metric_resp, vmn::em_msg_type_autoconf_renew, vmn::em_msg_type_ap_cap_query, vmn::em_msg_type_ap_cap_rprt, vmn::em_msg_type_map_policy_config_req, vmn::em_msg_type_channel_pref_query, vmn::em_msg_type_channel_pref_rprt, vmn::em_msg_type_channel_sel_req, vmn::em_msg_type_channel_sel_rsp, vmn::em_msg_type_op_channel_rprt, vmn::em_msg_type_client_cap_query, vmn::em_msg_type_client_steering_req, vmn::em_msg_type_client_steering_btm_rprt, vmn::em_msg_type_client_assoc_ctrl_req, vmn::em_msg_type_steering_complete, vmn::em_msg_type_higher_layer_data, vmn::em_msg_type_bh_steering_req, vmn::em_msg_type_bh_steering_rsp, vmn::em_msg_type_client_cap_rprt, vmn::em_msg_type_ap_metrics_query, vmn::em_msg_type_ap_metrics_rsp, vmn::em_msg_type_assoc_sta_link_metrics_query, vmn::em_msg_type_assoc_sta_link_metrics_rsp, vmn::em_msg_type_unassoc_sta_link_metrics_query, vmn::em_msg_type_unassoc_sta_link_metrics_rsp, vmn::em_msg_type_beacon_metrics_query, vmn::em_msg_type_beacon_metrics_rsp, vmn::em_msg_type_combined_infra_metrics, vmn::em_msg_type_channel_scan_req, vmn::em_msg_type_qos_mgmt_notif, vmn::em_msg_type_anticipated_channel_usage_rprt, vmn::em_msg_type_anticipated_channel_pref, vmn::em_msg_type_agent_list, vmn::em_msg_type_failed_conn, vmn::em_msg_type_dpp_bootstrap_uri_notif, vmn::em_msg_type_1905_encap_eapol, vmn::em_msg_type_chirp_notif, vmn::em_msg_type_bss_config_res, vmn::em_msg_type_bss_config_rsp, vmn::em_msg_type_bss_config_req, vmn::em_msg_type_channel_scan_rprt, vmn::em_msg_type_dpp_cce_ind, vmn::em_msg_type_1905_rekey_req, vmn::em_msg_type_1905_decrypt_fail, vmn::em_msg_type_cac_term, vmn::em_msg_type_client_disassoc_stats, vmn::em_msg_type_svc_prio_req, vmn::em_msg_type_err_rsp, vmn::em_msg_type_assoc_status_notif, vmn::em_msg_type_tunneled, vmn::em_msg_type_bh_sta_cap_query, vmn::em_msg_type_bh_sta_cap_rprt, vmn::em_msg_type_proxied_encap_dpp, vmn::em_msg_type_direct_encap_dpp, vmn::em_msg_type_reconfig_trigger, vmn::em_msg_type_cac_req, vmn::em_msg_type_1905_ack};
const int g_builder_of_case[68] = {0, 12, 11, 0, 0, 58, 59, 60, 61, 62, 47, 48, 10, 5, 6, 50, 24, 25, 28, 29, 49, 32, 36, 35, 31, 56, 43, 17, 18, 33, 7, 8, 54, 55, 64, 65, 13, 14, 37, 26, 52, 4, 3, 2, 42, 39, 45, 30, 20, 21, 19, 27, 40, 46, 44, 23, 34, 57, 41, 9, 63, 15, 16, 51, 38, 53, 22, 1};

/* --- copied verbatim (renamed by the macros) --- */
#define main vmn_main
#define scanf vmn_scanf
int main(){

    unsigned char buff[MAX_EM_BUFF_SZ];
    unsigned int sz; 
    int i=0;
    unsigned int len=0;
    int user_type;
    int user_profile;
    em_msg_type_t type;
    em_profile_type_t profile;
    em_testValidation_t objheader(buff,len);

    em_util_info_print(EM_CONF,"%s:%d:buff inside main ,after header:%u\n", __func__, __LINE__,buff);
    //   printf("s buff inside main:%s\n",buff);
    printf("\nplease select the message to be validated:\n1.autoconf_search\n2.autoconf_resp\n3.autoconfig_wsc_m1\n4.autoconfig_wsc_m2\n5.topo_disc\n6.topo_notif\n7.topo_query\n8.topo_resp\n9.topo_vendor\n10.link_metric_query\n11.link_metric_resp\n12.autoconf_renew\n13.ap_cap_query\n14.ap_cap_rprt\n15.map_policy_config_req\n16.channel_pref_query\n17.channel_pref_rprt\n18.channel_sel_req\n19.channel_sel_rsp\n20.op_channel_rprt\n21.client_cap_query\n22.client_steering_req\n23.client_steering_btm_rprt\n24.client_assoc_ctrl_req\n25.steering_complete\n26.higher_layer_data\n27.bh_steering_req\n28.bh_steering_rsp\n29.client_cap_rprt\n30.ap_metrics_query\n31.ap_metrics_rsp\n32.assoc_sta_link_metrics_query\n33.assoc_sta_link_metrics_rsp\n34.unassoc_sta_link_metrics_query\n35.unassoc_sta_link_metrics_rsp\n36.beacon_metrics_query\n37.beacon_metrics_rsp\n38.combined_infra_metrics\n39.channel_scan_req\n40.qos_mgmt_notif\n41.anticipated_channel_usage_rprt\n42.anticipated_channel_pref\n43.agent_list\n44.failed_conn\n45.dpp_bootstrap_uri_notif\n46.1905_encap_eapol\n47.chirp_notif\n48.bss_config_res\n49.bss_config_rsp\n50.bss_config_req\n51.channel_scan_rprt\n52.dpp_cce_ind\n53.1905_rekey_req\n54.1905_decrypt_fail\n55.cac_term\n56.client_disassoc_stats\n57.svc_prio_req\n58.err_rsp\n59.assoc_status_notif\n60.tunneled\n61.bh_sta_cap_query\n62.bh_sta_cap_rprt\n63.proxied_encap_dpp\n64.direct_encap_dpp\n65.reconfig_trigger\n66.cac_req\n67.1905_ack\n");

    scanf("%d",&user_type);
    printf("please enter the profile type: em_profile_type_1:1\nem_profile_type_2:2\nem_profile_type_3:3\n");
    scanf("%d",&user_profile);
    printf("type 0 to validate success case\ntype 1 to validate failure case\n");
    scanf("%d",&i);
    em_util_info_print(EM_CONF,"%s:%d: entering switch case\n", __func__, __LINE__);

    switch (user_profile){

        case 1:
            profile = em_profile_type_1;
            break;

        case 2:
            profile = em_profile_type_2;
            break;

        case 3:
            profile = em_profile_type_3;
            break;
        default:
            printf("user entered invalid profile\n");
            break;
    }

    switch (user_type) {

        case 1:
            sz = objheader.test_autoconfig_search_msg(buff,i,len);
            type = em_msg_type_autoconf_search;
            break;

        case 2:
            sz = objheader.test_autoconfig_resp_msg(buff,i,len);
            type = em_msg_type_autoconf_resp;
            break;

            /*                case 3:
                              sz = objheader.test_autoconfig_wsc_m1(buff,i,len);
                              type = em_msg_type_autoconf_wsc; 
                              break;

                              case 4:
                              sz = objheader.test_autoconfig_wsc_m2(buff,i,len);
                              type = em_msg_type_autoconf_wsc;
                              break;
             */

        case 5:
            sz = objheader.test_topo_disc(buff,i,len);
            type = em_msg_type_topo_disc;
            break;

        case 6:
            sz = objheader.test_topo_notif(buff,i,len);
            type = em_msg_type_topo_notif;
            break;

        case 7:
            sz =  objheader.test_topo_query(buff,i,len);
            type = em_msg_type_topo_query;
            break;

        case 8:
            sz =  objheader.test_topo_resp(buff,i,len);
            type = em_msg_type_topo_resp;
            break;

        case 9:
            sz =  objheader.test_topo_vendor(buff,i,len);
            type = em_msg_type_topo_vendor;
            break;

        case 10:
            sz = objheader.test_link_metric_query(buff,i,len);
            type = em_msg_type_link_metric_query;
            break;

        case 11:
            sz =  objheader.test_link_metric_resp(buff,i,len);
            type = em_msg_type_link_metric_resp;
            break;

        case 12:
            sz =  objheader.test_autoconfig_renew(buff,i,len);
            type = em_msg_type_autoconf_renew;
            break;

        case 13:
            sz =  objheader.test_ap_cap_query(buff,i,len);
            type = em_msg_type_ap_cap_query;
            break;

        case 14:
            sz =  objheader.test_ap_cap_rprt(buff,i,len);
            type = em_msg_type_ap_cap_rprt;
            break;

        case 15:
            sz =  objheader.test_policy_config_req(buff,i,len);
            type = em_msg_type_map_policy_config_req;
            break;

        case 16:
            sz =  objheader.test_channel_pref_query(buff,i,len);
            type = em_msg_type_channel_pref_query;
            break;

        case 17:
            sz =  objheader.test_channel_pref_rprt(buff,i,len);
            type =  em_msg_type_channel_pref_rprt;
            break;

        case 18:
            sz =  objheader.test_channel_sel_req(buff,i,len);
            type = em_msg_type_channel_sel_req;
            break;

        case 19:
            sz =  objheader.test_channel_sel_rsp(buff,i,len);
            type = em_msg_type_channel_sel_rsp;
            break;

        case 20:
            sz =  objheader.test_op_channel_rprt(buff,i,len);
            type = em_msg_type_op_channel_rprt;
            break;

        case 21:
            sz =  objheader.test_client_cap_query(buff,i,len);
            type =  em_msg_type_client_cap_query;
            break;

        case 22:
            sz =  objheader.test_client_steering_req(buff,i,len);
            type = em_msg_type_client_steering_req;
            break;

        case 23:
            sz =  objheader.test_client_steering_btm_rprt(buff,i,len);
            type = em_msg_type_client_steering_btm_rprt;
            break;


        case 24:
            sz =  objheader.test_client_assoc_ctrl_req(buff,i,len);
            type = em_msg_type_client_assoc_ctrl_req;
            break;

        case 25:
            sz =  objheader.test_steering_complete(buff,i,len);
            type = em_msg_type_steering_complete;
            break;


        case 26:
            sz =  objheader.test_higher_layer_data(buff,i,len);
            type = em_msg_type_higher_layer_data;
            break;


        case 27:
            sz =  objheader.test_bh_steering_req(buff,i,len);
            type = em_msg_type_bh_steering_req;
            break;


        case 28:
            sz =  objheader.test_bh_steering_rsp(buff,i,len);
            type = em_msg_type_bh_steering_rsp;
            break;


        case 29:
            sz = objheader.test_client_cap_rprt(buff,i,len);
            type = em_msg_type_client_cap_rprt;
            break;

        case 30:
            sz =  objheader.test_ap_metrics_query(buff,i,len);
            type = em_msg_type_ap_metrics_query;
            break;

        case 31:
            sz =  objheader.test_ap_metrics_rsp(buff,i,len);
            type =  em_msg_type_ap_metrics_rsp;
            break;

        case 32:
            sz =  objheader.test_sta_link_metrics_query(buff,i,len);
            type = em_msg_type_assoc_sta_link_metrics_query;
            break;

        case 33:
            sz =  objheader.test_sta_link_metrics_rsp(buff,i,len);
            type = em_msg_type_assoc_sta_link_metrics_rsp;
            break;

        case 34:
            sz =  objheader.test_unassoc_sta_link_metrics_query(buff,i,len);
            type = em_msg_type_unassoc_sta_link_metrics_query;
            break;

        case 35:
            sz =  objheader.test_unassoc_sta_link_metrics_rsp(buff,i,len);
            type =  em_msg_type_unassoc_sta_link_metrics_rsp;
            break;

        case 36:
            sz =  objheader.test_beacon_metrics_query(buff,i,len);
            type = em_msg_type_beacon_metrics_query;
            break;

        case 37:
            sz =  objheader.test_beacon_metrics_rsp(buff,i,len);
            type = em_msg_type_beacon_metrics_rsp;
            break;

        case 38:
            sz =  objheader.test_combined_infra_metrics(buff,i,len);
            type = em_msg_type_combined_infra_metrics;
            break;


        case 39:
            sz =  objheader.test_channel_scan_req(buff,i,len);
            type = em_msg_type_channel_scan_req;
            break;


        case  40:
            sz =  objheader.test_qos_mgmt_notif(buff,i,len);
            type = em_msg_type_qos_mgmt_notif;
            break;

        case  41:
            sz =  objheader.test_anticipated_channel_usage_rprt(buff,i,len);
            type = em_msg_type_anticipated_channel_usage_rprt;
            break;

        case  42:
            sz =  objheader.test_anticipated_channel_pref(buff,i,len);
            type =  em_msg_type_anticipated_channel_pref;
            break;

        case 43:
            sz =  objheader.test_agent_list(buff,i,len);
            type =  em_msg_type_agent_list;
            break;

        case 44:
            sz =  objheader.test_failed_conn(buff,i,len);
            type = em_msg_type_failed_conn;
            break;

        case 45:
            sz =  objheader.test_dpp_bootstrap_uri_notif(buff,i,len);
            type =  em_msg_type_dpp_bootstrap_uri_notif;
            break;

        case 46:
            sz =  objheader.test_i1905_encap_eapol(buff,i,len);
            type = em_msg_type_1905_encap_eapol;
            break;

        case 47:
            sz =  objheader.test_chirp_notif(buff,i,len);
            type = em_msg_type_chirp_notif;
            break;

        case 48:
            sz =  objheader.test_bss_config_res(buff,i,len);
            type = em_msg_type_bss_config_res;
            break;


        case 49:
            sz =  objheader.test_bss_config_rsp(buff,i,len);
            type = em_msg_type_bss_config_rsp;
            break;

        case 50:
            sz =  objheader.test_bss_config_req(buff,i,len);
            type =  em_msg_type_bss_config_req;
            break;

        case 51:
            sz =  objheader.test_channel_scan_rprt(buff,i,len);
            type =  em_msg_type_channel_scan_rprt;
            break;

        case 52:
            sz =  objheader.test_dpp_cce_ind(buff,i,len);
            type = em_msg_type_dpp_cce_ind;
            break;

        case 53:
            sz =  objheader.test_i1905_rekey_req(buff,i,len);
            type = em_msg_type_1905_rekey_req;
            break;

        case 54:
            sz =  objheader.test_i1905_decrypt_fail(buff,i,len);
            type =  em_msg_type_1905_decrypt_fail;
            break;

        case 55:
            sz =  objheader.test_cac_term(buff,i,len);
            type = em_msg_type_cac_term;
            break;

        case 56:
            sz =  objheader.test_client_disassoc_stats(buff,i,len);
            type = em_msg_type_client_disassoc_stats;
            break;

        case 57:
            sz =  objheader.test_svc_prio_req(buff,i,len);
            type = em_msg_type_svc_prio_req;
            break;

        case 58:
            sz =  objheader.test_err_rsp(buff,i,len);
            type =  em_msg_type_err_rsp;
            break;

        case 59:
            sz =  objheader.test_assoc_status_notif(buff,i,len);
            type = em_msg_type_assoc_status_notif;
            break;

        case 60:
            sz =  objheader.test_tunneled(buff,i,len);
            type = em_msg_type_tunneled;
            break;

        case 61:
            sz =  objheader.test_bh_sta_cap_query(buff,i,len);
            type = em_msg_type_bh_sta_cap_query;
            break;

        case 62:
            sz =  objheader.test_bh_sta_cap_rprt(buff,i,len);
            type = em_msg_type_bh_sta_cap_rprt;
            break;

        case 63:
            sz =  objheader.test_proxied_encap_dpp(buff,i,len);
            type = em_msg_type_proxied_encap_dpp;
            break;

        case 64:
            sz =  objheader.test_direct_encap_dpp(buff,i,len);
            type = em_msg_type_direct_encap_dpp;
            break;

        case 65:
            sz =  objheader.test_reconfig_trigger(buff,i,len);
            type =  em_msg_type_reconfig_trigger;
            break;

        case 66:
            sz = objheader.test_cac_req(buff,i,len);
            type = em_msg_type_cac_req;
            break;

        case 67:
            sz = objheader.test_1905_ack(buff,i,len);
            type = em_msg_type_1905_ack;
            break;

        default:
            printf("user entered invalid message type\n");
            break;
    }

    em_util_info_print(EM_CONF,"%s:%d:calling test validation function ; type: %d;profile: %d; sz = %d; buff= %s\n", __func__, __LINE__,type,profile,sz,buff);


    objheader.test_validation(type,profile,buff,sz);
    return 0;   /* the only change: main's implicit return 0, made explicit because the copy is no longer ::main (falling off a non-void function is UB) */
}
#undef main
#undef scanf

void invoke(void) { vmn_main(); }
} /* namespace vmn */
