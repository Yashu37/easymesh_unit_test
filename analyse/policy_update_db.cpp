/*
 * HANDLER: dm_policy_list_t::update_db (fixes 1-2 applied, start fix n / end fix n markers: clamp num_sta to 16, reject NULL data)
 *
 * Copied verbatim from unified-wifi-mesh (develop @ 1ba9529): dm_policy_list_t::update_db (src/dm/dm_policy_list.cpp) and
 * dm_easy_mesh_t::macbytes_to_string (src/dm/dm_easy_mesh.cpp). Local arrays: dev_mac_str[18], radio_mac_str[18], key[256],
 * sta_mac_str[18], sta_mac_list_str[1024]. insert_row / update_row / delete_row are stand-ins that record the key and the STA list
 * they receive (the real ones build and run an SQL statement).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "policy_update_db.h"

namespace pud {
char g_key[512]; char g_list[2048]; int g_calls = 0; policy_box_t *g_box = NULL;

int dm_policy_list_t::insert_row(db_client_t &db, ...)
{ (void)db; va_list a; va_start(a, db); char *key = va_arg(a, char *); (void)va_arg(a, int); (void)va_arg(a, int); char *list = va_arg(a, char *); va_end(a);
  g_calls++; snprintf(g_key, sizeof(g_key), "%s", key); snprintf(g_list, sizeof(g_list), "%s", list); return 0; }
int dm_policy_list_t::update_row(db_client_t &db, ...)
{ (void)db; va_list a; va_start(a, db); (void)va_arg(a, int); (void)va_arg(a, int); char *list = va_arg(a, char *);
  for (int i = 0; i < 14; i++) (void)va_arg(a, long); char *key = va_arg(a, char *); va_end(a);
  g_calls++; snprintf(g_key, sizeof(g_key), "%s", key); snprintf(g_list, sizeof(g_list), "%s", list); return 0; }
int dm_policy_list_t::delete_row(db_client_t &db, ...)
{ (void)db; va_list a; va_start(a, db); char *key = va_arg(a, char *); va_end(a); g_calls++; snprintf(g_key, sizeof(g_key), "%s", key); return 0; }

/* --- copied verbatim --- */
char *dm_easy_mesh_t::macbytes_to_string(mac_address_t mac, char* string)
{
    if( mac != NULL) {
        sprintf(const_cast<char *> (string), "%02x:%02x:%02x:%02x:%02x:%02x",
            mac[0] & 0xff,
            mac[1] & 0xff,
            mac[2] & 0xff,
            mac[3] & 0xff,
            mac[4] & 0xff,
            mac[5] & 0xff);
    }
    return const_cast<char *> (string);
}

int dm_policy_list_t::update_db(db_client_t& db_client, dm_orch_type_t op, void *data)
{
    mac_addr_str_t dev_mac_str, radio_mac_str;
	em_2xlong_string_t key;
    em_policy_t *policy = static_cast<em_policy_t *>(data);
    int ret = 0;
    unsigned int i = 0;
	mac_addr_str_t	sta_mac_str;
	char sta_mac_list_str[1024];

/* start fix 2 */
    if (policy == NULL) {
        return -1;
    }
/* end fix 2 */

    dm_easy_mesh_t::macbytes_to_string(policy->id.dev_mac, dev_mac_str);
    dm_easy_mesh_t::macbytes_to_string(policy->id.radio_mac, radio_mac_str);

	snprintf(key, sizeof(key), "%s@%s@%s@%d", policy->id.net_id, dev_mac_str, radio_mac_str, policy->id.type);

	memset(sta_mac_list_str, 0, sizeof(sta_mac_list_str));
/* start fix 1 */
    unsigned int num_sta = policy->num_sta > EM_MAX_STA_PER_STEER_POLICY ? EM_MAX_STA_PER_STEER_POLICY : policy->num_sta;
/* end fix 1 */
    for (i = 0; i < num_sta; i++) {
		dm_easy_mesh_t::macbytes_to_string(policy->sta_mac[i], sta_mac_str);
        snprintf(sta_mac_list_str + strlen(sta_mac_list_str), sizeof(sta_mac_list_str) - strlen(sta_mac_list_str) - 1,"%s,", sta_mac_str);
    }

	if (strlen(sta_mac_list_str) > 0)
	{
		sta_mac_list_str[strlen(sta_mac_list_str) - 1] = 0;
	}

    switch (op) {
        case dm_orch_type_db_insert:
            ret = insert_row(db_client, key, policy->id.type, policy->interval, sta_mac_list_str, policy->policy, policy->interval, policy->rcpi_threshold,
											policy->rcpi_hysteresis, policy->util_threshold, policy->sta_traffic_stats, 
											policy->sta_link_metric, policy->sta_status, policy->managed_sta_marker,
											policy->independent_scan_report, policy->profile_1_sta_disallowed, policy->profile_2_sta_disallowed,
                                            policy->def_8021q_settings.primary_vid, policy->def_8021q_settings.default_pcp);
            break;

	    case dm_orch_type_db_update:
            ret = update_row(db_client, policy->id.type, policy->interval, sta_mac_list_str, policy->policy, policy->interval, policy->rcpi_threshold,
                                            policy->rcpi_hysteresis, policy->util_threshold, policy->sta_traffic_stats, 
                                            policy->sta_link_metric, policy->sta_status, policy->managed_sta_marker,
                                            policy->independent_scan_report, policy->profile_1_sta_disallowed, policy->profile_2_sta_disallowed,
                                            policy->def_8021q_settings.primary_vid, policy->def_8021q_settings.default_pcp, key);
            break;

	    case dm_orch_type_db_delete:
	        ret = delete_row(db_client, key);
            break;

	    default:
	        break;
	}

    return ret;
}

int invoke(const test_case_t *tc)
{
    db_client_t db; dm_policy_list_t list;
    return list.update_db(db, (dm_orch_type_t)tc->op, tc->null_data ? NULL : (void *)&g_box->p);
}
} /* namespace pud */
