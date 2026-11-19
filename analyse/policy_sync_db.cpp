/*
 * HANDLER: dm_policy_list_t::sync_db
 *
 * Functions copied verbatim from unified-wifi-mesh (develop @ 1ba9529): dm_policy_list_t::sync_db (src/dm/dm_policy_list.cpp)
 * with the helpers it calls: db_easy_mesh_t::get_strings_by_token (src/db/db_easy_mesh.cpp), dm_policy_t::parse_dev_radio_mac_from_key
 * (src/dm/dm_policy.cpp) and dm_easy_mesh_t::string_to_macbytes (src/dm/dm_easy_mesh.cpp). Local arrays in sync_db: str[128],
 * sta_mac_list_str[1024], token_parts[16] (pointers) and sta_mac_str[16][64]. The DB is scripted: db_client_t::get_string copies
 * strlen + 1 bytes into the caller's buffer like the real one (no size), every cell sits between poisoned guards, update_list()
 * records the policies it is given.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "policy_sync_db.h"

namespace spl {
row_t g_rows[SPL_ROWS]; int g_nrows = 0;
std::vector<em_policy_t> dm_policy_list_t::g_updates;

/* --- copied verbatim --- */
void dm_easy_mesh_t::string_to_macbytes(char *key, mac_address_t bmac)
{
    unsigned char mac[6];
    if(strlen(key) > MIN_MAC_LEN)
        sscanf(key, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
                &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
    else
        sscanf(key, "%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx",
                &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
    bmac[0] = mac[0]; bmac[1] = mac[1]; bmac[2] = mac[2];
    bmac[3] = mac[3]; bmac[4] = mac[4]; bmac[5] = mac[5];

}

int dm_policy_t::parse_dev_radio_mac_from_key(const char *key, em_policy_id_t *id)
{
    em_long_string_t   str;
    char *tmp, *remain;
    unsigned int i = 0;

    strncpy(str, key, strlen(key) + 1);
    remain = str;
    while ((tmp = strchr(remain, '@')) != NULL) {
        if (i == 0) {
            *tmp = 0;
            strncpy(id->net_id, remain, strlen(remain) + 1);
            tmp++;
            remain = tmp;
        } else if (i == 1) {
            *tmp = 0;
			dm_easy_mesh_t::string_to_macbytes(remain, id->dev_mac);
            tmp++;
			remain = tmp;
        } else if (i == 2) {
            *tmp = 0;
			dm_easy_mesh_t::string_to_macbytes(remain, id->radio_mac);
            tmp++;
			id->type = static_cast<em_policy_id_type_t>(atoi(tmp));
		}
        i++;
    }

    return 0;
}

int db_easy_mesh_t::get_strings_by_token(char *parent, int token, unsigned int argc, char *argv[])
{
    unsigned int num = 0, i, max_len;
    em_2xlong_string_t str_copy;
    char *tmp, *orig;

	if (*parent == 0) {
		return 0;
	}

    for (i = 0; i < argc; i++) {
        memset(argv[i], 0, sizeof(em_short_string_t));
    }
    
    snprintf(str_copy, sizeof(str_copy), "%s", parent);
    tmp = str_copy;
    orig = str_copy;
    max_len = sizeof(em_short_string_t) - 1;

    while (tmp != NULL) {
        if ((tmp = strchr(orig, token)) != NULL) {
            *tmp = 0;
            assert (num < argc - 1 && "number of extracted values exceeds the limit");
            snprintf(argv[num], sizeof(em_short_string_t), "%.*s", max_len, orig);
            tmp++; num++;
            orig = tmp;
        }
    }

    snprintf(argv[num], sizeof(em_short_string_t), "%.*s", max_len, orig);
    num++;

    return static_cast<int> (num);
}

int dm_policy_list_t::sync_db(db_client_t& db_client, void *ctx)
{
    em_policy_t policy;
	em_policy_id_t	id;
    em_long_string_t   str;
	char sta_mac_list_str[1024] = {0};
	char   *token_parts[EM_MAX_STA_PER_STEER_POLICY];
	em_short_string_t	sta_mac_str[EM_MAX_STA_PER_STEER_POLICY];	
	unsigned int i;
    int rc = 0;

    while (db_client.next_result(ctx)) {
        memset(&policy, 0, sizeof(em_policy_t));
        memset(&id, 0, sizeof(id));

        db_client.get_string(ctx, str, 1);
		dm_policy_t::parse_dev_radio_mac_from_key(str, &id);
		strncpy(policy.id.net_id, id.net_id, sizeof(policy.id.net_id));
		memcpy(policy.id.dev_mac, id.dev_mac, sizeof(mac_address_t));
		memcpy(policy.id.radio_mac, id.radio_mac, sizeof(mac_address_t));
        policy.id.type = static_cast<em_policy_id_type_t>(db_client.get_number(ctx, 2));
        policy.interval = static_cast<unsigned short int>(db_client.get_number(ctx, 3));
        db_client.get_string(ctx, sta_mac_list_str, 4);
		for (i = 0; i < EM_MAX_STA_PER_STEER_POLICY; i++) {
            token_parts[i] = sta_mac_str[i];
        }

        policy.num_sta = static_cast<unsigned int>(get_strings_by_token(sta_mac_list_str, ',', EM_MAX_STA_PER_STEER_POLICY, token_parts));
		for (i = 0; i < policy.num_sta; i++) {
			dm_easy_mesh_t::string_to_macbytes(sta_mac_str[i], policy.sta_mac[i]);
		}		

		policy.policy = static_cast<em_steering_policy_type_t>(db_client.get_number(ctx, 5));
		policy.interval = static_cast<short unsigned int>(db_client.get_number(ctx, 6));
		policy.rcpi_threshold = static_cast<short unsigned int>(db_client.get_number(ctx, 7));
		policy.rcpi_hysteresis = static_cast<short unsigned int>(db_client.get_number(ctx, 8));
		policy.util_threshold = static_cast<short unsigned int>(db_client.get_number(ctx, 9));
		policy.sta_traffic_stats = db_client.get_number(ctx, 10);
		policy.sta_link_metric = db_client.get_number(ctx, 11);
		policy.sta_status = db_client.get_number(ctx, 12);
		db_client.get_string(ctx, policy.managed_sta_marker, 13);
		policy.independent_scan_report = db_client.get_number(ctx, 14);
		policy.profile_1_sta_disallowed = db_client.get_number(ctx, 15);
		policy.profile_2_sta_disallowed = db_client.get_number(ctx, 16);
        policy.def_8021q_settings.primary_vid = static_cast<unsigned short>(db_client.get_number(ctx, 17));
        policy.def_8021q_settings.default_pcp = static_cast<unsigned char>(db_client.get_number(ctx, 18));
        
		update_list(dm_policy_t(&policy), dm_orch_type_db_insert);
    }

    return rc;
}

int invoke(void)
{
    db_client_t db; db.pos = 0;
    dm_policy_list_t list;
    return list.sync_db(db, (void *)&db);
}
} /* namespace spl */
