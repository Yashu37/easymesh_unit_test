/*
 * HANDLER: dm_bss_list_t::sync_db
 *
 * Copied verbatim from unified-wifi-mesh (develop @ 1ba9529): dm_bss_list_t::sync_db (src/dm/dm_bss_list.cpp) with the helpers it
 * calls: db_easy_mesh_t::get_strings_by_token (src/db/db_easy_mesh.cpp), dm_bss_t::parse_bss_id_from_key (src/dm/dm_bss.cpp) and
 * dm_easy_mesh_t::string_to_macbytes (src/dm/dm_easy_mesh.cpp). Local arrays: mac[18], str[128], token_parts[10] (pointers) and the
 * em_bss_info_t info. The DB is scripted: db_client_t::get_string copies strlen + 1 bytes into the caller's buffer like the real one
 * (no size) and leaves the buffer alone for a NULL column; every cell sits between poisoned guards; update_list() records the BSSs
 * it is given.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "bss_sync_db.h"

namespace bsd {
row_t g_rows[BSD_ROWS]; int g_nrows = 0;
std::vector<em_bss_info_t> dm_bss_list_t::g_updates;

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

int dm_bss_t::parse_bss_id_from_key(const char *key, em_bss_id_t *id)
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
            dm_easy_mesh_t::string_to_macbytes(remain, id->ruid);
            tmp++;
			remain = tmp;
		} else if (i == 3) {
            *tmp = 0;
			dm_easy_mesh_t::string_to_macbytes(remain, id->bssid);
            tmp++;
			id->haul_type = static_cast<em_haul_type_t> (atoi(tmp));
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

int dm_bss_list_t::sync_db(db_client_t& db_client, void *ctx)
{
    em_bss_info_t info;
    mac_addr_str_t	mac;
    em_long_string_t   str;
    unsigned int i;
    char   *token_parts[EM_MAX_AKMS];
    int rc = 0;

    while (db_client.next_result(ctx)) {
        memset(&info, 0, sizeof(em_bss_info_t));

        db_client.get_string(ctx, str, 1);
		dm_bss_t::parse_bss_id_from_key(str, &info.id);

        db_client.get_string(ctx, mac, 2);
        dm_easy_mesh_t::string_to_macbytes(mac, info.bssid.mac);

        db_client.get_string(ctx, mac, 3);
        dm_easy_mesh_t::string_to_macbytes(mac, info.ruid.mac);

        db_client.get_string(ctx, info.ssid, 4);
        info.enabled = db_client.get_number(ctx, 5);

        db_client.get_string(ctx, info.est_svc_params_be, 6);
        db_client.get_string(ctx, info.est_svc_params_bk, 7);
        db_client.get_string(ctx, info.est_svc_params_vi, 8);
        db_client.get_string(ctx, info.est_svc_params_vo, 9);

        db_client.get_string(ctx, str, 10);
        for (i = 0; i < EM_MAX_AKMS; i++) {
            token_parts[i] = info.fronthaul_akm[i];
        }
        info.num_fronthaul_akms = static_cast<unsigned char> (get_strings_by_token(str, ',', EM_MAX_AKMS, token_parts));

        db_client.get_string(ctx, str, 11);

        for (i = 0; i < EM_MAX_AKMS; i++) {
            token_parts[i] = info.backhaul_akm[i];
        }
        info.num_backhaul_akms = static_cast<unsigned char> (get_strings_by_token(str, ',', EM_MAX_AKMS, token_parts));

        info.profile_1b_sta_allowed = db_client.get_number(ctx, 12);
        info.profile_2b_sta_allowed = db_client.get_number(ctx, 13);
        info.assoc_allowed_status = static_cast<unsigned int> (db_client.get_number(ctx, 14));
        info.backhaul_use = db_client.get_number(ctx, 15);
        info.fronthaul_use = db_client.get_number(ctx, 16);
        info.r1_disallowed = db_client.get_number(ctx, 17);
        info.r2_disallowed = db_client.get_number(ctx, 18);
        info.multi_bssid = db_client.get_number(ctx, 19);
        info.transmitted_bssid = db_client.get_number(ctx, 20);
        info.vlan_id = static_cast<unsigned int> (db_client.get_number(ctx, 21));

        update_list(dm_bss_t(&info), dm_orch_type_db_insert);
    }

    return rc;

}

int invoke(void)
{
    db_client_t db; db.pos = 0;
    dm_bss_list_t list;
    return list.sync_db(db, (void *)&db);
}
} /* namespace bsd */
