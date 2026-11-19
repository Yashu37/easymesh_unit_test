/*
 * HANDLER: dm_network_ssid_list_t::sync_db (fixes 1-2 applied, start fix n / end fix n markers: bounded get_string(ctx, buf, col, size)
 * overload for every string column, get_strings_by_token ignores entries beyond the slots instead of asserting)
 *
 * Copied verbatim from unified-wifi-mesh (develop @ 1ba9529): dm_network_ssid_list_t::sync_db (src/dm/dm_network_ssid_list.cpp) with
 * the helpers it calls: db_easy_mesh_t::get_strings_by_token (src/db/db_easy_mesh.cpp), dm_network_ssid_t::haul_type_from_string
 * (src/dm/dm_network_ssid.cpp) and dm_easy_mesh_t::string_to_macbytes (src/dm/dm_easy_mesh.cpp). Local arrays: mac[18], str[128],
 * token_parts[10] (pointers), haul_type[10][32] and the em_network_ssid_info_t info. The DB is scripted: db_client_t::get_string
 * copies strlen + 1 bytes into the caller's buffer like the real one (no size); every cell sits between poisoned guards;
 * update_list() records the networks it is given.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "network_ssid_sync_db.h"

namespace nss {
row_t g_rows[NSS_ROWS]; int g_nrows = 0;
std::vector<em_network_ssid_info_t> dm_network_ssid_list_t::g_updates;

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

em_haul_type_t dm_network_ssid_t::haul_type_from_string(em_string_t str)
{
    em_haul_type_t type;

    if (strncmp(str, "Fronthaul", strlen(str)) == 0) {
	type = em_haul_type_fronthaul;		
    } else if (strncmp(str, "Backhaul", strlen(str)) == 0) {
        type = em_haul_type_backhaul;
    } else if (strncmp(str, "IoT", strlen(str)) == 0) {
        type = em_haul_type_iot;
    } else if (strncmp(str, "Configurator", strlen(str)) == 0) {
        type = em_haul_type_configurator;
	} else if (strncmp(str, "Hotspot", strlen(str)) == 0) {
		type = em_haul_type_hotspot;
    } else {
        type = em_haul_type_max;
    }

    return type; 
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
/* start fix 2 */
            if (num >= argc - 1) {
                /* more values than slots: keep the first argc values, ignore the rest instead of asserting */
                break;
            }
/* end fix 2 */
            snprintf(argv[num], sizeof(em_short_string_t), "%.*s", max_len, orig);
            tmp++; num++;
            orig = tmp;
        }
    }

    snprintf(argv[num], sizeof(em_short_string_t), "%.*s", max_len, orig);
    num++;

    return static_cast<int> (num);
}

int dm_network_ssid_list_t::sync_db(db_client_t& db_client, void *ctx)
{
	em_network_ssid_info_t info;
	mac_addr_str_t	mac;
    em_long_string_t   str;
    char   *token_parts[10];
    em_string_t haul_type[10];
	unsigned int i;
    int rc = 0;

    while (db_client.next_result(ctx)) {
		memset(&info, 0, sizeof(em_network_ssid_info_t));

		/* start fix 1 */
		db_client.get_string(ctx, info.id, 1, sizeof(info.id));
		/* end fix 1 */
		/* start fix 1 */
		db_client.get_string(ctx, info.ssid, 2, sizeof(info.ssid));
		/* end fix 1 */
        /* start fix 1 */
        db_client.get_string(ctx, info.pass_phrase, 3, sizeof(info.pass_phrase));
        /* end fix 1 */
		/* start fix 1 */
		db_client.get_string(ctx, str, 4, sizeof(str));
		/* end fix 1 */
		for (i = 0; i < EM_MAX_BANDS; i++) {
			token_parts[i] = info.band[i];
		}
		info.num_bands = static_cast<unsigned char> (get_strings_by_token(str, ',', EM_MAX_BANDS, token_parts));
		for (i = 0; i < info.num_bands; i++) {
			//printf("%s:%d: Band[%d]: %s\n", __func__, __LINE__, i, info.band[i]);
		}

        info.enable = db_client.get_number(ctx, 5);

		/* start fix 1 */
		db_client.get_string(ctx, str, 6, sizeof(str));
		/* end fix 1 */
		for (i = 0; i < EM_MAX_AKMS; i++) {
			token_parts[i] = info.akm[i];
		}
		info.num_akms = static_cast<unsigned char> (get_strings_by_token(str, ',', EM_MAX_AKMS, token_parts));
		for (i = 0; i < info.num_akms; i++) {
			//printf("%s:%d: akm[%d]: %s\n", __func__, __LINE__, i, info.akm[i]);
		}


		/* start fix 1 */
		db_client.get_string(ctx, info.suite_select, 7, sizeof(info.suite_select));
		/* end fix 1 */
		info.advertisement = db_client.get_number(ctx, 8);
		/* start fix 1 */
		db_client.get_string(ctx, info.mfp, 9, sizeof(info.mfp));
		/* end fix 1 */

		/* start fix 1 */
		db_client.get_string(ctx, mac, 10, sizeof(mac));
		/* end fix 1 */
		dm_easy_mesh_t::string_to_macbytes(mac, info.mobility_domain);

		/* start fix 1 */
		db_client.get_string(ctx, str, 11, sizeof(str));
		/* end fix 1 */
		for (i = 0; i < EM_MAX_HAUL_TYPES; i++) {
			token_parts[i] = haul_type[i];
		}
		info.num_hauls = static_cast<unsigned char> (get_strings_by_token(str, ',', EM_MAX_HAUL_TYPES, token_parts));
		for (i = 0; i < info.num_hauls; i++) {
            info.haul_type[i] = dm_network_ssid_t::haul_type_from_string(haul_type[i]);
			//printf("%s:%d: Haul Type[%d]: %s\n", __func__, __LINE__, i, info.haul_type[i]);
		}

		/* start fix 1 */
		db_client.get_string(ctx, info.auth_type, 12, sizeof(info.auth_type));
		/* end fix 1 */

		info.vlan_id = db_client.get_number(ctx, 13);
        
		update_list(dm_network_ssid_t(&info), dm_orch_type_db_insert);
    }
    return rc;
}

int invoke(void)
{
    db_client_t db; db.pos = 0;
    dm_network_ssid_list_t list;
    return list.sync_db(db, (void *)&db);
}
} /* namespace nss */
