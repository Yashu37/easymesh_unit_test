/*
 * HANDLER: dm_network_list_t::sync_db
 *
 * Copied verbatim from unified-wifi-mesh (develop @ 1ba9529): dm_network_list_t::sync_db (src/dm/dm_network_list.cpp) with the
 * helpers it calls: util::get_date_time_rfc3399 (src/utils/util.cpp) and dm_easy_mesh_t::string_to_macbytes (src/dm/dm_easy_mesh.cpp).
 * Local arrays: mac[18] (mac_addr_str_t), date_time[64] and the em_network_info_t info (id[128], timestamp[128], ...). The DB is
 * scripted: db_client_t::get_string copies strlen + 1 bytes into the caller's buffer like the real one (no size) and leaves the
 * buffer alone for a NULL column; every cell sits between poisoned guards; update_list() records the networks it is given.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "network_sync_db.h"

namespace nsd {
row_t g_rows[NSD_ROWS]; int g_nrows = 0;
std::vector<em_network_info_t> dm_network_list_t::g_updates;

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

namespace util {
char *get_date_time_rfc3399(char *buff, unsigned int len)
{
	time_t now;
    struct tm *timeinfo;

    time(&now);
    timeinfo = localtime(&now);

	memset(buff, 0, len);
	strftime(buff, len, "%Y-%m-%dT%H:%M:%SZ", timeinfo);

	return buff;
}
}

int dm_network_list_t::sync_db(db_client_t& db_client, void *ctx)
{
    mac_addr_str_t	mac;
    em_network_info_t info;
    int rc = 0;
	char date_time[EM_DATE_TIME_BUFF_SZ];

	memset(&info, 0, sizeof(em_network_info_t));
	util::get_date_time_rfc3399(date_time, EM_DATE_TIME_BUFF_SZ);
	strncpy(info.timestamp, date_time, sizeof(em_long_string_t));

    // there is only one row in network
    while (db_client.next_result(ctx)) {
		db_client.get_string(ctx, info.id, 1);
		db_client.get_string(ctx, mac, 2);
		dm_easy_mesh_t::string_to_macbytes(mac, info.ctrl_id.mac);

		db_client.get_string(ctx, mac, 3);
		dm_easy_mesh_t::string_to_macbytes(mac, info.colocated_agent_id.mac);

		info.media = static_cast<em_media_type_t> (db_client.get_number(ctx, 4));

		info.ctrl_id.media = info.media;
		info.colocated_agent_id.media = info.media;

		update_list(dm_network_t(&info), dm_orch_type_db_insert);
    }
    return rc;
}

int invoke(void)
{
    db_client_t db; db.pos = 0;
    dm_network_list_t list;
    return list.sync_db(db, (void *)&db);
}
} /* namespace nsd */
