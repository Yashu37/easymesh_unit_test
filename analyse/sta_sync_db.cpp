/*
 * HANDLER: dm_sta_list_t::sync_db (fixes 1-2 applied, start fix n / end fix n markers: bounded get_string(ctx, buf, col, size) for the MAC
 * and frame body columns, mac / frame_body initialised; the stale-buffer failures are left original)
 *
 * Copied verbatim from unified-wifi-mesh (develop @ 1ba9529): dm_sta_list_t::sync_db (src/dm/dm_sta_list.cpp) with the helpers it
 * calls: dm_easy_mesh_t::unhex and string_to_macbytes (src/dm/dm_easy_mesh.cpp). Local arrays: mac[18] (mac_addr_str_t),
 * frame_body[1024] and the em_sta_info_t info. The DB is scripted: db_client_t::get_string copies strlen + 1 bytes into the caller's
 * buffer like the real one (no size) and leaves the buffer alone for a NULL column; every cell sits between poisoned guards;
 * update_list() records the stations it is given.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sta_sync_db.h"

namespace ssd {
row_t g_rows[SSD_ROWS]; int g_nrows = 0;
std::vector<em_sta_info_t> dm_sta_list_t::g_updates;

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

unsigned char *dm_easy_mesh_t::unhex(unsigned int in_len, char *in, unsigned int out_len, unsigned char *out)
{
    unsigned int i;
    unsigned char tmp1, tmp2;

    if (out_len < in_len/2) {
        return NULL;
    }

    for (i = 0; i < in_len/2; i++) {
        if (in[2*i] <= '9') {
            tmp1 = static_cast<unsigned char> (in[2*i]) - 0x30;
        } else {
            tmp1 = static_cast<unsigned char> (in[2*i]) - 0x61 + 0xa;
        }

        tmp1 = static_cast<unsigned char> (tmp1 << 4);

        if (in[2*i + 1] <= '9') {
            tmp2 = static_cast<unsigned char> (in[2*i + 1]) - 0x30;
        } else {
            tmp2 = static_cast<unsigned char> (in[2*i + 1]) - 0x61 + 0xa;
        }

        tmp2 &= 0xf;

        out[i] = tmp1 | tmp2;
    }

    return out;
}

int dm_sta_list_t::sync_db(db_client_t& db_client, void *ctx)
{
    em_sta_info_t info;
/* start fix 2 */
    mac_addr_str_t	mac = {0};
    int rc = 0;
    char frame_body[EM_MAX_FRAME_BODY_LEN*2] = {0};
/* end fix 2 */

    while (db_client.next_result(ctx)) {
        memset(&info, 0, sizeof(em_sta_info_t));

/* start fix 1 */
        db_client.get_string(ctx, mac, 1, sizeof(mac));
/* end fix 1 */
        dm_easy_mesh_t::string_to_macbytes(mac, info.id);

/* start fix 1 */
        db_client.get_string(ctx, mac, 2, sizeof(mac));
/* end fix 1 */
        dm_easy_mesh_t::string_to_macbytes(mac, info.bssid);

/* start fix 1 */
        db_client.get_string(ctx, mac, 3, sizeof(mac));
/* end fix 1 */
        dm_easy_mesh_t::string_to_macbytes(mac, info.radiomac);

        info.associated = db_client.get_number(ctx, 4);
        info.last_ul_rate = static_cast<unsigned int>(db_client.get_number(ctx, 5));
        info.last_dl_rate = static_cast<unsigned int>(db_client.get_number(ctx, 6));
        info.est_ul_rate = static_cast<unsigned int>(db_client.get_number(ctx, 7));
        info.est_dl_rate = static_cast<unsigned int>(db_client.get_number(ctx, 8));
        info.last_conn_time = static_cast<unsigned int>(db_client.get_number(ctx, 9));
        info.retrans_count = static_cast<unsigned int>(db_client.get_number(ctx, 10));
        info.signal_strength = static_cast<signed int> (db_client.get_number(ctx, 11));
        info.rcpi = static_cast<unsigned char> (db_client.get_number(ctx, 12));
        info.util_tx = static_cast<unsigned int> (db_client.get_number(ctx, 13));
        info.util_rx = static_cast<unsigned int> (db_client.get_number(ctx, 14));
        info.pkts_tx = static_cast<unsigned int> (db_client.get_number(ctx, 15));
        info.pkts_rx = static_cast<unsigned int> (db_client.get_number(ctx, 16));
        info.bytes_tx = static_cast<unsigned int> (db_client.get_number(ctx, 17));
        info.bytes_rx = static_cast<unsigned int> (db_client.get_number(ctx, 18));
        info.errors_tx = static_cast<unsigned int> (db_client.get_number(ctx, 19));
        info.errors_rx = static_cast<unsigned int> (db_client.get_number(ctx, 20));
        info.frame_body_len = static_cast<unsigned int> (db_client.get_number(ctx, 21));

/* start fix 1 */
        db_client.get_string(ctx, frame_body, 22, sizeof(frame_body));
/* end fix 1 */
        dm_easy_mesh_t::unhex(static_cast<unsigned int>(strlen(frame_body)), frame_body, EM_MAX_FRAME_BODY_LEN, info.frame_body);

        update_list(dm_sta_t(&info), dm_orch_type_db_insert);
    }
    return rc;
}

int invoke(void)
{
    db_client_t db; db.pos = 0;
    dm_sta_list_t list;
    return list.sync_db(db, (void *)&db);
}
} /* namespace ssd */
