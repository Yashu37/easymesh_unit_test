/*
 * HANDLER: dm_sta_list_t::compare_db (fix 1 applied, start fix n / end fix n markers)
 *
 * Copied verbatim from unified-wifi-mesh (develop @ aee6c47, after #857 reworked the frame body handling): dm_sta_list_t::compare_db
 * (src/dm/dm_sta_list.cpp) with the helpers it calls: decode_frame_body_from_hex and sta_info_equal (same file) and
 * dm_easy_mesh_t::unhex / string_to_macbytes (src/dm/dm_easy_mesh.cpp). The frame body is a std::vector and is length checked
 * before it is read, so the old frame_body[1024] overflow is gone upstream. What is left is the local array mac[18] (mac_addr_str_t):
 * get_string(ctx, mac, 1..3) copies the whole column into it with no size.
 *   fix 1: skip the row when a MAC column (1-3) is not shorter than mac[] (get_string_length()); db_client_t is not changed and the
 *          get_string lines stay original (a shorter column would still be rejected by string_to_macbytes() leaving mac[] uninitialised).
 * The DB is scripted: db_client_t::get_string copies the column's strlen + 1 bytes into the caller's buffer like the real
 * db_client_local_t::get_string (sqlite3_column_bytes + 1, no size) and leaves the buffer alone for a NULL column;
 * get_string_length returns the column length (0 for NULL); every cell sits between poisoned guards.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sta_compare_db.h"

namespace scd {
row_t g_rows[SCD_ROWS]; int g_nrows = 0; dm_sta_t g_sta; int g_gs_calls = 0;

unsigned int db_client_t::get_string_length(void *ctx, unsigned int col)
{ (void)ctx; if (col == 0) return 0; cell_t *c = &g_rows[pos - 1].c[col - 1]; return c->kind == 1 ? (unsigned int)strlen(c->s) : 0; }

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

// Reads and decodes the hex encoded frame body column, whatever its length
void dm_sta_list_t::decode_frame_body_from_hex(db_client_t& db_client, void *ctx, unsigned int col, std::vector<unsigned char>& body)
{
    unsigned int hex_len = db_client.get_string_length(ctx, col);

    body.clear();
    if (hex_len == 0) {
        return;
    }

    // Reject before allocating, the DB does not enforce the declared column width
    if (hex_len / 2 > EM_MAX_FRAME_BODY_LEN) {
        em_printfout("frame_body of %u bytes in DB exceeds max %u, ignoring it", hex_len / 2, EM_MAX_FRAME_BODY_LEN);
        return;
    }

    std::vector<char> hex_str(static_cast<size_t>(hex_len) + 1, '\0');
    if (db_client.get_string(ctx, hex_str.data(), col) == NULL) {
        return;
    }

    body.resize(hex_len / 2);
    if (dm_easy_mesh_t::unhex(hex_len, hex_str.data(), static_cast<unsigned int>(body.size()), body.data()) == NULL) {
        em_printfout("Failed to decode frame_body from DB, ignoring it");
        body.clear();
    }
}

static bool sta_info_equal(const em_sta_info_t *a, const em_sta_info_t *b)
{
    em_sta_info_t tmp;

    memcpy(&tmp, a, sizeof(em_sta_info_t));
    tmp.frame_body = b->frame_body;
    if (memcmp(&tmp, b, sizeof(em_sta_info_t)) != 0) {
        return false;
    }

    if (a->frame_body_len == 0) {
        return true;
    }

    return (a->frame_body != NULL) && (b->frame_body != NULL) &&
        (memcmp(a->frame_body, b->frame_body, a->frame_body_len) == 0);
}

bool dm_sta_list_t::compare_db(db_client_t& db_client, const dm_sta_t& sta)
{
    em_sta_info_t info = {};
    mac_addr_str_t mac;
    std::vector<unsigned char> frame_body;

    db_query_t    query;
    void *ctx;

    memset(query, 0, sizeof(db_query_t));
    snprintf(query, sizeof(db_query_t), "select * from %s", m_table_name);

    ctx = db_client.execute(query);

    while (db_client.next_result(ctx)) {
        memset(&info, 0, sizeof(em_sta_info_t));

/* start fix 1 */
        // A MAC column that does not fit mac[] is not a valid MAC: skip the whole row (string_to_macbytes() would copy
        // uninitialised bytes into the comparison data for an empty string)
        if ((db_client.get_string_length(ctx, 1) >= sizeof(mac)) ||
            (db_client.get_string_length(ctx, 2) >= sizeof(mac)) ||
            (db_client.get_string_length(ctx, 3) >= sizeof(mac))) {
            continue;
        }
/* end fix 1 */
        db_client.get_string(ctx, mac, 1);
        dm_easy_mesh_t::string_to_macbytes(mac, info.id);

        db_client.get_string(ctx, mac, 2);
        dm_easy_mesh_t::string_to_macbytes(mac, info.bssid);

        db_client.get_string(ctx, mac, 3);
        dm_easy_mesh_t::string_to_macbytes(mac, info.radiomac);

        info.associated = db_client.get_number(ctx, 4);
        info.last_ul_rate = static_cast<unsigned int>(db_client.get_number(ctx, 5));
        info.last_dl_rate = static_cast<unsigned int>(db_client.get_number(ctx, 6));
        info.est_ul_rate = static_cast<unsigned int>(db_client.get_number(ctx, 7));
        info.est_dl_rate = static_cast<unsigned int>(db_client.get_number(ctx, 8));
        info.last_conn_time = static_cast<unsigned int>(db_client.get_number(ctx, 9));
        info.retrans_count = static_cast<unsigned int>(db_client.get_number(ctx, 10));
        info.signal_strength = (db_client.get_number(ctx, 11));
        info.rcpi = static_cast<unsigned char> (db_client.get_number(ctx, 12));
        info.util_tx = static_cast<unsigned char> (db_client.get_number(ctx, 13));
        info.util_rx = static_cast<unsigned char> (db_client.get_number(ctx, 14));
        info.pkts_tx = static_cast<unsigned char> (db_client.get_number(ctx, 15));
        info.pkts_rx = static_cast<unsigned char> (db_client.get_number(ctx, 16));
        info.bytes_tx = static_cast<unsigned char> (db_client.get_number(ctx, 17));
        info.bytes_rx = static_cast<unsigned char> (db_client.get_number(ctx, 18));
        info.errors_tx = static_cast<unsigned char> (db_client.get_number(ctx, 19));
        info.errors_rx = static_cast<unsigned char> (db_client.get_number(ctx, 20));

        // info only borrows the decoded frame body for the comparison
        dm_sta_list_t::decode_frame_body_from_hex(db_client, ctx, 22, frame_body);
        info.frame_body = frame_body.empty() ? NULL : frame_body.data();
        info.frame_body_len = static_cast<unsigned int>(frame_body.size());

        if (sta_info_equal(&sta.m_sta_info, &info)) {
            db_client.free_result(ctx);
            return true;
        }
    }

    return false;
}

static __attribute__((noinline)) void dirty_stack(void) { volatile char junk[24000]; for (size_t i = 0; i < sizeof(junk); i++) junk[i] = 'A'; }

bool invoke(const test_case_t *tc)
{
    db_client_t db; db.pos = 0; g_gs_calls = 0;
    dm_sta_list_t list;
    if (tc->variant == 1) dirty_stack();
    return list.compare_db(db, g_sta);
}
} /* namespace scd */
