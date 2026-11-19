/*
 * HANDLER: dm_op_class_list_t::sync_db (fixes 1-2 applied, start fix n / end fix n markers: bounded get_string(ctx, buf, col, size)
 * for the ID and both list columns, get_strings_by_token ignores entries beyond the slots instead of asserting)
 *
 * Copied verbatim from unified-wifi-mesh (develop @ 1ba9529): dm_op_class_list_t::sync_db (src/dm/dm_op_class_list.cpp) with the
 * helpers it calls: db_easy_mesh_t::get_strings_by_token (src/db/db_easy_mesh.cpp), dm_op_class_t::parse_op_class_id_from_key
 * (src/dm/dm_op_class.cpp) and dm_easy_mesh_t::string_to_macbytes (src/dm/dm_easy_mesh.cpp). Local arrays: id[128], str[256],
 * ch_str[64][64], token_parts[64] (pointers) and the em_op_class_info_t info. The DB is scripted: db_client_t::get_string copies
 * strlen + 1 bytes into the caller's buffer like the real one (no size); every cell sits between poisoned guards; update_list()
 * records the op classes it is given; em_printfout() is a no-op.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "opclass_sync_db.h"

namespace ocs {
row_t g_rows[OCS_ROWS]; int g_nrows = 0;
std::vector<em_op_class_info_t> dm_op_class_list_t::g_updates;

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

int dm_op_class_t::parse_op_class_id_from_key(const char *key, em_op_class_id_t *id)
{
    em_long_string_t   str;
    char *tmp, *remain;
    unsigned int i = 0;

    strncpy(str, key, strlen(key) + 1);
    remain = str;
    while ((tmp = strchr(remain, '@')) != NULL) {
        if (i == 0) {
            *tmp = 0;
            dm_easy_mesh_t::string_to_macbytes(remain, id->ruid);
            tmp++;
            remain = tmp;
        } else if (i == 1) {
            *tmp = 0;
            id->type = static_cast<em_op_class_type_t>(atoi(remain));
            tmp++;
            id->op_class = static_cast<unsigned int>(atoi(tmp));
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

int dm_op_class_list_t::sync_db(db_client_t& db_client, void *ctx)
{
    em_op_class_info_t info;
    em_long_string_t   id;
    em_2xlong_string_t str;
    em_short_string_t	ch_str[EM_MAX_CHANNELS_IN_LIST];
    char   *token_parts[EM_MAX_CHANNELS_IN_LIST];
    unsigned int i = 0;
    int rc = 0;

    while (db_client.next_result(ctx)) {
        memset(&info, 0, sizeof(em_op_class_info_t));

        /* start fix 1 */
        db_client.get_string(ctx, id, 1, sizeof(id));
        /* end fix 1 */
        dm_op_class_t::parse_op_class_id_from_key(id, &info.id);
        info.op_class = static_cast<short unsigned int>(db_client.get_number(ctx, 2));
        info.channel = static_cast<short unsigned int>(db_client.get_number(ctx, 3));

        /* start fix 1 */
        db_client.get_string(ctx, str, 4, sizeof(str));
        /* end fix 1 */
        for (i = 0; i < EM_MAX_CHANNELS_IN_LIST; i++) {
            token_parts[i] = ch_str[i];
        }

        if (*str != 0) {
            info.num_channels = static_cast<unsigned int>(get_strings_by_token(str, ',', EM_MAX_CHANNELS_IN_LIST, token_parts));
            for (i = 0; i < info.num_channels; i++)
            {
                info.channels[i] = static_cast<unsigned int>(atoi(token_parts[i]));
            }
        }

        // Sync DB for preference of each channel in op classs.
        // This is only applicable for preference and anticipated type of op class.
        // For other types, set preference as valid but with 0 preference value.
        if (info.id.type == em_op_class_type_preference || info.id.type == em_op_class_type_anticipated)
        {
            /* start fix 1 */
            db_client.get_string(ctx, str, 5, sizeof(str));
            /* end fix 1 */
            for (i = 0; i < EM_MAX_CHANNELS_IN_LIST; i++) {
                token_parts[i] = ch_str[i];
            }

            if (*str != 0) {
                unsigned int num_of_pref = static_cast<unsigned int>(get_strings_by_token(str, ',', EM_MAX_CHANNELS_IN_LIST, token_parts));
                if (num_of_pref != info.num_channels)
                {
                    em_printfout("ERROR: Number of preferences %d does not match number of channels %d for op class %d\n",
                                 num_of_pref, info.num_channels, info.op_class);
                }
                for (i = 0; i < num_of_pref; i++)
                {
                    info.channel_pref[i] = static_cast<unsigned char>(atoi(token_parts[i]));
                }
            }
            info.pref_valid = static_cast<short unsigned int>(db_client.get_number(ctx, 6));
        } else {
            memset(info.channel_pref, 0, sizeof(info.channel_pref));
            info.pref_valid = EM_CH_PREF_ENTRY_VALID;
        }

        info.tx_power = db_client.get_number(ctx, 7);
        info.max_tx_power = db_client.get_number(ctx, 8);

        info.mins_since_cac_comp = static_cast<short unsigned int>(db_client.get_number(ctx, 9));
        info.sec_remain_non_occ_dur = static_cast<short unsigned int>(db_client.get_number(ctx, 10));
        info.countdown_cac_comp = static_cast<unsigned int>(db_client.get_number(ctx, 11));

        update_list(dm_op_class_t(&info), dm_orch_type_db_insert);
    }

    return rc;
}

int invoke(void)
{
    db_client_t db; db.pos = 0;
    dm_op_class_list_t list;
    return list.sync_db(db, (void *)&db);
}
} /* namespace ocs */
