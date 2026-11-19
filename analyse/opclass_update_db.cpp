/*
 * HANDLER: dm_op_class_list_t::update_db (fixes 1-2 applied, start fix n / end fix n markers: clamp num_channels to 64, reject NULL data)
 *
 * Copied verbatim from unified-wifi-mesh (develop @ 1ba9529): dm_op_class_list_t::update_db (src/dm/dm_op_class_list.cpp) and
 * dm_easy_mesh_t::macbytes_to_string (src/dm/dm_easy_mesh.cpp). Local arrays: mac_str[18], id[128], channels_str[256], pref_str[256],
 * tmp[8]. insert_row / update_row / delete_row are stand-ins that record the id, the channel list and the preference list they
 * receive (the real ones build and run an SQL statement).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "opclass_update_db.h"

namespace oud {
char g_id[512]; char g_channels[512]; char g_pref[512]; int g_calls = 0; info_box_t *g_box = NULL;

int dm_op_class_list_t::insert_row(db_client_t &db, ...)
{ (void)db; va_list a; va_start(a, db); char *id = va_arg(a, char *); (void)va_arg(a, unsigned); (void)va_arg(a, unsigned); char *ch = va_arg(a, char *); char *pf = va_arg(a, char *); va_end(a);
  g_calls++; snprintf(g_id, sizeof(g_id), "%s", id); snprintf(g_channels, sizeof(g_channels), "%s", ch); snprintf(g_pref, sizeof(g_pref), "%s", pf); return 0; }
int dm_op_class_list_t::update_row(db_client_t &db, ...)
{ (void)db; va_list a; va_start(a, db); (void)va_arg(a, unsigned); (void)va_arg(a, unsigned); char *ch = va_arg(a, char *); char *pf = va_arg(a, char *);
  for (int i = 0; i < 6; i++) (void)va_arg(a, long); char *id = va_arg(a, char *); va_end(a);
  g_calls++; snprintf(g_id, sizeof(g_id), "%s", id); snprintf(g_channels, sizeof(g_channels), "%s", ch); snprintf(g_pref, sizeof(g_pref), "%s", pf); return 0; }
int dm_op_class_list_t::delete_row(db_client_t &db, ...)
{ (void)db; va_list a; va_start(a, db); char *id = va_arg(a, char *); va_end(a); g_calls++; snprintf(g_id, sizeof(g_id), "%s", id); return 0; }

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

int dm_op_class_list_t::update_db(db_client_t& db_client, dm_orch_type_t op, void *data)
{
    mac_addr_str_t mac_str;
    em_long_string_t id;
    em_2xlong_string_t channels_str = {0};
    em_2xlong_string_t pref_str = {0};
    char tmp[8];
    em_op_class_info_t *info = static_cast<em_op_class_info_t *>(data);
    int ret = 0;
    unsigned int i;

/* start fix 2 */
    if (info == NULL) {
        return -1;
    }
/* end fix 2 */

    dm_easy_mesh_t::macbytes_to_string(info->id.ruid, mac_str);
    snprintf(id, sizeof(id), "%s@%d@%d", mac_str, info->id.type, info->id.op_class);
    //printf("%s:%d: Operation:%d, id:%s\tClass: %d Channel:%d\n", __func__, __LINE__, op, id, info->op_class, info->channel);
    //Storing channels and its preferences as comma separated string in db.
/* start fix 1 */
    unsigned int num_channels = info->num_channels > EM_MAX_CHANNELS_IN_LIST ? EM_MAX_CHANNELS_IN_LIST : info->num_channels;
/* end fix 1 */
	for (i = 0; i < num_channels; i++) {
		snprintf(tmp, sizeof(tmp), "%d,", info->channels[i]);
		snprintf(channels_str + strlen(channels_str), sizeof(channels_str) - strlen(channels_str), "%s", tmp);
        if (info->id.type == em_op_class_type_preference || info->id.type == em_op_class_type_anticipated) {
        	snprintf(tmp, sizeof(tmp), "%d,", info->channel_pref[i]);
        	snprintf(pref_str + strlen(pref_str), sizeof(pref_str) - strlen(pref_str), "%s", tmp);
        }
	}
    if (info->id.type != em_op_class_type_preference && info->id.type != em_op_class_type_anticipated) {
        info->pref_valid = EM_CH_PREF_ENTRY_VALID;
    }
	if (strlen(channels_str) > 0) {
		channels_str[strlen(channels_str) - 1] = 0;
	}

    if (strlen(pref_str) > 0) {
        pref_str[strlen(pref_str) - 1] = 0;
    }
    switch (op) {
        case dm_orch_type_db_insert:
            ret = insert_row(db_client, id, info->op_class, info->channel, channels_str, pref_str, info->pref_valid, info->tx_power, info->max_tx_power,
                                           info->mins_since_cac_comp, info->sec_remain_non_occ_dur, info->countdown_cac_comp);
            break;

	    case dm_orch_type_db_update:
            ret = update_row(db_client, info->op_class, info->channel, channels_str, pref_str, info->pref_valid, info->tx_power, info->max_tx_power,
                                       info->mins_since_cac_comp, info->sec_remain_non_occ_dur, info->countdown_cac_comp, id);
            break;

	    case dm_orch_type_db_delete:
	        ret = delete_row(db_client, id);
            break;

	    default:
	        break;
	}

    return ret;
}

int invoke(const test_case_t *tc)
{
    db_client_t db; dm_op_class_list_t list;
    return list.update_db(db, (dm_orch_type_t)tc->op, tc->null_data ? NULL : (void *)&g_box->info);
}
} /* namespace oud */
