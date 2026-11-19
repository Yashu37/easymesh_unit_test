/*
 * HANDLER: dm_radio_cap_list_t::update_db (fixes 1-2 applied, start fix n / end fix n markers: reject NULL data, size wifi7_str for the
 * whole 2 * sizeof(wifi7_cap) + 1 hex string)
 *
 * Copied verbatim from unified-wifi-mesh (develop @ 1ba9529): dm_radio_cap_list_t::update_db (src/dm/dm_radio_cap_list.cpp) and
 * dm_easy_mesh_t::macbytes_to_string (src/dm/dm_easy_mesh.cpp). Local arrays: mac_str[18], wifi7_str[256]. The radio cap info is the real
 * em_wifi7_agent_cap_t (488 bytes -> 976 hex characters). insert_row / update_row / delete_row are stand-ins that record the key and the
 * wifi7 string they receive (the real ones build and run an SQL statement).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "radio_cap_update_db.h"

namespace rcu {
char g_key[64]; char g_wifi7[4096]; unsigned int g_nop = 0; int g_calls = 0; box_t *g_box = NULL;

int dm_radio_cap_list_t::insert_row(db_client_t &db, char *mac, em_ap_ht_cap_t ht, em_ap_vht_cap_t vht, em_ap_he_cap_t he, char *wifi7, unsigned int nop)
{ g_calls++; snprintf(g_key, sizeof(g_key), "%s", mac); snprintf(g_wifi7, sizeof(g_wifi7), "%s", wifi7); g_nop = nop; return 0; }
int dm_radio_cap_list_t::update_row(db_client_t &db, em_ap_ht_cap_t ht, em_ap_vht_cap_t vht, em_ap_he_cap_t he, char *wifi7, unsigned int nop, char *mac)
{ g_calls++; snprintf(g_key, sizeof(g_key), "%s", mac); snprintf(g_wifi7, sizeof(g_wifi7), "%s", wifi7); g_nop = nop; return 0; }
int dm_radio_cap_list_t::delete_row(db_client_t &db, char *mac)
{ g_calls++; snprintf(g_key, sizeof(g_key), "%s", mac); return 0; }

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

int dm_radio_cap_list_t::update_db(db_client_t& db_client, dm_orch_type_t op, void *data)
{
    mac_addr_str_t mac_str;
    em_radio_cap_info_t *info = static_cast<em_radio_cap_info_t *>(data);
    int ret = 0;

/* start fix 1 */
    if (info == NULL) {
        return -1;
    }
/* end fix 1 */
/* start fix 2 */
    char wifi7_str[sizeof(info->wifi7_cap) * 2 + 1] = {0};
/* end fix 2 */
    size_t offset = 0;

    uint8_t *ptr = reinterpret_cast<uint8_t *> (&info->wifi7_cap);
    size_t len = sizeof(info->wifi7_cap);

    for (size_t i = 0; i < len; i++) {
        int ret = snprintf(wifi7_str + offset,
                   sizeof(wifi7_str) - offset,
                   "%02X", ptr[i]);
        if (ret < 0) {
            // encoding error
            return -1;
        }

        offset += static_cast<size_t> (ret);
    }

    printf("%s:%d: Opeartion:%d\n", __func__, __LINE__, op);

	switch (op) {
		case dm_orch_type_db_insert:
			ret = insert_row(db_client, dm_easy_mesh_t::macbytes_to_string(info->ruid.mac, mac_str), 
						info->ht_cap, info->vht_cap, info->he_cap, wifi7_str, info->num_op_classes);
			break;

		case dm_orch_type_db_update:
			ret = update_row(db_client, info->ht_cap, info->vht_cap, info->he_cap, wifi7_str, info->num_op_classes,
						dm_easy_mesh_t::macbytes_to_string(info->ruid.mac, mac_str));
			break;

		case dm_orch_type_db_delete:
			ret = delete_row(db_client, dm_easy_mesh_t::macbytes_to_string(info->ruid.mac, mac_str));
			break;

		default:
			break;
	}

    return ret;
}

int invoke(const test_case_t *tc)
{
    dm_radio_cap_list_t l; db_client_t db;
    return l.update_db(db, (dm_orch_type_t)tc->op, tc->null_data ? NULL : (void *)&g_box->info);
}
} /* namespace rcu */
