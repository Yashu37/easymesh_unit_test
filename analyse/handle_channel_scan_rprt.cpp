#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

dm_scan_result_t *dm_easy_mesh_t::find_matching_scan_result(em_scan_result_id_t *id)
{
    dm_scan_result_t *res;

        res = static_cast<dm_scan_result_t *> (hash_map_get_first(m_scan_result_map));
        while (res != NULL) {
        if ((strncmp(res->m_scan_result.id.net_id, id->net_id, strlen(id->net_id)) == 0) &&
                (memcmp(res->m_scan_result.id.dev_mac, id->dev_mac, sizeof(mac_address_t)) == 0) &&
                (memcmp(res->m_scan_result.id.scanner_mac, id->scanner_mac, sizeof(mac_address_t)) == 0) &&
                (res->m_scan_result.id.op_class == id->op_class) &&
                (res->m_scan_result.id.channel == id->channel) &&
                (res->m_scan_result.id.scanner_type == id->scanner_type)) {
            return res;
        }

                res = static_cast<dm_scan_result_t *> (hash_map_get_next(m_scan_result_map, res));
        }

    return NULL;
}

int8_t     queue_push      (queue_t *q, void *data)
{
    element_t *e, *tmp;
    e = (element_t *)malloc(sizeof(element_t));
    if (e == NULL) {
        return -1;
    }
    memset(e, 0, sizeof(element_t));
    e->data = data;
    if (q->head == NULL) {
        q->head = e;
    } else {
        tmp = q->head;
        q->head = e;
        e->next = tmp;
    }
    q->count++;
    return 0;
}

int8_t hash_map_put(hash_map_t *map, char *key, void *data)
{
    hash_element_t *e;

    if (map == NULL || map->queue == NULL || key == NULL) {
        return -1;
    }

    map->itr = NULL;
    e = (hash_element_t *)malloc(sizeof(hash_element_t));
    if (e == NULL) {
        return -1;
    }
    memset(e, 0, sizeof(hash_element_t));
    e->key = key;
    e->data = data;

    if (queue_push(map->queue, e) < 0) {
        free(key);
        key = NULL;
        if (e->data != NULL) {
            free(e->data);
            e->data = NULL;
        }
        free(e);
        return -1;
    }
    return 0;
}

dm_scan_result_t *dm_easy_mesh_t::create_new_scan_result(em_scan_result_id_t *id)
{
        dm_scan_result_t *res, scan_result;
        em_2xlong_string_t key;
        mac_addr_str_t  dev_mac_str, scanner_mac_str;

        memcpy(&scan_result.m_scan_result.id, id, sizeof(em_scan_result_id_t));

        res = new dm_scan_result_t(scan_result);

    dm_easy_mesh_t::macbytes_to_string(id->dev_mac, dev_mac_str);
    dm_easy_mesh_t::macbytes_to_string(id->scanner_mac, scanner_mac_str);

        snprintf(key, sizeof(em_2xlong_string_t), "%s@%s@%s@%d@%d@%d", res->m_scan_result.id.net_id, dev_mac_str, scanner_mac_str,
                    res->m_scan_result.id.op_class, res->m_scan_result.id.channel, res->m_scan_result.id.scanner_type);

        hash_map_put(m_scan_result_map, strdup(key), res);

        return res;
}

void em_channel_t::fill_scan_result(dm_scan_result_t *scan_res, em_channel_scan_result_t *res)
{
        unsigned char *tmp;
        em_neighbor_t *nbr;
        unsigned char ssid_len, bw_len;
        char bandwidth[32] = {0};
        unsigned int i;
        mac_addr_str_t bssid_str;

        scan_res->m_scan_result.scan_status = res->scan_status;
        strncpy(scan_res->m_scan_result.timestamp, res->timestamp, static_cast<size_t>(res->timestamp_len + 1));

        tmp = reinterpret_cast<unsigned char *> (res) + sizeof(em_channel_scan_result_t) + res->timestamp_len;

        memcpy(&scan_res->m_scan_result.util, tmp, sizeof(unsigned char));
        tmp += sizeof(unsigned char);

        memcpy(&scan_res->m_scan_result.noise, tmp, sizeof(unsigned char));
        tmp += sizeof(unsigned char);

        memcpy(&scan_res->m_scan_result.num_neighbors, tmp, sizeof(unsigned short));
        scan_res->m_scan_result.num_neighbors = htons(scan_res->m_scan_result.num_neighbors);
        tmp += sizeof(unsigned short);

        if (scan_res->m_scan_result.num_neighbors > EM_MAX_NEIGHBORS) {
                scan_res->m_scan_result.num_neighbors = EM_MAX_NEIGHBORS;
        }

    for (i = 0; i < scan_res->m_scan_result.num_neighbors; i++) {
        nbr = &scan_res->m_scan_result.neighbor[i];

        memcpy(nbr->bssid, tmp, sizeof(mac_address_t));
        tmp += sizeof(mac_address_t);

        memcpy(&ssid_len, tmp, sizeof(unsigned char));
        tmp += sizeof(unsigned char);

        strncpy(nbr->ssid, reinterpret_cast<char *> (tmp), static_cast<size_t>(ssid_len + 1));
        nbr->ssid[ssid_len] = '\0';
        tmp += ssid_len;

        memcpy(&nbr->signal_strength, tmp, sizeof(unsigned char));
        tmp += sizeof(unsigned char);

        memcpy(&bw_len, tmp, sizeof(unsigned char));
        tmp += sizeof(unsigned char);

        memcpy(bandwidth, tmp, bw_len);
        tmp += bw_len;

        if (strncmp(bandwidth, "20", strlen("20")) == 0) {
            nbr->bandwidth = WIFI_CHANNELBANDWIDTH_20MHZ;
        } else if (strncmp(bandwidth, "40", strlen("40")) == 0) {
            nbr->bandwidth = WIFI_CHANNELBANDWIDTH_40MHZ;
        } else if (strncmp(bandwidth, "80", strlen("80")) == 0) {
            nbr->bandwidth = WIFI_CHANNELBANDWIDTH_40MHZ;
        } else if (strncmp(bandwidth, "160", strlen("160")) == 0) {
            nbr->bandwidth = WIFI_CHANNELBANDWIDTH_160MHZ;
        } else if (strncmp(bandwidth, "320", strlen("320")) == 0) {
            nbr->bandwidth = WIFI_CHANNELBANDWIDTH_320MHZ;
        }

        memcpy(&nbr->bss_color, tmp, sizeof(unsigned char));
        tmp += sizeof(unsigned char);

        memcpy(&nbr->channel_util, tmp, sizeof(unsigned char));
        tmp += sizeof(unsigned char);

        memcpy(&nbr->sta_count, tmp, sizeof(unsigned short));
                nbr->sta_count = htons(nbr->sta_count);
        tmp += sizeof(unsigned short);

                dm_easy_mesh_t::macbytes_to_string(nbr->bssid, bssid_str);
                //printf("%s:%d: bssid: %s\tssid: %s\trssi: %d\tbandwidth: %s\tutil: %d\tcount: %d\n", __func__, __LINE__,
                //                      bssid_str, nbr->ssid, nbr->signal_strength, bandwidth, nbr->channel_util, nbr->sta_count);
    }

    memcpy(&scan_res->m_scan_result.aggr_scan_duration, tmp, sizeof(unsigned int));
    tmp += sizeof(unsigned int);

    memcpy(&scan_res->m_scan_result.scan_type, tmp, sizeof(unsigned char));
    tmp += sizeof(unsigned char);

}

int em_channel_t::handle_channel_scan_rprt(unsigned char *buff, unsigned int len)
{
        em_tlv_t    *tlv;
    int tlv_len;
        em_channel_scan_result_t *res;
        dm_easy_mesh_t *dm;
        em_scan_result_id_t id;
        dm_scan_result_t *scan_res;

        dm = get_data_model();

    tlv = reinterpret_cast<em_tlv_t *> (buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    tlv_len = static_cast<int> (len - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)));

    while ((tlv->type != em_tlv_type_eom) && (len > 0)) {
                if (tlv->type == em_tlv_type_channel_scan_rslt) {
                        res = reinterpret_cast<em_channel_scan_result_t *> (tlv->value);

                        strncpy(id.net_id, dm->m_network.m_net_info.id, sizeof(em_long_string_t));
                        memcpy(id.dev_mac, dm->m_device.m_device_info.intf.mac, sizeof(mac_address_t));
            memcpy(id.scanner_mac, res->ruid, sizeof(mac_address_t));
            id.op_class = res->op_class;
            id.channel = res->channel;
                        id.scanner_type = em_scanner_type_radio;

                        if ((scan_res = dm->find_matching_scan_result(&id)) == NULL) {
                                scan_res = dm->create_new_scan_result(&id);
                        }

                        fill_scan_result(scan_res, res);
                }

        if (tlv->type == em_tlv_type_timestamp) {
                ;
                }

        tlv_len -= static_cast<int> (sizeof(em_tlv_t) + htons(tlv->len));
        tlv = reinterpret_cast<em_tlv_t *> (reinterpret_cast<unsigned char *> (tlv) + sizeof(em_tlv_t) + htons(tlv->len));
    }

        dm->set_db_cfg_param(db_cfg_type_scan_result_list_update, "");


        return 0;
}

