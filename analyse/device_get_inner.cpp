/*
 * HANDLER: device_get_inner
 *
 * Function copied VERBATIM from unified-wifi-mesh src/ctrl/dm_easy_mesh_ctrl.cpp
 * (develop @ 1ba9529), dm_easy_mesh_ctrl_t::device_get_inner, with get_table_instance() and
 * fill_comma_sep() (same file). Local arrays: instance[32], val_str[MAX_EM_BUFF_SZ=1024] and the
 * reads di->backhaul_down_mac[i] (16 entries) / pi->m_policy.sta_mac[index] (16 entries) whose
 * bound is a count from the data model.
 * Scaffolding: one device (number 1 / alias 02:00:00:00:00:01) described by cog-style knobs of
 * dgi::test_case_t; raw_data_set records the value it is given.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cstring>
#include <stdint.h>
#include <string>
#include <vector>
#include <type_traits>
#include "device_get_inner.h"

namespace dgi {

char g_val[2048];
int g_nset = 0;
dm_easy_mesh_t *g_dm = NULL;
dm_easy_mesh_t *g_bh = NULL;

void *hash_map_get_first(policy_map_t *m) { return m->n ? m->p[0] : NULL; }
void *hash_map_get_next(policy_map_t *m, void *cur)
{ for (int i = 0; i < m->n; i++) if (m->p[i] == cur) return i + 1 < m->n ? m->p[i + 1] : NULL; return NULL; }

namespace util {
inline std::string mac_to_string(const uint8_t mac[6], const std::string& delim = ":")
{ char s[32]; snprintf(s, sizeof(s), "%02x%s%02x%s%02x%s%02x%s%02x%s%02x", mac[0], delim.c_str(), mac[1], delim.c_str(), mac[2], delim.c_str(), mac[3], delim.c_str(), mac[4], delim.c_str(), mac[5]); return s; }
}

class dm_easy_mesh_ctrl_t {
public:
    const char* get_table_instance(const char *src, char *instance, size_t max_len, bool *is_num);
    void fill_comma_sep(em_short_string_t str[], size_t max, char *buf);
    dm_easy_mesh_t *get_dm_easy_mesh(char *instance, bool is_num)
    {   if (!g_dm) return NULL;
        if (is_num) return atoi(instance) == 1 ? g_dm : NULL;
        return strcmp(instance, "02:00:00:00:00:01") == 0 ? g_dm : NULL; }
    dm_device_t *get_dm_dev(unsigned char *dev_mac, unsigned char *bmac)
    {   (void)dev_mac; if (g_bh && !memcmp(g_bh->dev.info.intf.mac, bmac, 6)) return &g_bh->dev; return NULL; }
    bus_error_t raw_data_set(raw_data_t *p, const char *v) { (void)p; g_nset++; snprintf(g_val, sizeof(g_val), "%s", v); return bus_error_success; }
    bus_error_t raw_data_set(raw_data_t *p, const unsigned char *mac)
    { (void)p; g_nset++; snprintf(g_val, sizeof(g_val), "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]); return bus_error_success; }
    template <typename T>
    typename std::enable_if<std::is_arithmetic<T>::value, bus_error_t>::type
    raw_data_set(raw_data_t *p, T v) { (void)p; g_nset++; snprintf(g_val, sizeof(g_val), "%lld", (long long)v); return bus_error_success; }
    bus_error_t device_get_inner(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data);
};
class em_ctrl_t {
public:
    dm_easy_mesh_ctrl_t m_data_model;
    static em_ctrl_t *get_em_ctrl_instance();
    dm_easy_mesh_ctrl_t *get_dm_ctrl() { return &m_data_model; }
};
static em_ctrl_t g_ctrl;
em_ctrl_t *em_ctrl_t::get_em_ctrl_instance() { return &g_ctrl; }

/* --- copied verbatim from src/ctrl/dm_easy_mesh_ctrl.cpp --- */
const char* dm_easy_mesh_ctrl_t::get_table_instance(const char *src, char *instance, size_t max_len, bool *is_num)
{
	char *dst = instance;
	size_t len = 0;

    src = strstr(src, ".");
    ++src;

	if (*src == '[') {
		*is_num = false;
		++src;
		while (*src && *src != ']' && ++len < max_len) {
			*dst++ = *src++;
		}
		*dst++ = 0;
		src += 2;
	} else {
		*is_num = true;
		while (*src && *src != '.' && ++len < max_len) {
			*dst++ = *src++;
		}
		*dst++ = 0;
		src++;
	}

	return src;
}

void dm_easy_mesh_ctrl_t::fill_comma_sep(em_short_string_t str[], size_t max, char *buf)
{
    unsigned int cnt = 0;
    const char *delim = NULL;

    if (max > 15) {
        max = 15;
    }

    while (cnt < max) {
        if (strlen(str[cnt]) > 0) {
            if (delim) {
                strcat(buf, delim);
            } else {
                delim = ",";
            }
            strcat(buf, str[cnt]);
        } else {
            break;
        }
        cnt++;
    }
}

bus_error_t dm_easy_mesh_ctrl_t::device_get_inner(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    (void) user_data;
    const char *name = event_name;
    const char *param;
    char val_str[MAX_EM_BUFF_SZ] = { 0 };
    char instance[MAX_INSTANCE_LEN] = { 0 };
    bool is_num;
    bus_error_t rc;

    if (!name || !p_data) {
        return bus_error_invalid_input;
    }

    param = strrchr(name, '.');
    if (param == NULL) {
        return bus_error_invalid_input;
    }
    ++param;

    dm_easy_mesh_ctrl_t *dm_ctrl = em_ctrl_t::get_em_ctrl_instance()->get_dm_ctrl();

    /* Extract device instance (numeric or alias) and find the dm object for
     * that device instance */
    name += sizeof(DATAELEMS_NETWORK);
    name = dm_ctrl->get_table_instance(name, instance, MAX_INSTANCE_LEN, &is_num);
    dm_easy_mesh_t *dm = dm_ctrl->get_dm_easy_mesh(instance, is_num);
    if (dm == NULL) {
        printf("device not found\n");
        return bus_error_invalid_namespace;
    }

    dm_device_t *dev = dm->get_device();
    if (dev == NULL) {
        em_printfout("NULL dev");
        return bus_error_invalid_input;
    }
    em_device_info_t *di = dev->get_device_info();
    if (memcmp(di->intf.mac, ZERO_MAC_ADDR, sizeof(di->intf.mac)) == 0) {
        em_printfout("NULL dev_info");
        return bus_error_invalid_input;
    }
    em_ieee_1905_security_cap_t *sec_cap = dm->get_ieee_1905_security_cap();
    if (sec_cap == NULL) {
        em_printfout("NULL sec_cap");
        return bus_error_invalid_input;
    }

    if (strcmp(param, "ID") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, di->intf.mac);
    } else if (strcmp(param, "MultiAPCapabilities") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, di->multi_ap_cap);
    } else if (strcmp(param, "CollectionInterval") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, di->coll_interval);
    } else if (strcmp(param, "ReportUnsuccessfulAssociations") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, di->report_unsuccess_assocs);
    } else if (strcmp(param, "MaxReportingRate") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, di->max_reporting_rate);
    } else if (strcmp(param, "APMetricsReportingInterval") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, di->ap_metrics_reporting_interval);
    } else if (strcmp(param, "Manufacturer") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, di->manufacturer);
    } else if (strcmp(param, "SerialNumber") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, di->serial_number);
    } else if (strcmp(param, "ManufacturerModel") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, di->manufacturer_model);
    } else if (strcmp(param, "SoftwareVersion") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, di->software_ver);
    } else if (strcmp(param, "ExecutionEnv") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, di->exec_env);
    } else if (strcmp(param, "LocalSteeringDisallowedSTAList") == 0) {
        //rc = dm_ctrl->raw_data_set(p_data, );
    } else if (strcmp(param, "BTMSteeringDisallowedSTAList") == 0) {
        for (dm_policy_t *pi = dm->m_policy_map ? static_cast<dm_policy_t *>(hash_map_get_first(dm->m_policy_map)) : NULL;
             pi != NULL;
             pi = static_cast<dm_policy_t *>(hash_map_get_next(dm->m_policy_map, pi))) {
            if(pi->m_policy.id.type == em_policy_id_type_steering_btm) {
                const size_t n = static_cast<size_t>(pi->m_policy.num_sta);
                std::vector<em_short_string_t> BTMSteeringDisallowed(n);
                for (size_t index = 0; index < n; index++) {
			const std::string mac = util::mac_to_string(pi->m_policy.sta_mac[index]);
			std::snprintf(BTMSteeringDisallowed[index], sizeof(em_short_string_t), "%s", mac.c_str());
                }
                dm_ctrl->fill_comma_sep(BTMSteeringDisallowed.data(), static_cast<size_t>(n), val_str);
                rc = dm_ctrl->raw_data_set(p_data, val_str);
                break;
            }
        }
    } else if (strcmp(param, "MaxVIDs") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, di->max_vids);
    } else if (strcmp(param, "TrafficSeparationPolicy") == 0) {
        //rc = dm_ctrl->raw_data_set(p_data, );
    } else if (strcmp(param, "SSIDtoVIDMapping") == 0) {
        //rc = dm_ctrl->raw_data_set(p_data, );
    } else if (strcmp(param, "DSCPMap") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, di->dscp_map);
    } else if (strcmp(param, "MaxPrioritizationRules") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, di->max_pri_rules);
    } else if (strcmp(param, "CountryCode") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, di->country_code);
    } else if (strcmp(param, "PrioritizationSupport") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, di->prioritization_sup);
    } else if (strcmp(param, "ReportIndependentScans") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, di->report_ind_scans);
    } else if (strcmp(param, "TrafficSeparationAllowed") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, di->traffic_sep_allowed);
    } else if (strcmp(param, "ServicePrioritizationAllowed") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, di->svc_prio_allowed);
    } else if (strcmp(param, "DFSEnable") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, di->dfs_enable);
    } else if (strcmp(param, "MaxUnsuccessfulAssociationReportingRate") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, di->max_unsuccessful_assoc_report_rate);
    } else if (strcmp(param, "STASteeringState") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, di->sta_steer_state);
    } else if (strcmp(param, "CoordinatedCACAllowed") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, di->coord_cac_allowed);
    } else if (strcmp(param, "ControllerOperationMode") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, di->ctrl_operation_mode);
    } else if (strcmp(param, "BackhaulMACAddress") == 0) {
        if (memcmp(di->backhaul_mac.mac, ZERO_MAC_ADDR, sizeof(ZERO_MAC_ADDR)) == 0) {
            rc = dm_ctrl->raw_data_set(p_data, "");
        } else {
            rc = dm_ctrl->raw_data_set(p_data, di->backhaul_mac.mac);
        }
    } else if (strcmp(param, "BackhaulDownMACAddress") == 0) {
        const size_t n = static_cast<size_t>(di->num_backhaul_down_mac);
        std::vector<em_short_string_t> tmp(n);

        for (size_t i = 0; i < n; i++) {
            std::strncpy(tmp[i], di->backhaul_down_mac[i], sizeof(tmp[i]) - 1);
            tmp[i][sizeof(tmp[i]) - 1] = '\0';
        }
        dm_ctrl->fill_comma_sep(tmp.data(), n, val_str);
        rc = dm_ctrl->raw_data_set(p_data, val_str);
    } else if (strcmp(param, "BackhaulPHYRate") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, di->backhaul_phyrate);
    } else if (strcmp(param, "TrafficSeparationCapability") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, di->traffic_sep_cap);
    } else if (strcmp(param, "EasyConnectCapability") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, di->easy_conn_cap);
    } else if (strcmp(param, "TestCapabilities") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, di->test_cap);
    } else if (strcmp(param, "bSTAMLDMaxLinks") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, di->bstamld_maxlinks);
    } else if (strcmp(param, "MaxNumMLDs") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, di->max_nummlds);
    } else if (strcmp(param, "BackhaulALID") == 0) {
        if (memcmp(di->backhaul_mac.mac, ZERO_MAC_ADDR, sizeof(ZERO_MAC_ADDR)) == 0) {
            rc = dm_ctrl->raw_data_set(p_data, "");
        } else {
            dm_device_t *bhdev = dm_ctrl->get_dm_dev(di->id.dev_mac, di->backhaul_mac.mac);
            if (bhdev == NULL) {
                rc = dm_ctrl->raw_data_set(p_data, "");
            } else {
                em_device_info_t *bhdi = bhdev->get_device_info();
                rc = dm_ctrl->raw_data_set(p_data, bhdi->id.dev_mac);
            }
        }
    } else if (strcmp(param, "TIDLinkMapping") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, di->tidlink_map);
    } else if (strcmp(param, "AssociatedSTAReportingInterval") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, di->assoc_sta_reporting_int);
    } else if (strcmp(param, "BackhaulMediaType") == 0) {
        if (memcmp(di->backhaul_mac.mac, ZERO_MAC_ADDR, sizeof(ZERO_MAC_ADDR)) == 0) {
            rc = dm_ctrl->raw_data_set(p_data, di->backhaul_media_type);
        } else {
            rc = dm_ctrl->raw_data_set(p_data, WIFI_80211_VARIANT_AC);
        }
    } else if (strcmp(param, "RadioNumberOfEntries") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, dm->get_num_radios());
    } else if (strcmp(param, "CACStatusNumberOfEntries") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, 0U);
    } else if (strcmp(param, "BackhaulDownNumberOfEntries") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, di->num_backhaul_down_mac);
    } else if (strcmp(param, "Uptime") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, di->uptime);
    } else if (strcmp(param, "Total") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, di->total_mem);
    } else if (strcmp(param, "Free") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, di->free_mem);
    } else if (strcmp(param, "Cached") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, di->cached_mem);
    } else if (strcmp(param, "CPUUsage") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, di->cpu_load);
    } else if (strcmp(param, "CPUTemperature") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, di->cpu_temp);
    } else if (strcmp(param, "OnboardingProtocol") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, sec_cap ? sec_cap->onboarding_proto : 0);
    } else if (strcmp(param, "IntegrityAlgorithm") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, sec_cap ? sec_cap->integrity_algo : 0);
    } else if (strcmp(param, "EncryptionAlgorithm") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, sec_cap ? sec_cap->encryption_algo : 0);
    } else if (strcmp(param, "X_AIRTIES_BootID") == 0) {
        em_ext_device_info_t *edi = &di->extended_info;
        rc = dm_ctrl->raw_data_set(p_data, edi->received ? edi->boot_id : 0);
    } else if (strcmp(param, "X_AIRTIES_ClientID") == 0) {
        em_ext_device_info_t *edi = &di->extended_info;
        if (edi->received && edi->client_id_len) {
            rc = dm_ctrl->raw_data_set(p_data, edi->client_id);
        } else {
            rc = dm_ctrl->raw_data_set(p_data, "");
        }
    } else if (strcmp(param, "X_AIRTIES_ClientSecret") == 0) {
        em_ext_device_info_t *edi = &di->extended_info;
        if (edi->received && edi->client_secret_len) {
            rc = dm_ctrl->raw_data_set(p_data, edi->client_secret);
        } else {
            rc = dm_ctrl->raw_data_set(p_data, "");
        }
    } else {
        em_printfout("Invalid param: %s", param);
        rc = bus_error_invalid_input;
    }

    return rc;
}

int invoke(const char *event, bool no_pdata)
{
    raw_data_t raw;
    memset(&raw, 0, sizeof(raw));
    bus_user_data_t ud;
    return (int)g_ctrl.m_data_model.device_get_inner((char *)event, no_pdata ? NULL : &raw, &ud);
}

} /* namespace dgi */
