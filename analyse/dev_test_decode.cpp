/*
 * HANDLER: dev_test_decode
 *
 * Function copied verbatim (no fix applied yet) from unified-wifi-mesh src/ctrl/em_dev_test_ctrl.cpp
 * (develop @ 1ba9529), em_dev_test_t::decode (row "decode" of the Local Array list). Local array: str_type[32]
 * (snprintf bounded); em_dev_test_info arrays are indexed with index = ssid(0) / channel(1) only. Real
 * cJSON. The "Test_status" branch reads tmp->valuestring without checking that the item is a string.
 * Scaffolding: the caller-owned event subdoc (dtd::evt_buf, runner poisons past the subdoc NUL and the
 * event's guard field); a hash map of dtd::em_t entries (dtd::g_em[]) whose state decides which entries
 * get set_devteststatus(true / false) when "Configure_active_em" is 1.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <string>
#include "dev_test_decode.h"

namespace dtd {

em_t g_em[DTD_MAXEM];
int g_nem = 0;
hash_map_t g_map;

void *hash_map_get_first(hash_map_t *m) { (void)m; return g_nem > 0 ? &g_em[0] : NULL; }
void *hash_map_get_next(hash_map_t *m, void *cur)
{
    (void)m;
    int idx = (int)((em_t *)cur - g_em) + 1;
    return idx < g_nem ? &g_em[idx] : NULL;
}

/* --- copied verbatim from src/ctrl/em_dev_test_ctrl.cpp --- */
void em_dev_test_t:: decode(em_subdoc_info_t *subdoc, hash_map_t *m_em_map, const char *str)
{
   cJSON *parent_obj, *dev_test_obj, *obj, *tmp, *test;
   int index = 0, arr_size = 0, i = 0;
   char str_type[32];
   em_t *em = NULL;

	parent_obj = cJSON_Parse(subdoc->buff);
	if (parent_obj == NULL) {
		printf("%s:%d: Failed to parse: %s\n", __func__, __LINE__, subdoc->buff);
		return;
	}
	if ((test = cJSON_GetObjectItem(parent_obj, "wfa-dataelements:SetDevTest")) == NULL) {
	printf("%s:%d: wfa-dataelements:SetDevTest not present\n", __func__, __LINE__);
	cJSON_Delete(parent_obj);
		return;
	}
	if (test == NULL) {
		printf("%s:%d:	test info not present\n", __func__, __LINE__);
		cJSON_Delete(parent_obj);
		return;
	}

	if ((dev_test_obj = cJSON_GetObjectItem(test, "dev_test")) == NULL) {
	printf("%s:%d: wfa-dataelements:SetDevTest not present\n", __func__, __LINE__);
	cJSON_Delete(parent_obj);
		return;
	}
	if (dev_test_obj == NULL) {
		printf("%s:%d: dev test info not present\n", __func__, __LINE__);
		cJSON_Delete(parent_obj);
		return;
	}

	arr_size = cJSON_GetArraySize(dev_test_obj);
	if (arr_size != em_dev_test_type_max) {
		printf("%s:%d: Invalid configuration:\n", __func__, __LINE__);
		cJSON_Delete(parent_obj);
		return;
	}
	for (i = 0; i < arr_size; i++) {
		if ((obj = cJSON_GetArrayItem(dev_test_obj, i)) == NULL) {
		   printf("%s:%d: Type: Dev Test has no memebers\n", __func__, __LINE__);
		   return;
		}
		if ((tmp = cJSON_GetObjectItem(obj, "Test_type")) != NULL) {
		   snprintf(str_type, sizeof(str_type), "%s", cJSON_GetStringValue(tmp));
		}
		if (strncmp(str_type, "ssid_change", sizeof(str_type)) == 0) {
		   index = static_cast<int>(em_dev_test_type_ssid);
		} else {
		   index = static_cast<int>(em_dev_test_type_channel);
		}
		if ((tmp = cJSON_GetObjectItem(obj, "No_of_iteration")) != NULL) {
			dev_test_info.num_iteration[index] = static_cast<int> (tmp->valuedouble);
		}

		if ((tmp = cJSON_GetObjectItem(obj, "Current_iteration_inprogress")) != NULL) {
			dev_test_info.test_inprogress[index] = static_cast<int> (tmp->valuedouble);
		}
		if ((tmp = cJSON_GetObjectItem(obj, "Num_of_iteration_completed")) != NULL) {
			dev_test_info.num_of_iteration_completed[index] = static_cast<int> (tmp->valuedouble);
		}
		if ((tmp = cJSON_GetObjectItem(obj, "Haul_type:[Fronthault:0,Backhaul:1,IOT:2,Configurator:3,Hotspot:4]")) != NULL) {
			dev_test_info.haul_type = static_cast<em_haul_type_t> (tmp->valuedouble);
		}
		if ((tmp = cJSON_GetObjectItem(obj, "Test_enabled")) != NULL) {
			dev_test_info.enabled[index] = static_cast<int> (tmp->valuedouble);
			if (dev_test_info.enabled[index] == 0) {
				dev_test_info.test_status[index] = em_dev_test_status_idle;
				dev_test_info.test_inprogress[index] = 0;
			}

		}

		if ((tmp = cJSON_GetObjectItem(obj, "Test_status")) != NULL) {
			if(strncmp(tmp->valuestring, "Inprogress", sizeof("Inprogress")) == 0) {
				dev_test_info.test_status[index] = em_dev_test_status_inprogess;
			} else if(strncmp(tmp->valuestring, "Complete", sizeof("Complete")) == 0) {
				dev_test_info.test_status[index] = em_dev_test_status_complete;
			} else if(strncmp(tmp->valuestring, "Failed", sizeof("Failed")) == 0) {
				dev_test_info.test_status[index] = em_dev_test_status_failed;
			}
		}

		if ((tmp = cJSON_GetObjectItem(obj, "Configure_active_em")) != NULL) {
			if (tmp->valuedouble == 1) {
				em = static_cast<em_t *> (hash_map_get_first(m_em_map));
				while(em != NULL) {
					if ((em->get_state() >= em_state_ctrl_configured) && (em->get_state() != em_state_ctrl_misconfigured)) {
							em->set_devteststatus(true);
					} else {
							em->set_devteststatus(false);
					}
					em = static_cast<em_t *> (hash_map_get_next(m_em_map, em));
				}
				dev_test_info.test_status[index] = em_dev_test_status_inprogess;
				dev_test_info.num_of_iteration_completed[index] = 0;
			}
		}

/* Need to be implemented TBD
		if ((tmp = cJSON_GetObjectItem(obj, "Freq_band")) != NULL) {
				dev_test_info.freq_band =  (em_freq_band_t) (tmp->valuedouble);
		}
*/
	}
}

static em_dev_test_t g_dt;

const char *g_default = "ni=0,0 en=0,0 ip=0,0 done=0,0 st=0,0 haul=0 em=";

void summarise(void)
{
    em_dev_test_info *d = &g_out;
    size_t l = (size_t)snprintf(g_sum, sizeof(g_sum), "ni=%d,%d en=%d,%d ip=%d,%d done=%d,%d st=%d,%d haul=%d em=",
        d->num_iteration[0], d->num_iteration[1], d->enabled[0], d->enabled[1], d->test_inprogress[0], d->test_inprogress[1],
        d->num_of_iteration_completed[0], d->num_of_iteration_completed[1], (int)d->test_status[0], (int)d->test_status[1], (int)d->haul_type);
    for (int i = 0; i < g_nem && l + 2 < sizeof(g_sum); i++) g_sum[l++] = g_em[i].devtest < 0 ? '-' : (char)('0' + g_em[i].devtest);
    g_sum[l] = '\0';
}

void invoke(void)
{
    memset(&g_dt, 0, sizeof(g_dt));
    g_dt.dev_test_info.haul_type = em_haul_type_fronthaul;
    g_dt.decode(&((em_bus_event_t *)evt_buf)->u.subdoc, &g_map, "SetDevTest");
    memcpy(&g_out, &g_dt.dev_test_info, sizeof(g_out));
    summarise();
}

} /* namespace dtd */
