/*
 * HANDLER: curops_get_inner
 *
 * Function copied (fixes 1-3 applied, start fix n / end fix n markers) from unified-wifi-mesh src/ctrl/dm_easy_mesh_ctrl.cpp
 * (develop @ 1ba9529), dm_easy_mesh_ctrl_t::curops_get_inner, with get_table_instance() and
 * get_dm_curop() (same file). Local arrays: instance[32], time[24], zone[8], buffer[64], and the
 * array access dm->m_radio[radio_instance - 1] (EM_MAX_BANDS = 3).
 * Scaffolding: one device 1 (or MAC alias 02:00:00:00:00:01) whose op class list holds the entries of
 * cog::oc_spec_t; raw_data_set records the value it is given.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <string>
#include <type_traits>
#include "curops_get_inner.h"

namespace cog {

char g_val[64];
int g_nset = 0;
dm_easy_mesh_t *g_dm = NULL;

class dm_easy_mesh_ctrl_t {
public:
    const char* get_table_instance(const char *src, char *instance, size_t max_len, bool *is_num);
    dm_op_class_t *get_dm_curop(dm_easy_mesh_t *dm, dm_radio_t *radio, int instance);
    dm_easy_mesh_t *get_dm_easy_mesh(char *instance, bool is_num)
    {   if (!g_dm) return NULL;
        if (is_num) return atoi(instance) == 1 ? g_dm : NULL;
        return strcmp(instance, "02:00:00:00:00:01") == 0 ? g_dm : NULL; }
    bus_error_t raw_data_set(raw_data_t *p, const char *v) { (void)p; g_nset++; snprintf(g_val, sizeof(g_val), "%s", v); return bus_error_success; }
    template <typename T>
    typename std::enable_if<std::is_arithmetic<T>::value, bus_error_t>::type
    raw_data_set(raw_data_t *p, T v) { (void)p; g_nset++; snprintf(g_val, sizeof(g_val), "%lld", (long long)v); return bus_error_success; }
    bus_error_t curops_get_inner(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data);
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

/* start fix 2 */
    if (src == NULL) {
        return NULL;
    }
    src = strstr(src, ".");
    if (src == NULL) {
        return NULL;
    }
/* end fix 2 */
    ++src;

	if (*src == '[') {
		*is_num = false;
		++src;
		while (*src && *src != ']' && ++len < max_len) {
			*dst++ = *src++;
		}
		*dst++ = 0;
/* start fix 2 */
        if (*src != ']' || src[1] != '.') {
            return NULL;
        }
        src += 2;
/* end fix 2 */
	} else {
		*is_num = true;
		while (*src && *src != '.' && ++len < max_len) {
			*dst++ = *src++;
		}
		*dst++ = 0;
/* start fix 2 */
        if (*src) {
            src++;
        }
/* end fix 2 */
	}

	return src;
}

dm_op_class_t* dm_easy_mesh_ctrl_t::get_dm_curop(dm_easy_mesh_t *dm, dm_radio_t *radio, int instance)
{
    int ocnt = 0;
    em_radio_info_t *ri = radio->get_radio_info();

    for (unsigned int i = 0; i < dm->get_num_op_class(); i++) {
        dm_op_class_t *op_class = dm->get_op_class(i);
        if (op_class == NULL) {
            continue;
        }
        em_op_class_info_t *oci = op_class->get_op_class_info();
        if (oci->id.type != em_op_class_type_current) {
            continue;
        }
        if (memcmp(ri->id.ruid, oci->id.ruid, sizeof(oci->id.ruid)) != 0) {
            continue;
        }
        ++ocnt;
        if (ocnt == instance) {
            return op_class;
        }
    }

    return NULL;
}

bus_error_t dm_easy_mesh_ctrl_t::curops_get_inner(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    (void) user_data;
    const char *name = event_name;
    const char *param;
    char instance[MAX_INSTANCE_LEN] = { 0 };
    bool is_num;
    int radio_instance = 0, curop_class_instance = 0;
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
/* start fix 1 */
    if (strlen(name) < sizeof(DATAELEMS_NETWORK)) {
        return bus_error_invalid_input;
    }
/* end fix 1 */
    name += sizeof(DATAELEMS_NETWORK);
    name = dm_ctrl->get_table_instance(name, instance, MAX_INSTANCE_LEN, &is_num);
/* start fix 2 */
    if (name == NULL) {
        return bus_error_invalid_input;
    }
/* end fix 2 */
    dm_easy_mesh_t *dm = dm_ctrl->get_dm_easy_mesh(instance, is_num);
    if (dm == NULL) {
        printf("device not found\n");
        return bus_error_invalid_namespace;
    }

    name = dm_ctrl->get_table_instance(name, instance, MAX_INSTANCE_LEN, &is_num);
/* start fix 2 */
    if (name == NULL) {
        return bus_error_invalid_input;
    }
/* end fix 2 */
    radio_instance = is_num ? atoi(instance) : 0;
/* start fix 3 */
    if (radio_instance < 1 || radio_instance > EM_MAX_BANDS) {
        em_printfout("radio instance %d out of range", radio_instance);
        return bus_error_invalid_input;
    }
/* end fix 3 */
    dm_radio_t *radio = &dm->m_radio[radio_instance - 1];
    if (radio == NULL) {
        em_printfout("radio is NULL\n");
        return bus_error_invalid_input;
    }

    name = dm_ctrl->get_table_instance(name, instance, MAX_INSTANCE_LEN, &is_num);
/* start fix 2 */
    if (name == NULL) {
        return bus_error_invalid_input;
    }
/* end fix 2 */
    curop_class_instance = is_num ? atoi(instance) : 0;
    dm_op_class_t *op_class = dm_ctrl->get_dm_curop(dm, radio, curop_class_instance);
    if (op_class == NULL) {
        em_printfout("op_class is NULL\n");
        return bus_error_invalid_input;
    }
    em_op_class_info_t *oci = op_class->get_op_class_info();

    if (strcmp(param, "TimeStamp") == 0) {
        char time[MAX_TIME_STRLEN];
        char zone[MAX_ZONE_STRLEN];
        char buffer[MAX_TIMESTAMP_STRLEN];
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        strftime(time, sizeof(time), "%FT%T", localtime(&ts.tv_sec));
        strftime(zone, sizeof(zone), "%z", localtime(&ts.tv_sec));
        snprintf(buffer, sizeof(buffer) - 1, "%s.%06ld%s", time, ts.tv_nsec / 1000, zone);
        rc = dm_ctrl->raw_data_set(p_data, buffer);
    } else if (strcmp(param, "Class") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, oci->op_class);
    } else if (strcmp(param, "Channel") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, oci->channel);
    } else if (strcmp(param, "TxPower") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, oci->tx_power);
    } else {
        em_printfout("Invalid param: %s\n", param);
        rc = bus_error_invalid_input;
    }

    return rc;
}

int invoke(const char *event, bool no_pdata)
{
    raw_data_t raw;
    memset(&raw, 0, sizeof(raw));
    bus_user_data_t ud;
    return (int)g_ctrl.m_data_model.curops_get_inner((char *)event, no_pdata ? NULL : &raw, &ud);
}

} /* namespace cog */
