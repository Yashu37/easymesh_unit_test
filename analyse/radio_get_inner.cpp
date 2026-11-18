/*
 * HANDLER: radio_get_inner
 *
 * Function copied verbatim (no fix applied yet) from unified-wifi-mesh src/ctrl/dm_easy_mesh_ctrl.cpp
 * (develop @ 1ba9529), dm_easy_mesh_ctrl_t::radio_get_inner, with get_table_instance() (same file).
 * Local arrays: instance[32], id_str[16]; array access dm->m_radio[radio_instance - 1] (EM_MAX_BANDS = 3);
 * loop over dm->get_num_op_class() / get_op_class(i) (m_op_class[64], get_num_op_class() does not clamp);
 * raw_data_set(ri->chip_vendor) does strlen() on an em_long_string_t[128].
 * Scaffolding: one device 1 (or MAC alias 02:00:00:00:00:01) with radios 1..3 (RUID 02:00:00:00:00:r);
 * raw_data_set records the value it is given.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <string>
#include <type_traits>
#include "radio_get_inner.h"

namespace rgi {

char g_val[RGI_VAL_SZ];
int g_nset = 0;
dm_easy_mesh_t *g_dm = NULL;

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

bus_error_t dm_easy_mesh_ctrl_t::radio_get_inner(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    (void) user_data;
    const char *name = event_name;
    const char *param;
    char instance[MAX_INSTANCE_LEN] = { 0 };
    bool is_num;
    int radio_instance = 0;
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

    name = dm_ctrl->get_table_instance(name, instance, MAX_INSTANCE_LEN, &is_num);
    radio_instance = is_num ? atoi(instance) : 0;
    dm_radio_t *radio = &dm->m_radio[radio_instance - 1];
    if (radio == NULL) {
        em_printfout("radio is NULL\n");
        return bus_error_invalid_input;
    }
    em_radio_info_t *ri = radio->get_radio_info();

    if (strcmp(param, "ID") == 0) {
        /* Radio ID is the base64 encoded RUID (MAC) per TR-181 DataElements. */
        char id_str[16] = { 0 };
        std::string id_b64 = em_crypto_t::base64_encode(ri->id.ruid, sizeof(ri->id.ruid));
        snprintf(id_str, sizeof(id_str), "%s", id_b64.c_str());
        rc = dm_ctrl->raw_data_set(p_data, id_str);
    } else if (strcmp(param, "Enabled") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, ri->enabled);
    } else if (strcmp(param, "Noise") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, static_cast<unsigned int> (ri->noise));
    } else if (strcmp(param, "Utilization") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, static_cast<unsigned int> (ri->utilization));
    } else if (strcmp(param, "Transmit") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, static_cast<unsigned int> (ri->transmit));
    } else if (strcmp(param, "ReceiveSelf") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, static_cast<unsigned int> (ri->receive_self));
    } else if (strcmp(param, "ReceiveOther") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, static_cast<unsigned int> (ri->receive_other));
    } else if (strcmp(param, "ChipsetVendor") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, ri->chip_vendor);
    } else if (strcmp(param, "CurrentOperatingClassProfileNumberOfEntries") == 0) {
        unsigned int curop_count = 0;
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
            curop_count++;
        }
        rc = dm_ctrl->raw_data_set(p_data, curop_count);
    } else if (strcmp(param, "BSSNumberOfEntries") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, ri->number_of_bss);
    } else if (strcmp(param, "X_AIRTIES_Temperature") == 0) {
        rc = dm_ctrl->raw_data_set(p_data, ri->radio_temp);
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
    return (int)g_ctrl.m_data_model.radio_get_inner((char *)event, no_pdata ? NULL : &raw, &ud);
}

} /* namespace rgi */
