/* cmd_channelselect scaffolding (namespace ccs): usings, macros, typedefs and stand-in classes for the handler. Own header, kept out of common.h. */
#ifndef CMD_CHANNELSELECT_H
#define CMD_CHANNELSELECT_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <limits.h>
#include <ctype.h>
#include <stdint.h>
#include <vector>
#include "common.h"

namespace ccs {

/* ---- scaffolding classes, usings, macros moved from cmd_channelselect.cpp ---- */
#ifndef MAX_INSTANCE_LEN
#define MAX_INSTANCE_LEN 32
#endif
#define BUS_MAX_NAME_LENGTH 128
#define DATAELEMS_NETWORK "Device.WiFi.DataElements.Network."
#define EM_IO_BUFF_SZ 4096
#undef GLOBAL_NET_ID
#define GLOBAL_NET_ID "OneWifiMesh"
#undef EM_CH_PREF_MAX
#define EM_CH_PREF_MAX 0x0F
#ifndef EM_MAX_CHANNELS_IN_LIST
#define EM_MAX_CHANNELS_IN_LIST 64
#endif
typedef char mac_addr_str_t[18];

/* bus types: see common.h (namespace ccs) */

typedef struct { char name[64]; char buff[0]; } __attribute__((__packed__)) em_subdoc_info_t;
typedef enum { em_freq_band_24, em_freq_band_5, em_freq_band_60, em_freq_band_6, em_freq_band_unknown } em_freq_band_t;
typedef enum { em_bus_event_type_channel_select = 1, em_bus_event_type_scan_channel } em_bus_event_type_t;

/* --- scaffolding: dm / controller stand-ins --- */
extern int g_radio_band;
extern int io_calls;
extern char io_json[EM_IO_BUFF_SZ + 64];
extern unsigned int io_len;
extern char last_status[16];
typedef struct { struct { unsigned char mac[6]; } intf; } em_device_info_t;
typedef struct { struct { unsigned char ruid[6]; } id; em_freq_band_t band; } em_radio_info_t;
class dm_device_t { public: em_device_info_t info; em_device_info_t *get_device_info() { return &info; } };
class dm_radio_t  { public: em_radio_info_t info; em_radio_info_t *get_radio_info() { return &info; } };
class dm_easy_mesh_t {
public:
    dm_device_t device;
    dm_radio_t radio;
    dm_device_t *get_device() { return &device; }
    static void macbytes_to_string(unsigned char *mac, char *string)
    { snprintf(string, 18, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]); }
    static em_freq_band_t get_freq_band_by_op_class(int op_class)
    {
        switch (op_class) {
        case 81: return em_freq_band_24;
        case 115: case 118: case 121: return em_freq_band_5;
        case 131: return em_freq_band_6;
        }
        return em_freq_band_unknown;
    }
    static std::vector<int> get_channel_list_by_op_class(int op_class)
    {
        std::vector<int> c;
        switch (op_class) {
        case 81:  for (int i = 1; i <= 13; i++) c.push_back(i); break;
        case 115: c = {36, 40, 44, 48}; break;
        case 118: c = {52, 56, 60, 64}; break;
        case 121: c = {100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140}; break;
        case 131: for (int i = 1; i <= 233; i += 4) c.push_back(i); break;
        }
        return c;
    }
};
class dm_easy_mesh_ctrl_t {
public:
    dm_easy_mesh_t dm;
    const char* get_table_instance(const char *src, char *instance, size_t max_len, bool *is_num);
    dm_easy_mesh_t *get_dm_easy_mesh(char *instance, bool is_num)
    {   /* one device: id 1 / mac 02:00:00:00:00:01 */
        char mac_str[18];
        if (is_num) return (atoi(instance) == 1) ? &dm : NULL;
        dm_easy_mesh_t::macbytes_to_string(dm.device.info.intf.mac, mac_str);
        return strcmp(instance, mac_str) == 0 ? &dm : NULL;
    }
    dm_radio_t *get_dm_radio(dm_easy_mesh_t *d, char *instance, bool is_num)
    {   /* one radio: index 1 */
        return (is_num && atoi(instance) == 1) ? &d->radio : NULL;
    }
};
class em_ctrl_t {
public:
    dm_easy_mesh_ctrl_t m_data_model;
    static em_ctrl_t *get_em_ctrl_instance();
    dm_easy_mesh_ctrl_t *get_dm_ctrl() { return &m_data_model; }
    void io_process(em_bus_event_type_t type, char *data, unsigned int len)
    {
        (void)type; io_calls++; io_len = len;
        memset(io_json, 0, sizeof(io_json));
        memcpy(io_json, data, len < sizeof(io_json) ? len : sizeof(io_json) - 1);
    }
    static const int MAX_CHANSEL_CLASSES = 32;
    static const int MAX_CHANSEL_CHANNELS = 64;
    static const int MAX_CHANSEL_LIST_LEN = EM_MAX_CHANNELS_IN_LIST * 4 - 1;
    static bus_error_t cmd_channelselect(const char *method_name, const bus_data_prop_t *input_params, bus_data_prop_t **output_params, void *async_handle);
};

class tr_181_t {
public:
    static bool tr181_copy_prop_string(const bus_data_prop_t *prop, char *dst, size_t dst_len);
    static bool tr181_get_prop_int(const bus_data_prop_t *prop, int *value);
    static bus_data_prop_t *tr181_set_status_output_prop(const char *status)
    {   /* stand-in for tr181_alloc_string_prop("Status", status) */
        bus_data_prop_t *p = (bus_data_prop_t *)calloc(1, sizeof(*p));
        snprintf(last_status, sizeof(last_status), "%s", status);
        p->value.data_type = bus_data_type_string;
        p->value.raw_data.bytes = strdup(status);
        return p;
    }
};

/* copied verbatim from src/ctrl/tr_181/wfa_data_model/tr_181_helper.cpp */
bool tr_181_t::tr181_copy_prop_string(const bus_data_prop_t *prop, char *dst, size_t dst_len)
{
    if (!prop || !dst || (dst_len == 0U)) {
        return false;
    }
    if ((prop->value.data_type != bus_data_type_string) || !prop->value.raw_data.bytes) {
        return false;
    }

    const char *src = static_cast<const char *>(prop->value.raw_data.bytes);
    size_t len = prop->value.raw_data_len;
    if (len == 0U) {
        len = strnlen(src, dst_len - 1U);
    } else if (src[len - 1U] == '\0') {
        len -= 1U;
    }
    if (len >= dst_len) {
        len = dst_len - 1U;
    }

    memcpy(dst, src, len);
    dst[len] = '\0';
    return true;
}

bool tr_181_t::tr181_get_prop_int(const bus_data_prop_t *prop, int *value)
{
    if (!prop || !value) {
        return false;
    }

    if (prop->value.data_type == bus_data_type_int8) {
        *value = static_cast<int>(prop->value.raw_data.i8);
    } else if (prop->value.data_type == bus_data_type_uint8) {
        *value = static_cast<int>(prop->value.raw_data.u8);
    } else if (prop->value.data_type == bus_data_type_int16) {
        *value = static_cast<int>(prop->value.raw_data.i16);
    } else if (prop->value.data_type == bus_data_type_uint16) {
        *value = static_cast<int>(prop->value.raw_data.u16);
    } else if (prop->value.data_type == bus_data_type_int32) {
        *value = prop->value.raw_data.i32;
    } else if (prop->value.data_type == bus_data_type_uint32) {
        *value = static_cast<int>(prop->value.raw_data.u32);
    } else {
        return false;
    }

    return true;
}

/* copied verbatim from src/ctrl/dm_easy_mesh_ctrl.cpp */
const char* dm_easy_mesh_ctrl_t::get_table_instance(const char *src, char *instance, size_t max_len, bool *is_num)
{
	char *dst = instance;
	size_t len = 0;

/* start updated fix 3 */
    if (src == NULL) {
        return NULL;
    }
/* end updated fix 3 */
    src = strstr(src, ".");
/* start fix 3 */
    if (src == NULL) {
        return NULL;
    }
/* end fix 3 */
    ++src;

	if (*src == '[') {
		*is_num = false;
		++src;
		while (*src && *src != ']' && ++len < max_len) {
			*dst++ = *src++;
		}
		*dst++ = 0;
/* start updated fix 3 */
        if (*src != ']' || src[1] != '.') {
            return NULL;
        }
        src += 2;
/* end updated fix 3 */
	} else {
		*is_num = true;
		while (*src && *src != '.' && ++len < max_len) {
			*dst++ = *src++;
		}
		*dst++ = 0;
/* start fix 3 */
        if (*src) {
            src++;
        }
/* end fix 3 */
	}

	return src;
}

extern em_ctrl_t *ctrl_instance_ptr;
}
#endif
