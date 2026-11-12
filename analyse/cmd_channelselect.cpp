/*
 * HANDLER: cmd_channelselect
 *
 * Function copied VERBATIM from unified-wifi-mesh src/ctrl/dm_easy_mesh_ctrl.cpp
 * (develop @ 1ba9529), em_ctrl_t::cmd_channelselect. No fixes. Local arrays:
 * instance[MAX_INSTANCE_LEN], prop_name[BUS_MAX_NAME_LENGTH], tokens[6],
 * list_str[MAX_CHANSEL_LIST_LEN + 1], buff[sizeof(em_subdoc_info_t)+EM_IO_BUFF_SZ],
 * plus classes[MAX_CHANSEL_CLASSES] each with channels[MAX_CHANSEL_CHANNELS].
 * It also does pointer arithmetic on the caller's method_name
 * (name += sizeof(DATAELEMS_NETWORK)) and walks it with get_table_instance().
 *
 * Poison lives ONLY in the runner (cmd_channelselect_test.cpp): method_name tail,
 * every property's string value tail. Scaffolding (namespace ccs) stubs only what
 * the function calls: the bus property types, em_ctrl_t / dm_easy_mesh_ctrl_t
 * lookups, the dm device/radio info, tr_181_t helpers and io_process. The real
 * get_table_instance and tr181_copy_prop_string / tr181_get_prop_int are copied
 * verbatim. dm_easy_mesh_t's operating-class table is a small stand-in
 * (81=2.4G, 115/118/121=5G, 131=6G) - the table contents are not under test.
 */

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

/* CCS_FIX 1 = fixed handler (FIX 1-3 below), 0 = verbatim original (crashes) */
#ifndef CCS_FIX
#define CCS_FIX 1
#endif

namespace ccs {

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
typedef struct { struct { unsigned char mac[6]; } intf; } em_device_info_t;
typedef struct { struct { unsigned char ruid[6]; } id; em_freq_band_t band; } em_radio_info_t;
int g_radio_band = em_freq_band_5;
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
int io_calls = 0;
char io_json[EM_IO_BUFF_SZ + 64];
unsigned int io_len = 0;
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
em_ctrl_t *ctrl_instance_ptr = NULL;
em_ctrl_t *em_ctrl_t::get_em_ctrl_instance() { return ctrl_instance_ptr; }

char last_status[16];
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

    src = strstr(src, ".");
#if CCS_FIX
    /* FIX 3: no '.' left in the path -> strstr() returns NULL and ++src / *src dereferenced it */
    if (src == NULL) {
        return NULL;
    }
#endif
    ++src;

	if (*src == '[') {
		*is_num = false;
		++src;
		while (*src && *src != ']' && ++len < max_len) {
			*dst++ = *src++;
		}
		*dst++ = 0;
#if CCS_FIX
        /* FIX 3: never step past the terminating NUL (callers feed the result back into strstr) */
        for (int k = 0; k < 2 && *src; k++) {
            src++;
        }
#else
		src += 2;
#endif
	} else {
		*is_num = true;
		while (*src && *src != '.' && ++len < max_len) {
			*dst++ = *src++;
		}
		*dst++ = 0;
#if CCS_FIX
        if (*src) {
            src++;
        }
#else
		src++;
#endif
	}

	return src;
}

/* --- copied verbatim from src/ctrl/dm_easy_mesh_ctrl.cpp --- */
bus_error_t em_ctrl_t::cmd_channelselect(const char *method_name, const bus_data_prop_t *input_params, bus_data_prop_t **output_params, void *async_handle)
{
    (void)async_handle;
    const char *name = method_name;
    const char *param;
    char instance[MAX_INSTANCE_LEN] = { 0 };
    bool is_num;
    const bus_data_prop_t *prop = NULL;
    em_subdoc_info_t *subdoc = NULL;
    unsigned char buff[sizeof(em_subdoc_info_t) + EM_IO_BUFF_SZ];
    cJSON *root = NULL, *json = NULL, *net_obj = NULL;
    cJSON *dev_list = NULL, *dev_obj = NULL, *radio_list = NULL, *radio_obj = NULL;
    cJSON *class_arr = NULL, *class_obj = NULL;
    cJSON *channel_list_obj = NULL, *channel_pref_obj = NULL;
    mac_addr_str_t mac_str;
    char *json_buff = NULL;
    size_t json_len = 0;
    bus_error_t rc = bus_error_success;

#if CCS_FIX
    /* FIX 1: NULL method_name went straight into strrchr() */
    if (name == NULL) {
        em_printfout("Invalid method name");
        if (output_params) {
            *output_params = tr_181_t::tr181_set_status_output_prop("Failure");
        }
        return bus_error_invalid_input;
    }
#endif
    param = strrchr(name, '.');
    if (param == NULL) {
        em_printfout("Invalid method name");
        if (output_params) {
            *output_params = tr_181_t::tr181_set_status_output_prop("Failure");
        }
        return bus_error_invalid_input;
    }
    ++param;
    if (strcmp("ChannelSelectionRequest()", param) != 0) {
        em_printfout("Invalid method");
        if (output_params) {
            *output_params = tr_181_t::tr181_set_status_output_prop("Failure");
        }
        return bus_error_invalid_method;
    }

    // Lookup controller and get the DM instance for this device/radio path
    em_ctrl_t *em_ctrl = em_ctrl_t::get_em_ctrl_instance();
    if (!em_ctrl) {
        em_printfout("Controller not found");
        if (output_params) {
            *output_params = tr_181_t::tr181_set_status_output_prop("Failure");
        }
        return bus_error_general;
    }
    dm_easy_mesh_ctrl_t *dm_ctrl = em_ctrl->get_dm_ctrl();

    // Skip the static network prefix and parse the device instance from the TR-181 path
#if CCS_FIX
    /* FIX 2: a method name shorter than the network prefix made "name +=" run past the NUL */
    if (strlen(name) < sizeof(DATAELEMS_NETWORK)) {
        em_printfout("Invalid method path");
        if (output_params) {
            *output_params = tr_181_t::tr181_set_status_output_prop("Failure");
        }
        return bus_error_invalid_namespace;
    }
#endif
    name += sizeof(DATAELEMS_NETWORK);
    name = dm_ctrl->get_table_instance(name, instance, MAX_INSTANCE_LEN, &is_num);
#if CCS_FIX
    /* FIX 3: get_table_instance() now returns NULL when the path has no further '.' */
    if (name == NULL) {
        em_printfout("Invalid method path");
        if (output_params) {
            *output_params = tr_181_t::tr181_set_status_output_prop("Failure");
        }
        return bus_error_invalid_namespace;
    }
#endif
    dm_easy_mesh_t *dm = dm_ctrl->get_dm_easy_mesh(instance, is_num);
    if (dm == NULL) {
        em_printfout("Device not found");
        if (output_params) {
            *output_params = tr_181_t::tr181_set_status_output_prop("Failure");
        }
        return bus_error_invalid_namespace;
    }

    name = dm_ctrl->get_table_instance(name, instance, MAX_INSTANCE_LEN, &is_num);
#if CCS_FIX
    /* FIX 3: no Radio.{i} component in the path */
    if (name == NULL) {
        em_printfout("Radio not found");
        if (output_params) {
            *output_params = tr_181_t::tr181_set_status_output_prop("Failure");
        }
        return bus_error_invalid_namespace;
    }
#endif
    dm_radio_t *radio = dm_ctrl->get_dm_radio(dm, instance, is_num);
    if (radio == NULL) {
        em_printfout("Radio not found");
        if (output_params) {
            *output_params = tr_181_t::tr181_set_status_output_prop("Failure");
        }
        return bus_error_invalid_namespace;
    }

    em_device_info_t *di = dm->get_device()->get_device_info();
    em_radio_info_t *ri = radio->get_radio_info();

    // Data structures used to collect nested Class.N.* channel preference input.
    // The instance number is represented by the array slot itself, so the
    // incoming values must be contiguous and start at 1.
    // Each Channel.M entry is a group of channel numbers sharing one preference.
    struct channel_info {
        std::vector<int> channels;
        int preference;
    };

    // Track one parsed Class.N instance and all of its Channel.M children.
    struct class_info {
        int op_class;
        int num_channels;
        int highest_channel_instance;
        channel_info channels[MAX_CHANSEL_CHANNELS];
    };

    // Parsed classes keyed by their 1-based instance number; heap-allocated,
    // the channel group vectors are too heavy for the stack.
    std::vector<class_info> classes(MAX_CHANSEL_CLASSES);
    int highest_class_instance = 0;

    // Reset a class slot so it can be reused for a newly parsed instance.
    auto clear_class = [&](class_info &cls) {
        cls.op_class = -1;
        cls.num_channels = 0;
        cls.highest_channel_instance = 0;
        for (int i = 0; i < MAX_CHANSEL_CHANNELS; i++) {
            cls.channels[i].channels.clear();
            cls.channels[i].preference = -1;
        }
    };

    // Initialize every slot so the emptiness checks are always well-defined.
    for (class_info &cls : classes) {
        clear_class(cls);
    }

    // Locate the storage slot for a given Class.N instance, creating it when needed.
    auto find_or_create_class_by_instance = [&](int instance_index) -> class_info* {
        if (instance_index < 1 || instance_index > MAX_CHANSEL_CLASSES) {
            return NULL;
        }

        size_t slot = static_cast<size_t>(instance_index - 1);
        if (classes[slot].op_class == -1 && classes[slot].num_channels == 0 && classes[slot].highest_channel_instance == 0) {
            clear_class(classes[slot]);
            if (instance_index > highest_class_instance) {
                highest_class_instance = instance_index;
            }
        }
        return &classes[slot];
    };

    // Locate the storage slot for a given Channel.M entry inside a class instance.
    auto find_or_create_channel_slot = [&](class_info *cls, int channel_instance) -> int {
        if (channel_instance < 1 || channel_instance > MAX_CHANSEL_CHANNELS) {
            return -1;
        }

        int slot = channel_instance - 1;
        bool slot_is_empty = (cls->channels[slot].channels.empty() && cls->channels[slot].preference == -1);
        if (cls->num_channels == 0 || slot_is_empty) {
            cls->num_channels++;
            if (channel_instance > cls->highest_channel_instance) {
                cls->highest_channel_instance = channel_instance;
            }
            cls->channels[slot].channels.clear();
            cls->channels[slot].preference = -1;
        }
        return slot;
    };

    // Parse incoming TR-181 parameters and populate the temporary class/channel structures.
    // Maximum number of tokens in a TR-181 parameter
    static const int TR181_MAX_TOKENS = 6;
    // Token indexes for Class.N.Channel.M.* "Class" string and "N" index
    static const int TR181_CLASS_STR_TOKEN = 0;
    static const int TR181_CLASS_INDEX_TOKEN = 1;

    // Token indexes for Class.N.Channel.M.* "Channel" string and "M" index
    static const int TR181_PARAM_TOKEN = 2;
    static const int TR181_CHANNEL_INSTANCE_TOKEN = 3;

    // Token index for Class.N.Channel.M.* "Channel" or "Preference" string
    static const int TR181_CHANNEL_ATTR_TOKEN = 4;

    // Number of tokens in Class.N.* parameters and Class.N.Channel.M.* parameters
    static const int TR181_NUM_OF_TOKENS_IN_CLASS = 3;
    static const int TR181_NUM_OF_TOKENS_IN_CHANNEL = 5;

    // TR-181 strings used in parsing
    static const char TR181_CLASS_STR[] = "Class";
    static const char TR181_OPCLASS_STR[] = "OpClass";
    static const char TR181_CHANNEL_STR[] = "Channel";
    static const char TR181_PREFERENCE_STR[] = "Preference";

    for (prop = input_params; prop; prop = prop->next_data) {
        char prop_name[BUS_MAX_NAME_LENGTH];
        snprintf(prop_name, sizeof(prop_name), "%s", prop->name);

        char *tokens[TR181_MAX_TOKENS] = { NULL };
        char *saveptr = NULL;
        int token_count = 0;
        char *tok = strtok_r(prop_name, ".", &saveptr);
        while (tok != NULL && token_count < TR181_MAX_TOKENS) {
            tokens[token_count++] = tok;
            tok = strtok_r(NULL, ".", &saveptr);
        }

        // Only nested Class.N.* properties are valid for ChannelSelectionRequest()
        if (token_count >= 2 && strcmp(tokens[TR181_CLASS_STR_TOKEN], TR181_CLASS_STR) == 0) {
            char *end = NULL;
            errno = 0;
            long class_index_l = strtol(tokens[TR181_CLASS_INDEX_TOKEN], &end, 10);
            if (end == tokens[TR181_CLASS_INDEX_TOKEN] || *end != '\0' || errno == ERANGE || class_index_l < 1 || class_index_l > INT_MAX) {
                em_printfout("Invalid class index in '%s'", prop->name);
                rc = bus_error_invalid_input;
                goto finish;
            }
            int class_index = static_cast<int>(class_index_l);
            class_info *cls = find_or_create_class_by_instance(class_index);
            if (!cls) {
                em_printfout("Too many classes");
                rc = bus_error_invalid_input;
                goto finish;
            }

            if (token_count == TR181_NUM_OF_TOKENS_IN_CLASS && strcmp(tokens[TR181_PARAM_TOKEN], TR181_OPCLASS_STR) == 0) {
                // Parse Class.N.OpClass
                if (!tr_181_t::tr181_get_prop_int(prop, &cls->op_class)) {
                    rc = bus_error_invalid_input;
                    goto finish;
                }
            } else if (token_count == TR181_NUM_OF_TOKENS_IN_CHANNEL && strcmp(tokens[TR181_PARAM_TOKEN], TR181_CHANNEL_STR) == 0) {
                // Parse Class.N.Channel.M.Channel or Class.N.Channel.M.Preference
                char *end = NULL;
                errno = 0;
                long channel_instance_l = strtol(tokens[TR181_CHANNEL_INSTANCE_TOKEN], &end, 10);
                if (end == tokens[TR181_CHANNEL_INSTANCE_TOKEN] || *end != '\0' || errno == ERANGE || channel_instance_l < 1 || channel_instance_l > INT_MAX) {
                    em_printfout("Invalid channel index in '%s'", prop->name);
                    rc = bus_error_invalid_input;
                    goto finish;
                }
                int channel_instance = static_cast<int>(channel_instance_l);
                int channel_slot = find_or_create_channel_slot(cls, channel_instance);
                if (channel_slot < 0) {
                    em_printfout("Too many Channel entries in '%s'", prop->name);
                    rc = bus_error_invalid_input;
                    goto finish;
                }
                if (strcmp(tokens[TR181_CHANNEL_ATTR_TOKEN], TR181_CHANNEL_STR) == 0) {
                    // TR-181 models Channel as a list of unsignedInt, carried
                    // as a comma-separated string per TR-106 list syntax.
                    char list_str[MAX_CHANSEL_LIST_LEN + 1] = { 0 };
                    if (!tr_181_t::tr181_copy_prop_string(prop, list_str, sizeof(list_str))) {
                        em_printfout("Channel in '%s' must be a comma-separated list string", prop->name);
                        rc = bus_error_invalid_input;
                        goto finish;
                    }
                    // tr181_copy_prop_string() truncates silently and stops at an
                    // embedded NUL; the copy must be the whole property value.
                    const char *list_src = static_cast<const char *>(prop->value.raw_data.bytes);
                    size_t list_len = prop->value.raw_data_len;
                    if (list_len > 0 && list_src[list_len - 1] == '\0') {
                        list_len--;
                    } else if (list_len == 0) {
                        list_len = strnlen(list_src, sizeof(list_str));
                    }
                    if (strlen(list_str) != list_len) {
                        em_printfout("Channel list in '%s' is too long or not a plain string", prop->name);
                        rc = bus_error_invalid_input;
                        goto finish;
                    }
                    cls->channels[channel_slot].channels.clear();
                    const char *cursor = list_str;
                    while (*cursor != '\0') {
                        char *chan_end = NULL;
                        errno = 0;
                        long channel_l = strtol(cursor, &chan_end, 10);
                        while (isspace(static_cast<unsigned char>(*chan_end))) {
                            ++chan_end;
                        }
                        if (chan_end == cursor || errno == ERANGE ||
                            channel_l < 1 || channel_l > 255 ||
                            (*chan_end != ',' && *chan_end != '\0') ||
                            (*chan_end == ',' && *(chan_end + 1) == '\0')) {
                            em_printfout("Invalid channel list '%s' in '%s'", list_str, prop->name);
                            rc = bus_error_invalid_input;
                            goto finish;
                        }
                        cls->channels[channel_slot].channels.push_back(static_cast<int>(channel_l));
                        cursor = (*chan_end == ',') ? chan_end + 1 : chan_end;
                    }
                    if (cls->channels[channel_slot].channels.empty()) {
                        em_printfout("Empty channel list in '%s'", prop->name);
                        rc = bus_error_invalid_input;
                        goto finish;
                    }
                } else if (strcmp(tokens[TR181_CHANNEL_ATTR_TOKEN], TR181_PREFERENCE_STR) == 0) {
                    if (!tr_181_t::tr181_get_prop_int(prop, &cls->channels[channel_slot].preference)) {
                        rc = bus_error_invalid_input;
                        goto finish;
                    }
                    if (cls->channels[channel_slot].preference < 0 || cls->channels[channel_slot].preference >= EM_CH_PREF_MAX) {
                        em_printfout("Invalid preference value in '%s'", prop->name);
                        rc = bus_error_invalid_input;
                        goto finish;
                    }
                } else {
                    em_printfout("Invalid parameter: %s", prop->name);
                    rc = bus_error_invalid_input;
                    goto finish;
                }
            } else {
                em_printfout("Invalid parameter: %s", prop->name);
                rc = bus_error_invalid_input;
                goto finish;
            }
        } else {
            em_printfout("Invalid parameter: %s", prop->name);
            rc = bus_error_invalid_input;
            goto finish;
        }
    }

    // Fail fast if the request does not contain any class instances at all.
    if (highest_class_instance == 0) {
        em_printfout("Mandatory parameters missing: expected nested Class.N.* entries");
        if (output_params) {
            *output_params = tr_181_t::tr181_set_status_output_prop("Failure");
        }
        return bus_error_invalid_input;
    }

    // Validate that all requested class instances have an OpClass and at least one channel entry.
    for (int class_index = 1; class_index <= highest_class_instance; class_index++) {
        const class_info &cls = classes[static_cast<size_t>(class_index - 1)];
        if (cls.op_class == -1 && cls.num_channels == 0 && cls.highest_channel_instance == 0) {
            em_printfout("Missing Class.%d instance", class_index);
            rc = bus_error_invalid_input;
            goto finish;
        }
    }

    // Validate each parsed class entry against the radio band and operating-class rules.
    for (int class_index = 1; class_index <= highest_class_instance; class_index++) {
        class_info &cls = classes[static_cast<size_t>(class_index - 1)];
        if (cls.op_class == -1) {
            em_printfout("Missing OpClass for Class.%d", class_index);
            rc = bus_error_invalid_input;
            goto finish;
        }
        if (cls.op_class < 1) {
            em_printfout("Invalid OpClass %d for Class.%d", cls.op_class, class_index);
            rc = bus_error_invalid_input;
            goto finish;
        }
        
        // Reject numbering gaps and entries missing one of Channel/Preference.
        for (int channel_index = 1; channel_index <= cls.highest_channel_instance; channel_index++) {
            int channel_slot = channel_index - 1;
            bool has_channel = !cls.channels[channel_slot].channels.empty();
            bool has_preference = (cls.channels[channel_slot].preference != -1);
            if (!has_channel && !has_preference) {
                em_printfout("Missing Channel.%d instance for Class.%d", channel_index, class_index);
                rc = bus_error_invalid_input;
                goto finish;
            }
            if (has_channel != has_preference) {
                em_printfout("Class.%d.Channel.%d must set both Channel and Preference",
                              class_index, channel_index);
                rc = bus_error_invalid_input;
                goto finish;
            }
        }

        std::vector<int> valid_channels = dm_easy_mesh_t::get_channel_list_by_op_class(cls.op_class);
        if (valid_channels.empty()) {
            em_printfout("Unknown OpClass %d for Class.%d", cls.op_class, class_index);
            rc = bus_error_invalid_input;
            goto finish;
        }

        em_freq_band_t opclass_band = dm_easy_mesh_t::get_freq_band_by_op_class(cls.op_class);
        if (opclass_band == em_freq_band_unknown) {
            em_printfout("Unknown band for OpClass %d in Class.%d", cls.op_class, class_index);
            rc = bus_error_invalid_input;
            goto finish;
        }
        if (opclass_band != ri->band) {
            em_printfout("OpClass %d in Class.%d does not match radio band %d", cls.op_class, class_index, ri->band);
            rc = bus_error_invalid_input;
            goto finish;
        }

        std::vector<int> seen_channels;
        for (int channel_index = 1; channel_index <= cls.highest_channel_instance; channel_index++) {
            int channel_slot = channel_index - 1;
            channel_info &group = cls.channels[channel_slot];
            if (group.channels.empty()) {
                continue;
            }

            for (int channel : group.channels) {
                // Reject duplicate channel values within the same Class
                for (int prev : seen_channels) {
                    if (prev == channel) {
                        em_printfout("Duplicate Channel %d in Class.%d", channel, class_index);
                        rc = bus_error_invalid_input;
                        goto finish;
                    }
                }
                seen_channels.push_back(channel);

                bool channel_matches_opclass = false;
                for (int valid_channel : valid_channels) {
                    if (valid_channel == channel) {
                        channel_matches_opclass = true;
                        break;
                    }
                }
                if (!channel_matches_opclass) {
                    em_printfout("Channel %d not allowed for OpClass %d in Class.%d",
                                  channel, cls.op_class, class_index);
                    rc = bus_error_invalid_input;
                    goto finish;
                }
            }
        }
        // The decoded ChannelList holds EM_MAX_CHANNELS_IN_LIST entries; reject
        // a class that would be truncated silently.
        if (seen_channels.size() > EM_MAX_CHANNELS_IN_LIST) {
            em_printfout("Class.%d lists %zu channels, at most %d allowed",
                          class_index, seen_channels.size(), EM_MAX_CHANNELS_IN_LIST);
            rc = bus_error_invalid_input;
            goto finish;
        }
    }

    // Build the EM control subdocument and JSON payload for ChannelSelectionRequest.
    subdoc = reinterpret_cast<em_subdoc_info_t *>(buff);
    memset(subdoc, 0, sizeof(em_subdoc_info_t));
    strncpy(subdoc->name, "ChannelSelectionRequest", sizeof(subdoc->name) - 1);

    root = cJSON_CreateObject();
    json = cJSON_CreateObject();
    if (!root || !json) {
        em_printfout("Create object failed");
        rc = bus_error_out_of_resources;
        goto finish;
    }
    if (!cJSON_AddItemToObject(root, "wfa-dataelements:ChannelSelectionRequest", json)) {
        em_printfout("Add item failed");
        cJSON_Delete(json);
        rc = bus_error_out_of_resources;
        goto finish;
    }

    // Create the Network/Device/Radio container structure used by the EM payload.
    net_obj = cJSON_AddObjectToObject(json, "Network");
    if (!net_obj) {
        em_printfout("Add Network failed");
        rc = bus_error_out_of_resources;
        goto finish;
    }
    if (!cJSON_AddStringToObject(net_obj, "ID", GLOBAL_NET_ID)) {
        em_printfout("Add Network ID failed");
        rc = bus_error_out_of_resources;
        goto finish;
    }

    dev_list = cJSON_AddArrayToObject(net_obj, "DeviceList");
    if (!dev_list) {
        em_printfout("Add DeviceList failed");
        rc = bus_error_out_of_resources;
        goto finish;
    }

    dev_obj = cJSON_CreateObject();
    if (!dev_obj) {
        em_printfout("Create device object failed");
        rc = bus_error_out_of_resources;
        goto finish;
    }
    if (!cJSON_AddItemToArray(dev_list, dev_obj)) {
        em_printfout("Add Device failed");
        cJSON_Delete(dev_obj);
        rc = bus_error_out_of_resources;
        goto finish;
    }
    dm_easy_mesh_t::macbytes_to_string(di->intf.mac, mac_str);
    if (!cJSON_AddStringToObject(dev_obj, "ID", mac_str)) {
        em_printfout("Add Device ID failed");
        rc = bus_error_out_of_resources;
        goto finish;
    }

    radio_list = cJSON_AddArrayToObject(dev_obj, "RadioList");
    if (!radio_list) {
        em_printfout("Add RadioList failed");
        rc = bus_error_out_of_resources;
        goto finish;
    }

    radio_obj = cJSON_CreateObject();
    if (!radio_obj) {
        em_printfout("Create radio object failed");
        rc = bus_error_out_of_resources;
        goto finish;
    }
    if (!cJSON_AddItemToArray(radio_list, radio_obj)) {
        em_printfout("Add Radio failed");
        cJSON_Delete(radio_obj);
        rc = bus_error_out_of_resources;
        goto finish;
    }
    dm_easy_mesh_t::macbytes_to_string(ri->id.ruid, mac_str);
    if (!cJSON_AddStringToObject(radio_obj, "ID", mac_str)) {
        em_printfout("Add Radio ID failed");
        rc = bus_error_out_of_resources;
        goto finish;
    }

    // Add the radio-level ChannelSelectionRequest array that will carry the parsed classes.
    class_arr = cJSON_AddArrayToObject(radio_obj, "ChannelSelectionRequest");
    if (!class_arr) {
        em_printfout("Add ChannelSelectionRequest failed");
        rc = bus_error_out_of_resources;
        goto finish;
    }

    if (highest_class_instance > 0) {
        // Convert each validated class entry into JSON with ChannelList and ChannelPrefList.
        for (int class_index = 1; class_index <= highest_class_instance; class_index++) {
            class_info &cls = classes[static_cast<size_t>(class_index - 1)];
            if (cls.op_class == -1 || cls.num_channels == 0) {
                em_printfout("Incomplete class entry");
                rc = bus_error_invalid_input;
                goto finish;
            }

            class_obj = cJSON_CreateObject();
            if (!class_obj) {
                em_printfout("Create class object failed");
                rc = bus_error_out_of_resources;
                goto finish;
            }
            if (!cJSON_AddItemToArray(class_arr, class_obj)) {
                em_printfout("Add class object failed");
                cJSON_Delete(class_obj);
                rc = bus_error_out_of_resources;
                goto finish;
            }
            if (!cJSON_AddNumberToObject(class_obj, "Class", cls.op_class)) {
                em_printfout("Add Class failed");
                rc = bus_error_out_of_resources;
                goto finish;
            }

            channel_list_obj = cJSON_AddArrayToObject(class_obj, "ChannelList");
            channel_pref_obj = cJSON_AddArrayToObject(class_obj, "ChannelPrefList");
            if (!channel_list_obj || !channel_pref_obj) {
                em_printfout("Add ChannelList or ChannelPrefList failed");
                rc = bus_error_out_of_resources;
                goto finish;
            }

            for (int channel_index = 1; channel_index <= cls.highest_channel_instance; channel_index++) {
                int channel_slot = channel_index - 1;
                channel_info &group = cls.channels[channel_slot];
                if (group.channels.empty() || group.preference == -1) {
                    em_printfout("Missing Channel or Preference for channel instance %d", channel_index);
                    rc = bus_error_invalid_input;
                    goto finish;
                }
                for (int channel : group.channels) {
                    if (!cJSON_AddItemToArray(channel_list_obj, cJSON_CreateNumber(channel)) ||
                        !cJSON_AddItemToArray(channel_pref_obj, cJSON_CreateNumber(group.preference))) {
                        em_printfout("Add channel entry failed");
                        rc = bus_error_out_of_resources;
                        goto finish;
                    }
                }
            }
        }
    }

    // Serialize the final JSON payload and send it to the EM control bus.
    json_buff = cJSON_PrintUnformatted(root);
    if (!json_buff) {
        em_printfout("Print JSON failed");
        rc = bus_error_out_of_resources;
        goto finish;
    }

    json_len = strlen(json_buff) + 1;
    if (json_len > EM_IO_BUFF_SZ) {
        em_printfout("JSON payload too large");
        rc = bus_error_invalid_input;
        goto finish;
    }
    memcpy(subdoc->buff, json_buff, json_len);

    em_printfout("Sending ChannelSelectionRequest with JSON payload len %zu:", json_len - 1);
    em_ctrl->io_process(em_bus_event_type_channel_select, subdoc->buff, json_len);
    free(json_buff);
    cJSON_Delete(root);

    if (output_params) {
        *output_params = tr_181_t::tr181_set_status_output_prop("Success");
    }

    // Request processed successfully
    return bus_error_success;

finish:
    // Common cleanup for failure paths
    if (output_params) {
        *output_params = tr_181_t::tr181_set_status_output_prop("Failure");
    }
    if (json_buff) free(json_buff);
    if (root) cJSON_Delete(root);
    return rc;
}

/* --- runner entry point --- */
bus_error_t invoke(const char *method, const bus_data_prop_t *in, bus_data_prop_t **out)
{
    static em_ctrl_t ctrl;
    ctrl_instance_ptr = &ctrl;
    ctrl.m_data_model.dm.device.info.intf.mac[5] = 1; ctrl.m_data_model.dm.device.info.intf.mac[0] = 2;
    ctrl.m_data_model.dm.radio.info.band = (em_freq_band_t)g_radio_band;
    ctrl.m_data_model.dm.radio.info.id.ruid[5] = 0x11;
    io_calls = 0; io_len = 0; last_status[0] = 0; memset(io_json, 0, sizeof(io_json));
    return em_ctrl_t::cmd_channelselect(method, in, out, NULL);
}

} /* namespace ccs */
