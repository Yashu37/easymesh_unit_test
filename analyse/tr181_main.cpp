/*
 * HANDLER: main (src/network_optimiser/test_tr181.cpp)
 *
 * Copied verbatim from unified-wifi-mesh (develop @ 1ba9529): the test_tr enum, print_options, output_cb, topo_cb and main() of the TR-181
 * test tool, main renamed tmo_main with a macro. Local arrays: char service_name[] = "Test_TR181". scanf is redirected to a scripted
 * stdin (tmo_scanf); the bus descriptor is a stand-in (see tr181_main.h) whose functions record what main asks for; calloc / strdup / free
 * go through tracked allocations that sit between poisoned guards. The stand-in invoke_fn frees the SetSSID object tree like a
 * well-behaved callee, so whatever main still owns at the end is a leak of main itself.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <signal.h>
#include <sanitizer/asan_interface.h>
#include "tr181_main.h"

namespace tmo {
int *g_script = NULL; int g_script_n = 0; int g_script_pos = 0; int g_eof_calls = 0; int g_mode = 0; bool g_hung = false; bool g_ended_by_stdin = false;
jmp_buf g_env;
int g_open_rc = 0, g_get_rc = 0, g_invoke_rc = 0, g_subs_rc = 0; bool g_null_desc = false;
std::string g_seq, g_get_names; int g_free_calls = 0, g_invoke_calls = 0, g_subs_calls = 0, g_inv_props = 0, g_inv_ok = 0, g_subs_ok = 0;
std::vector<void *> g_live; static std::vector<size_t> s_live_sz; bool g_returned = false; int g_ret = 0;

int tmo_scanf(const char *fmt, ...)
{
    va_list a; va_start(a, fmt); int *p = va_arg(a, int *); va_end(a);
    if (g_script_pos < g_script_n) { *p = g_script[g_script_pos++]; return 1; }
    g_eof_calls++;
    if (g_mode == 0 || g_eof_calls > 50) { g_hung = (g_mode != 0); g_ended_by_stdin = true; longjmp(g_env, 1); }   /* Ctrl-C / hang detected */
    return EOF;
}
/* tracked allocations: [guard][object][guard], guards poisoned while the object is alive */
void *tmo_calloc(size_t n, size_t sz)
{
    char *raw = (char *)calloc(1, TMO_GUARD + n * sz + TMO_GUARD); g_live.push_back(raw); s_live_sz.push_back(n * sz);
    __asan_poison_memory_region(raw, TMO_GUARD); __asan_poison_memory_region(raw + TMO_GUARD + n * sz, TMO_GUARD);
    return raw + TMO_GUARD;
}
char *tmo_strdup(const char *s)
{
    size_t n = strlen(s) + 1; char *p = (char *)tmo_calloc(n, 1); memcpy(p, s, n); return p;
}
void tmo_free(void *p)
{
    if (!p) return;
    char *raw = (char *)p - TMO_GUARD;
    size_t n = 0;
    for (size_t i = 0; i < g_live.size(); i++) if (g_live[i] == raw) { n = s_live_sz[i]; g_live.erase(g_live.begin() + i); s_live_sz.erase(s_live_sz.begin() + i); break; }
    __asan_unpoison_memory_region(raw, TMO_GUARD + n + TMO_GUARD); free(raw);
}

/* --- the bus stand-ins --- */
static bus_error_t s_open(bus_handle_t *h, char *name) { g_seq += 'O'; return (bus_error_t)g_open_rc; }
static bus_error_t s_get(bus_handle_t *h, char const *name, raw_data_t *d)
{
    g_seq += strcmp(name, DEVICE_WIFI_DATAELEMENTS_NETWORK_CONTROLLERID) == 0 ? 'G' : 'g'; g_get_names += name; g_get_names += ';';
    if (g_get_rc == 0) { d->data_type = bus_data_type_string; d->raw_data.bytes = strdup("02:00:00:00:00:01"); d->raw_data_len = 18; }
    return (bus_error_t)g_get_rc;
}
static void s_free(raw_data_t *d) { g_free_calls++; free(d->raw_data.bytes); d->raw_data.bytes = NULL; }
static bus_error_t s_subs(bus_handle_t *h, char const *name, void *cb, void *ud, int to)
{
    g_seq += 'S'; g_subs_calls++; g_subs_ok = strcmp(name, DEVICE_WIFI_DATAELEMENTS_NETWORK_TOPOLOGY) == 0 && cb != NULL; return (bus_error_t)g_subs_rc;
}
static bus_error_t s_invoke(bus_handle_t *h, char const *pn, char const *en, bus_data_obj_t *in, wifi_bus_method_async_resp_handler_t cb, uint32_t to)
{
    g_seq += 'I'; g_invoke_calls++;
    static const char *names[5] = { "SSID", "AddRemoveChange", "Band", "PassPhrase", "AKMsAllowed" };
    static const char *vals[5]  = { "atest", "Add", "2.4", "rdk@1234", "psk" };
    int n = 0, ok = in->num_prop == 5 && strcmp(pn, DEVICE_WIFI_DATAELEMENTS_NETWORK_SETSSID_CMD) == 0 && cb != NULL && to == BUS_METHOD_SET;
    for (bus_data_prop_t *p = &in->data_prop; p; p = p->next_data, n++) {
        if (n < 5) ok = ok && !strcmp(p->name, names[n]) && p->value.raw_data.bytes && !strcmp((char *)p->value.raw_data.bytes, vals[n]);
    }
    g_inv_props = n; g_inv_ok = ok && n == 5;
    /* a well-behaved callee releases what it was handed */
    bus_data_prop_t *p = in->data_prop.next_data;
    tmo_free(in->data_prop.value.raw_data.bytes);
    while (p) { bus_data_prop_t *nx = p->next_data; tmo_free(p->value.raw_data.bytes); tmo_free(p); p = nx; }
    tmo_free(in);
    return (bus_error_t)g_invoke_rc;
}
static wifi_bus_desc_t s_desc = { s_open, s_get, s_free, s_subs, s_invoke };
void bus_init(bus_handle_t *h) { }
wifi_bus_desc_t *get_bus_descriptor(void) { return g_null_desc ? NULL : &s_desc; }

/* --- copied verbatim (main renamed by the macro; calloc / strdup / scanf are the tracked / scripted ones) --- */
#define main tmo_main
#define scanf tmo_scanf
#define strdup tmo_strdup
#define calloc tmo_calloc
typedef enum{
    CONTROLLERID,
    COLOCATEDAGENTID,
    SETSSID,
    TOPO_PUBLISH
}test_tr;

void print_options()
{
    printf("\n ---------------------------------------------------");
    printf("\n Test TR-Param");
    printf("\nDEVICE_WIFI_DATAELEMENTS_NETWORK_CONTROLLERID:%d",CONTROLLERID);
    printf("\nDEVICE_WIFI_DATAELEMENTS_NETWORK_COLOCATEDAGENTID:%d",COLOCATEDAGENTID);
    printf("\nDEVICE_WIFI_DATAELEMENTS_NETWORK_SETSSID_CMD:%d",SETSSID);
    printf("\nDEVICE_WIFI_DATAELEMENTS_NETWORK_TOPO_PUBLISH:%d",TOPO_PUBLISH);
    printf("\n ---------------------------------------------------");
    printf("\n");
}

void output_cb(char const* methodName, bus_error_t error, bus_data_prop_t *params, void *userData)
{
    printf("	OUTPUT Callback status: %d, params:%s, userData: %s\n", error, params, userData);
    //check wheter config is successfully applied to all agents or not
    //wait all devices are online and check ssid details of all devices
}


int topo_cb(char *event_name, raw_data_t *data, void *userData)
{
    printf("%s:%d Received Frame data for event [%s] and data :\n%s\n", __func__, __LINE__, event_name, data->raw_data.bytes);
    (void)userData;

    return 0;
}

int main()
{
    wifi_bus_desc_t *desc;
    bus_handle_t m_bus_hdl;
    memset(&m_bus_hdl, 0, sizeof(bus_handle_t));
    raw_data_t data;

    int num_retry = 0;
    bus_error_t bus_error_val;
    int rc = bus_error_success;
    char service_name[] = "Test_TR181";
    int input = 0;
    //cmdsetssid add_ssid;
    bus_data_prop_t *prop_data;


    bus_init(&m_bus_hdl);
    if((desc = get_bus_descriptor()) == NULL) {
        printf("%s:%d descriptor is null\n", __func__, __LINE__);
    }
    if (desc->bus_open_fn(&m_bus_hdl, service_name) != 0) {
        printf("%s:%d bus open failed\n",__func__, __LINE__);
        return 0;
    }
    printf("%s:%d he_bus open success\n", __func__, __LINE__);
    memset(&data, 0, sizeof(raw_data_t));

    while(1) {
        print_options();
        printf("\n Enter number to test: \n");
        scanf("%d", &input);
        memset(&data, 0, sizeof(raw_data_t));
        printf("%s:%d input=%d\n",__func__, __LINE__, input);
        
        if (input == CONTROLLERID) {
            if((bus_error_val = desc->bus_data_get_fn(&m_bus_hdl, DEVICE_WIFI_DATAELEMENTS_NETWORK_CONTROLLERID, &data)) != bus_error_success ) {
                printf("%s:%d bus_data_get_fn failed with error: %d\n", __func__, __LINE__, bus_error_val);
            }
            if (data.raw_data.bytes != NULL) {
                printf("\n%s:%d recv data: CONTROLLERID=%s\n", __func__, __LINE__, (char *)data.raw_data.bytes);
                get_bus_descriptor()->bus_data_free_fn(&data);
            } else
                printf("\n%s:%d recv data: CONTROLLERID is NULL: %s\n", __func__, __LINE__, (char *)data.raw_data.bytes);
        } else if (input == COLOCATEDAGENTID) { 
            if((bus_error_val = desc->bus_data_get_fn(&m_bus_hdl, DEVICE_WIFI_DATAELEMENTS_NETWORK_COLOCATEDAGENTID, &data)) != bus_error_success ) {
                printf("%s:%d bus_data_get_fn failed with error: %d\n", __func__, __LINE__, bus_error_val);
            }
            printf("\n%s:%d recv data:COLOCATEDAGENTID=%s\n", __func__, __LINE__, (char *)data.raw_data.bytes);
            get_bus_descriptor()->bus_data_free_fn(&data);
        } else if (input == SETSSID) {
            printf("\n%s:%d SET SSID start\n", __func__, __LINE__);
            bus_data_obj_t *input_data = (bus_data_obj_t*)calloc(1, sizeof(bus_data_obj_t));
            // Allocate on heap
            bus_data_prop_t *add_prop  = (bus_data_prop_t*)calloc(1, sizeof(bus_data_prop_t));
            bus_data_prop_t *band_prop = (bus_data_prop_t*)calloc(1, sizeof(bus_data_prop_t));
            bus_data_prop_t *pass_prop = (bus_data_prop_t*)calloc(1, sizeof(bus_data_prop_t));
            bus_data_prop_t *akm_prop  = (bus_data_prop_t*)calloc(1, sizeof(bus_data_prop_t));

            raw_data_t *p_raw_data = (raw_data_t*)calloc(1, sizeof(raw_data_t));
            input_data->data_prop.value.data_type = bus_data_type_string;
            input_data->data_prop.value.raw_data.bytes = strdup("private_ssid"); // strdup allocates and copies string
            input_data->data_prop.value.raw_data_len = strlen("private_ssid") + 1;

            //1st prop
            memset(&input_data->data_prop, 0, sizeof(bus_data_prop_t));
            strncpy(input_data->data_prop.name, "SSID", BUS_MAX_NAME_LENGTH);
            input_data->data_prop.name_len = strlen("SSID") + 1;
            input_data->data_prop.value.data_type = bus_data_type_string;
            input_data->data_prop.value.raw_data.bytes = strdup("atest");
            input_data->data_prop.value.raw_data_len = strlen("atest") + 1;
            input_data->data_prop.next_data = add_prop;

            //2nd prop
            // AddRemoveChange
            add_prop->value.data_type = bus_data_type_string;
            strncpy(add_prop->name, "AddRemoveChange", BUS_MAX_NAME_LENGTH);
            add_prop->name_len = strlen("AddRemoveChange") + 1;
            add_prop->value.raw_data.bytes = strdup("Add");
            add_prop->value.raw_data_len = strlen("Add") + 1;
            add_prop->next_data = band_prop;

            //3rd prop
            // Band
            band_prop->value.data_type = bus_data_type_string;
            strncpy(band_prop->name, "Band", BUS_MAX_NAME_LENGTH);
            band_prop->name_len = strlen("Band") + 1;
            band_prop->value.raw_data.bytes = strdup("2.4");
            band_prop->value.raw_data_len = strlen("2.4") + 1;
            band_prop->next_data = pass_prop;

            // PassPhrase
            pass_prop->value.data_type = bus_data_type_string;
            strncpy(pass_prop->name, "PassPhrase", BUS_MAX_NAME_LENGTH);
            pass_prop->name_len = strlen("PassPhrase") + 1;
            pass_prop->value.raw_data.bytes = strdup("rdk@1234");
            pass_prop->value.raw_data_len = strlen("rdk@1234") + 1;
            pass_prop->next_data = akm_prop;

            // AKMsAllowed
            akm_prop->value.data_type = bus_data_type_string;
                strncpy(akm_prop->name, "AKMsAllowed", BUS_MAX_NAME_LENGTH);
            akm_prop->name_len = strlen("AKMsAllowed") + 1;
            akm_prop->value.raw_data.bytes = strdup("psk");
            akm_prop->value.raw_data_len = strlen("psk") + 1;
            akm_prop->next_data = NULL;

            // Fill input_data
            input_data->num_prop = 5;

            bus_data_prop_t *prop = &input_data->data_prop;
            bus_data_prop_t *next;
            int idx = 0;
            printf("Total params: %d\n", idx);
            while (prop) {
                printf("  Param %d: name='%s', value='%s', len=%u\n", idx, prop->name, (char*)prop->value.raw_data.bytes, prop->value.raw_data_len);
                prop = prop->next_data;
                idx++;
            }
            if((bus_error_val = desc->bus_method_async_invoke_fn(&m_bus_hdl, \
                (char const *) DEVICE_WIFI_DATAELEMENTS_NETWORK_SETSSID_CMD, \
                ( char const *)DEVICE_WIFI_DATAELEMENTS_NETWORK_SETSSID_CMD, \
                input_data, output_cb, BUS_METHOD_SET)) != bus_error_success ) {
                printf("%s:%d bus_set_fn failed with error: %d\n", __func__, __LINE__, bus_error_val);
            }

            printf("%s:%d bus_set_fn SUCCESS: %d\n", __func__, __LINE__, bus_error_val);
        } else if (input == TOPO_PUBLISH) {
            printf("\n%s:%d PUBLISH TOPOLOGY start\n", __func__, __LINE__);
            if (desc->bus_event_subs_fn(&m_bus_hdl, DEVICE_WIFI_DATAELEMENTS_NETWORK_TOPOLOGY, reinterpret_cast<void *>(&topo_cb), nullptr, 0) != 0) {
                printf("Failed to subscribe to 'Device.WiFi.DataElements.Network.Topology'\n");
            }
        } else {
            printf("\n%s:%d Invalid Input\n", __func__, __LINE__);
        }
    }
    return 0;
}
#undef main
#undef scanf
#undef strdup
#undef calloc

void invoke(void)
{
    if (setjmp(g_env) == 0) { g_ret = tmo_main(); g_returned = true; }
}
} /* namespace tmo */
