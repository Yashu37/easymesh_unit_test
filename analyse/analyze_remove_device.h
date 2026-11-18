/* analyze_remove_device harness types (namespace ard). Own header, kept out of common.h so `make` stays incremental. */
#ifndef ANALYZE_REMOVE_DEVICE_H
#define ANALYZE_REMOVE_DEVICE_H
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include "common.h"

namespace ard {
#define ARD_EVT_SZ 16384
#define ARD_MAXCMD 16            /* EM_MAX_CMD: usable pcmd slots of the caller (em_ctrl_t::handle_remove_device) */
#define ARD_PCMD_EXTRA 40        /* slots past the caller's array, poisoned by the runner */
#define ARD_MAXDEV 48
#ifndef MIN_MAC_LEN
#define MIN_MAC_LEN 12
#endif
typedef unsigned char mac_address_t[6];
typedef char mac_addr_str_t[18];

typedef struct { char name[64]; char buff[0]; } __attribute__((__packed__)) em_subdoc_info_t;
typedef struct { int unused; } em_cmd_params_t;
typedef struct {
    em_cmd_params_t params;
    unsigned char guard[32];           /* members after params (runner poisons it) */
    union { em_subdoc_info_t subdoc; } u;
} em_bus_event_t;

/* stand-ins for the data model (handler body is in analyze_remove_device.cpp) */
class dm_device_t {
public:
    struct { struct { unsigned char mac[6]; } intf; struct { char net_id[16]; } id; } m_device_info;
};
class dm_easy_mesh_t {
public:
    bool present;                      /* get_data_model() finds a data model for this device */
    unsigned char mac[6];
    static void macbytes_to_string(unsigned char *mac, char *string);
    static void string_to_macbytes(char *key, mac_address_t bmac);
};
class dm_easy_mesh_list_t {
public:
    dm_device_t *get_first_device();
    dm_device_t *get_next_device(dm_device_t *dev);
    dm_easy_mesh_t *get_data_model(const char *net_id, const unsigned char *al_mac);
};
extern int g_cmds;
extern char g_sum[2048];
class em_cmd_t {
public:
    virtual ~em_cmd_t() {}
    virtual em_cmd_t *clone_for_next() { return NULL; }    /* src/cmd/em_cmd.cpp returns NULL */
};
class em_cmd_remove_device_t : public em_cmd_t {
public:
    em_cmd_remove_device_t(em_cmd_params_t param, dm_easy_mesh_t &dm)
    {   (void)param; g_cmds++;
        char s[24]; dm_easy_mesh_t::macbytes_to_string(dm.mac, s);
        size_t l = strlen(g_sum); snprintf(g_sum + l, sizeof(g_sum) - l, "%s;", s); }
};
class dm_easy_mesh_ctrl_t {
public:
    dm_easy_mesh_list_t m_data_model_list;
    int analyze_remove_device(em_bus_event_t *evt, em_cmd_t *pcmd[]);
};
extern dm_easy_mesh_ctrl_t g_ctrl_obj;

typedef struct {
    const char *test_name;
    const char *json;      /* the subdoc text; NULL when gen is used */
    int gen;               /* 1: DeviceList of 33 IDs, 2: 32 IDs (all kept), 3: 40 IDs */
    int ndev;              /* devices in the data model: 02:00:00:00:00:01 .. ndev */
    int expect_num;        /* return value = number of commands built */
    const char *has;       /* substring of the recorded device list that must appear */
    const char *not_has;   /* must NOT appear */
    bool crash;
} test_case_t;

extern test_case_t suite[];
extern char evt_buf[ARD_EVT_SZ];
extern void *pcmd_buf[ARD_MAXCMD + ARD_PCMD_EXTRA];
extern int g_num;
extern int g_ndev;
extern dm_device_t g_devs[ARD_MAXDEV];
extern dm_easy_mesh_t g_dms[ARD_MAXDEV];
void construct_input(const test_case_t *tc);
int invoke(void);
void teardown(void);
}
void run_all_tests_analyze_remove_device(void);
#endif
