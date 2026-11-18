/* analyze_beacon_metrics_query scaffolding (namespace abq): usings, macros, typedefs and stand-in classes for the handler. Own header, kept out of common.h. */
#ifndef ANALYZE_BEACON_METRICS_QUERY_H
#define ANALYZE_BEACON_METRICS_QUERY_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "common.h"

namespace abq {

/* ---- scaffolding classes, usings, macros moved from analyze_beacon_metrics_query.cpp ---- */
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a)           (sizeof(a) / sizeof(a[0]))
#endif

/* --- scaffolding --- */
extern int cmd_created;
class em_cmd_t {
public:
    virtual ~em_cmd_t() {}
    virtual em_cmd_t *clone_for_next() { return NULL; }   /* src/cmd/em_cmd.cpp returns NULL */
};
em_cmd_beacon_metrics_param_t last_params;
class dm_easy_mesh_t {
public:
    static void string_to_macbytes(char *key, mac_address_t bmac);
};
class em_cmd_beacon_query_t : public em_cmd_t {
public:
    em_cmd_beacon_query_t(em_cmd_params_t param, dm_easy_mesh_t &dm)
    {
        (void)dm;
        memcpy(&last_params, &param.u.beacon_metrics_params, sizeof(last_params));
        cmd_created++;
    }
};
class dm_easy_mesh_ctrl_t {
public:
    operator dm_easy_mesh_t() { return dm_easy_mesh_t(); }
    int analyze_beacon_metrics_query(em_bus_event_t *evt, em_cmd_t *pcmd[]);
};

/* copied verbatim from src/dm/dm_easy_mesh.cpp */
void dm_easy_mesh_t::string_to_macbytes(char *key, mac_address_t bmac)
{
    unsigned char mac[6];
    if(strlen(key) > MIN_MAC_LEN)
        sscanf(key, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
                &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
    else
        sscanf(key, "%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx",
                &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
    bmac[0] = mac[0]; bmac[1] = mac[1]; bmac[2] = mac[2];
    bmac[3] = mac[3]; bmac[4] = mac[4]; bmac[5] = mac[5];

}

}
#endif
