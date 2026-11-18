/* analyze_unassoc_sta_metrics_query harness types (namespace uaq). Own header, kept out of common.h. */
#ifndef ANALYZE_UNASSOC_STA_METRICS_QUERY_H
#define ANALYZE_UNASSOC_STA_METRICS_QUERY_H
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include "common.h"

namespace uaq {
#define UAQ_EVT_SZ 16384
#define UAQ_PCMD_EXTRA 8
#define UAQ_MAXCMD 16
#undef EM_MAX_OP_CLASS
#define EM_MAX_OP_CLASS 48
#undef EM_MAX_OPCLASS
#define EM_MAX_OPCLASS 64
#define EM_MAX_CHANNELS_PER_OPCLASS 16
#define EM_MAX_STA_PER_CHANNEL 64
#ifndef MIN_MAC_LEN
#define MIN_MAC_LEN 12
#endif
typedef unsigned char mac_address_t[6];

/* verbatim from inc/em_base.h */
typedef struct { uint8_t channel; uint8_t num_sta; mac_address_t sta_list[EM_MAX_STA_PER_CHANNEL]; } em_unassoc_query_channel_t;
typedef struct { uint8_t op_class; uint8_t num_channels; em_unassoc_query_channel_t channel_list[EM_MAX_CHANNELS_PER_OPCLASS]; } em_unassoc_query_opclass_t;
typedef struct { uint8_t num_opclass; em_unassoc_query_opclass_t opclass_list[EM_MAX_OPCLASS]; } em_unassoc_query_list_t;

typedef struct { mac_address_t al_mac; } em_cmd_unassoc_sta_query_params_t;
typedef struct { union { em_cmd_unassoc_sta_query_params_t unassoc_sta_query_params; } u; } em_cmd_params_t;
typedef struct { char name[64]; char buff[0]; } __attribute__((__packed__)) em_subdoc_info_t;
typedef struct {
    em_cmd_params_t params;
    unsigned char guard[32];           /* members after params (runner poisons it) */
    union { em_subdoc_info_t subdoc; } u;
} em_bus_event_t;

typedef struct {
    const char *test_name;
    const char *json;      /* the subdoc text; NULL when gen is used */
    int gen;               /* 1: 49 opclasses, 2: 48, 3: 17 channels, 4: 16, 5: 65 stas, 6: 64 stas */
    int expect_num;        /* return value: 1 = command built, 0 = rejected */
    const char *has;       /* substring of the recorded query summary that must appear */
    const char *not_has;   /* must NOT appear */
    bool crash;
} test_case_t;

extern test_case_t suite[];
extern char evt_buf[UAQ_EVT_SZ];
extern void *pcmd_buf[UAQ_MAXCMD + UAQ_PCMD_EXTRA];
extern int g_num;
extern char g_sum[4096];
void construct_input(const test_case_t *tc);
int invoke(void);
void teardown(void);

/* ---- scaffolding classes, usings, macros moved from analyze_unassoc_sta_metrics_query.cpp ---- */
extern int g_num;
extern char g_sum[4096];
static int g_cmds = 0;

class em_cmd_t {
public:
    virtual ~em_cmd_t() {}
    virtual em_cmd_t *clone_for_next() { return NULL; }    /* src/cmd/em_cmd.cpp returns NULL */
};
class dm_easy_mesh_t {
public:
    static void string_to_macbytes(char *key, mac_address_t bmac);
};
static void summarise(em_cmd_params_t *p, em_unassoc_query_list_t *q)
{
    char *s = g_sum; size_t n = sizeof(g_sum);
    unsigned char *a = p->u.unassoc_sta_query_params.al_mac;
    int w = snprintf(s, n, "al=%02x:%02x:%02x:%02x:%02x:%02x nop=%d", a[0], a[1], a[2], a[3], a[4], a[5], q->num_opclass);
    s += w; n -= w;
    for (int i = 0; i < q->num_opclass && i < 3; i++) {
        em_unassoc_query_opclass_t *o = &q->opclass_list[i];
        w = snprintf(s, n, " oc%d=%d/%d", i, o->op_class, o->num_channels); s += w; n -= w;
        for (int j = 0; j < o->num_channels && j < 3; j++) {
            em_unassoc_query_channel_t *c = &o->channel_list[j];
            w = snprintf(s, n, " c%d.%d=%d/%d", i, j, c->channel, c->num_sta); s += w; n -= w;
            for (int k = 0; k < c->num_sta && k < 3; k++) {
                unsigned char *m = c->sta_list[k];
                w = snprintf(s, n, " s%d.%d.%d=%02x:%02x:%02x:%02x:%02x:%02x", i, j, k, m[0], m[1], m[2], m[3], m[4], m[5]); s += w; n -= w;
            }
        }
    }
}
class em_cmd_unassoc_sta_query_t : public em_cmd_t {
public:
    em_cmd_unassoc_sta_query_t(em_cmd_params_t param, dm_easy_mesh_t &dm, em_unassoc_query_list_t *query)
    { (void)dm; g_cmds++; summarise(&param, query); }
};
class dm_easy_mesh_ctrl_t {
public:
    operator dm_easy_mesh_t() { return dm_easy_mesh_t(); }
    int analyze_unassoc_sta_metrics_query(em_bus_event_t *evt, em_cmd_t *pcmd[]);
};
static dm_easy_mesh_ctrl_t g_ctrl;

}
void run_all_tests_analyze_unassoc_sta_metrics_query(void);
#endif
