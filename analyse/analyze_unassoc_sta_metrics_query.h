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
}
void run_all_tests_analyze_unassoc_sta_metrics_query(void);
#endif
