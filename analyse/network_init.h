/* dm_network_t::init harness types (namespace nit). Own header, kept out of common.h so `make` stays incremental. */
#ifndef NETWORK_INIT_H
#define NETWORK_INIT_H
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "common.h"

namespace nit {
#define NIT_GUARD 128
#define EM_DATE_TIME_BUFF_SZ 64
typedef unsigned char mac_address_t[6];
typedef char em_string_t[32]; typedef char em_long_string_t[128]; typedef char em_interface_name_t[32];
typedef int em_media_type_t;
#define em_media_type_ieee8023ab 0x01
typedef struct { em_interface_name_t name; mac_address_t mac; em_media_type_t media; } __attribute__((__packed__)) em_interface_t;
/* em_network_info_t as in inc/em_base.h */
typedef struct {
    em_long_string_t id; unsigned short num_of_devices; em_long_string_t timestamp; em_interface_t ctrl_id;
    unsigned char num_mscs_disallowed_sta; em_string_t mscs_disallowed_sta[10];
    unsigned char num_scs_disallowed_sta; em_string_t scs_disallowed_sta[10];
    em_interface_t colocated_agent_id; em_media_type_t media;
} em_network_info_t;
class dm_network_t { public: em_network_info_t m_net_info; int init(); };
namespace util { char *get_date_time_rfc3399(char *buff, unsigned int len); }

typedef struct { unsigned char before[NIT_GUARD]; dm_network_t obj; unsigned char after[NIT_GUARD]; } box_t;
typedef struct {
    const char *test_name;
    const char *tz;      /* TZ value for the call */
    bool prefill;        /* fill the object with garbage first */
    int check;           /* 0 return value + timestamp format, 1 media, 2 prefill cleared, 3 timestamp is UTC (gmtime), 4 second call */
    bool crash;
} test_case_t;
extern test_case_t suite[];
extern box_t *g_box;
void construct_input(const test_case_t *tc);
int invoke(void);
void teardown(void);
}
void run_all_tests_network_init(void);
#endif
