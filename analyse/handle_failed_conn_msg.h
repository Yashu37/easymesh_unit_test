/* handle_failed_conn_msg harness types (namespace hfc). Own header, kept out of common.h. */
#ifndef HANDLE_FAILED_CONN_MSG_H
#define HANDLE_FAILED_CONN_MSG_H
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include "common.h"

namespace hfc {
#define HFC_LEFT 16          /* poisoned bytes in front of the message */
#define HFC_MSG_SZ 400
#define HFC_PAD 64
#define HFC_MAXTLV 8
#define MAX_TIMESTAMP_STRLEN 64
#define DEVICE_WIFI_DATAELEMENTS_FAILED_CONNECTION "Device.WiFi.DataElements.FailedConnectionEvent.FailedConnection!"
using ccs::raw_data_t; using ccs::bus_data_type_string;
typedef struct { unsigned short status_code; } __attribute__((__packed__)) em_status_code_t;
typedef struct { unsigned short reason_code; } __attribute__((__packed__)) em_reason_code_t;

typedef struct {
    int (*bus_event_publish_fn)(void *hdl, const char *name, raw_data_t *data);
} wifi_bus_desc_t;

extern bool g_no_desc, g_pub_fail;
extern wifi_bus_desc_t g_desc;

/* stand-ins for the data-model / message / controller classes (member bodies copied verbatim stay in handle_failed_conn_msg.cpp) */
class dm_easy_mesh_t {
public:
    static void macbytes_to_string(unsigned char *mac, char *string)
    { snprintf(string, 18, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]); }
};
class em_data_model_t { public: void *get_bus_hdl() { return NULL; } };

class em_msg_t {
    em_msg_type_t m_type;
    em_profile_type_t m_profile;
    unsigned int m_num_tlv;
    em_tlv_member_t m_tlv_member[EM_MAX_TLV_MEMBERS];
    unsigned int m_num_errors;
    em_short_string_t m_errors[EM_MAX_TLV_MEMBERS];
    unsigned char *m_buff;
    unsigned int m_len;
public:
    em_msg_t(em_msg_type_t type, em_profile_type_t profile, unsigned char *tlvs, unsigned int len)
    {   m_type = type; m_profile = profile; m_num_tlv = 0; m_buff = tlvs; m_len = len; m_num_errors = 0;
        if (type == em_msg_type_failed_conn) failed_conn(); }
    unsigned int validate(char *errors[]);
    void failed_conn();
};
class em_ctrl_t {
public:
    em_data_model_t m_data_model;
    wifi_bus_desc_t *get_bus_descriptor() { return g_no_desc ? NULL : &g_desc; }
    void handle_failed_conn_msg(unsigned char *data, unsigned int len);
};


typedef struct {
    unsigned char type;
    unsigned short len;              /* the length FIELD of the TLV (host order) */
    const unsigned char *val;
    unsigned short nval;             /* value bytes really present in the message */
} tlv_spec_t;

typedef struct {
    const char *test_name;
    tlv_spec_t tlvs[HFC_MAXTLV];     /* type 0xff ends the list */
    int cut;                         /* bytes removed from the end of the message (len passed is smaller) */
    int short_len;                   /* >0: pass this len instead (below the header size) */
    bool no_desc;                    /* get_bus_descriptor() returns NULL */
    bool pub_fail;                   /* publish returns non-zero */
    int expect_pub;                  /* number of published events (0/1) */
    const char *has;                 /* substring of the (whitespace-stripped) published JSON */
    const char *not_has;
    bool crash;
} test_case_t;

extern test_case_t suite[];
extern unsigned char msg_store[HFC_LEFT + HFC_MSG_SZ + HFC_PAD];
extern unsigned int g_len;           /* len passed to the handler */
extern unsigned char *g_msg;         /* data passed to the handler */
extern int g_npub;
extern char g_pub[2048];
extern bool g_no_desc, g_pub_fail;
void construct_input(const test_case_t *tc);
void invoke(void);
void teardown(void);
}
void run_all_tests_handle_failed_conn_msg(void);
#endif
