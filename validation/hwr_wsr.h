/* hwr_wsr.h - plumbing for the sg_wifi_anqpSendResponse harness (src/wifi_hal_anqp.c, FEATURE_SUPPORT_PASSPOINT + RDK_ONEWIFI build).
 * wifi_anqp_node_t / wifi_anqp_elem_t / wifi_anqp_element_name_t / mac_address_t / wifi_GASConfiguration_t are the REAL HAL types; the frame / element structs (wifi_publicActionFrameHdr_t,
 * wifi_gasAnqpInitialResponseFrame_t, wifi_anqpResponseFrame_t, wifi_anqp_element_format_t, wifi_hs_2_anqp_element_format_t) and wifi_gas_status_code_t are declared exactly like wifi_hal_rdk.h.
 * wifi_hal_send_mgmt_frame records what would be sent; malloc / free used by the function are counting wrappers (the list handed in is owned by the function and must be released by it);
 * wifi_anqp_dbg_print is a counting stub; the static gasCfg[] lives in the handler file and is reachable through hwr_wsr_gas(). */
#ifndef HWR_WSR_H
#define HWR_WSR_H
#include "hwr_defs.h"
#include <stddef.h>
#include <stdint.h>
#define HWR_WSR_FRAMEMAX 8400
typedef struct { unsigned char cat; unsigned char action; } __attribute__((packed)) wifi_actionFrameHdr_t;
typedef wifi_actionFrameHdr_t wifi_publicActionFrameHdr_t;
typedef struct { unsigned char query_rsp_info; unsigned char adv_proto_id; } __attribute__((packed)) wifi_AnqpAdvertisementProtoTuple_t;
typedef struct { unsigned char id; unsigned char len; wifi_AnqpAdvertisementProtoTuple_t proto_tuple; } __attribute__((packed)) wifi_AnqpAdvertisementProtoElement_t;
typedef struct { unsigned char token; unsigned short status; unsigned short comeback_delay; wifi_AnqpAdvertisementProtoElement_t proto_elem; } __attribute__((packed)) wifi_gasAnqpInitialResponseFrame_t;
typedef struct { wifi_publicActionFrameHdr_t public_action_hdr; wifi_gasAnqpInitialResponseFrame_t gas_resp_body; unsigned short rsp_len; unsigned char rsp_body[0]; } __attribute__((packed)) wifi_anqpResponseFrame_t;
typedef struct { unsigned short info_id; unsigned short len; unsigned char info[0]; } __attribute__((packed)) wifi_anqp_element_format_t;
typedef struct { unsigned short info_id; unsigned short len; unsigned char oi[3]; unsigned char type; unsigned char subtype; unsigned char reserved; unsigned char payload[0]; } __attribute__((packed)) wifi_hs_2_anqp_element_format_t;
typedef enum { wifi_gas_status_success = 0, wifi_gas_advertisement_protocol_not_supported = 59, wifi_no_outstanding_gas_request = 60, wifi_gas_response_not_received_from_server = 61, wifi_gas_query_timeout = 62, wifi_gas_query_response_too_large = 63 } wifi_gas_status_code_t;
typedef struct {
	int mgmt_calls; int ap; unsigned char sta_copy[6]; const unsigned char *sta_ptr; size_t len; unsigned freq, wait;
	unsigned char frame[HWR_WSR_FRAMEMAX];
	int dbg_calls;
	int in_func, fn_mallocs, fail_at;        /* malloc call number (1-based, inside the function) that fails, 0: none */
	int live, bad_free;
	void *unrelated[4];                      /* poisoned: the function must not touch it */
} hwr_wsr_world_t;
extern hwr_wsr_world_t hwr_wsr_world;
extern "C" void *hwr_wsr_new(size_t n);      /* runner allocation (never fails, counted as live) */
extern "C" wifi_GASConfiguration_t *hwr_wsr_gas(void);
extern "C" INT hwr_sg_wifi_anqpSendResponse(UINT apIndex, mac_address_t sta, unsigned char token, wifi_anqp_node_t *head);
typedef struct { int type; int id; unsigned len; int data_null; int null_elem; } hwr_wsr_elem_t;   /* type 0 ANQP, 1 HS2, 2 neither */
typedef struct {
	const char *test_name;
	int head_null;
	int n; hwr_wsr_elem_t e[4];
	int sta_null; unsigned char token; unsigned ap;
	int malloc_fail_at;
	unsigned gas_adv, gas_lim;
	int last;                      /* 1: input that crashes the original, run LAST */
} hwr_wsr_case_t;
extern hwr_wsr_case_t sg_wifi_anqpSendResponse_suite[];
extern "C" void run_all_tests_sg_wifi_anqpSendResponse(void);
#endif
