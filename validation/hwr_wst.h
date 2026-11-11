/* hwr_wst.h - plumbing for the sg_wifi_anqpStartTest harness (src/wifi_hal_anqp.c).
 * The function builds one test datagram (signature + command / vap name / station mac / raw ANQP TLVs) and sends it by UDP to 127.0.0.1:8889.  socket / sendto / close are recording stubs (macros in the
 * handler file); wifi_tlv_t / wifi_test_command_id_t / wifi_test_attrib_t are declared exactly like wifi_hal_rdk.h and set_tlv is the REAL wifi_tlv.c:49-58 copied verbatim into the handler file;
 * wifi_anqp_dbg_print is a no-op; mac_address_t / IFNAMSIZ are the real types. */
#ifndef HWR_WST_H
#define HWR_WST_H
#include "hwr_defs.h"
#include <stddef.h>
typedef struct { unsigned short type; unsigned short length; unsigned char value[0]; } __attribute__((packed)) wifi_tlv_t;
typedef enum {
    wifi_test_command_id_mgmt = 0x1010, wifi_test_command_id_action, wifi_test_command_id_probe_req, wifi_test_command_id_probe_rsp, wifi_test_command_id_assoc_req, wifi_test_command_id_assoc_rsp,
    wifi_test_command_id_auth, wifi_test_command_id_deauth, wifi_test_command_id_data = 0x1050, wifi_test_command_id_8021x, wifi_test_command_id_ctl = 0x10a0, wifi_test_command_id_chirp,
    wifi_test_command_id_anqp, wifi_test_command_id_reconf_auth_resp,
} wifi_test_command_id_t;
typedef enum { wifi_test_attrib_cmd, wifi_test_attrib_vap_name, wifi_test_attrib_sta_mac, wifi_test_attrib_direction, wifi_test_attrib_raw } wifi_test_attrib_t;
typedef struct {
	int socket_fail, send_fail;
	int socket_calls, sendto_calls, closes;
	int sock_domain, sock_type, sock_proto;
	unsigned char sent[1100]; long sent_len; unsigned sent_addr_family, sent_port, sent_ip;
	void *unrelated[4];            /* poisoned: the function must not touch it */
} hwr_wst_world_t;
extern hwr_wst_world_t hwr_wst_world;
extern "C" INT hwr_sg_wifi_anqpStartTest(unsigned int apIndex, mac_address_t sta);
typedef struct {
	const char *test_name;
	unsigned ap;
	int sta_null;
	int sta_pattern;               /* station mac: 0 zeros, 1 broadcast, 2 distinct bytes */
	int socket_fail, send_fail;
	int calls;                     /* 1 or 2 consecutive calls (the second one with ap + 1) */
	int last;                      /* 1: input that crashes the original, run LAST */
} hwr_wst_case_t;
extern hwr_wst_case_t sg_wifi_anqpStartTest_suite[];
extern "C" void run_all_tests_sg_wifi_anqpStartTest(void);
#endif
