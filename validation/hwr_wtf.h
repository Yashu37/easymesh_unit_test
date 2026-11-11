/* hwr_wtf.h - plumbing for the sg_wifi_anqpTestFrameHandler harness (src/wifi_hal_anqp.c).
 * The function is a receive loop over a UDP socket bound to 127.0.0.1:8889.  socket / bind / select / recvfrom / close / prctl are scripted stubs: the runner queues up to 3 datagrams; select reports
 * "readable" while one is queued (optionally a timeout and a failing recvfrom first) and then fails, which ends the loop.  wifi_tlv_t / wifi_test_command_id_t / wifi_test_attrib_t are declared exactly like
 * wifi_hal_rdk.h, get_tlv is the REAL wifi_tlv.c:29-46 copied verbatim into the handler file, mgmt_frame_received_callback is a recording stub, wifi_anqp_dbg_print a no-op. */
#ifndef HWR_WTF_H
#define HWR_WTF_H
#include "hwr_defs.h"
#include <stddef.h>
typedef struct { unsigned short type; unsigned short length; unsigned char value[0]; } __attribute__((packed)) wifi_tlv_t;
typedef enum {
    wifi_test_command_id_mgmt = 0x1010, wifi_test_command_id_action, wifi_test_command_id_probe_req, wifi_test_command_id_probe_rsp, wifi_test_command_id_assoc_req, wifi_test_command_id_assoc_rsp,
    wifi_test_command_id_auth, wifi_test_command_id_deauth, wifi_test_command_id_data = 0x1050, wifi_test_command_id_8021x, wifi_test_command_id_ctl = 0x10a0, wifi_test_command_id_chirp,
    wifi_test_command_id_anqp, wifi_test_command_id_reconf_auth_resp,
} wifi_test_command_id_t;
typedef enum { wifi_test_attrib_cmd, wifi_test_attrib_vap_name, wifi_test_attrib_sta_mac, wifi_test_attrib_direction, wifi_test_attrib_raw } wifi_test_attrib_t;
typedef struct { int type; unsigned len; int val; } hwr_wtf_tlv_t;   /* type: wifi_test_attrib_t or 99 (filler); val: cmd id (0 = anqp) / ap index (-1: "eth0") / pattern seed */
typedef struct {
	int sig_ok; int n; hwr_wtf_tlv_t t[5];
	unsigned total;                /* pad with filler TLVs (type 99, length 0) up to this many bytes (0: none) */
	unsigned cut;                  /* > 0: only the first cut bytes are sent */
} hwr_wtf_dg_t;
#define HWR_WTF_MAXCB 4
typedef struct {
	hwr_wtf_dg_t dg[3]; int ndg;
	unsigned char dgbuf[3][1100]; unsigned dglen[3]; int next;
	int socket_fail, bind_fail, sel0, recvfail, sel0_done, recv_done, closes, binds, prctl_calls;
	int cb_calls; int cb_ap[HWR_WTF_MAXCB]; unsigned char cb_mac[HWR_WTF_MAXCB][6]; unsigned char cb_frame[HWR_WTF_MAXCB][128]; unsigned cb_len[HWR_WTF_MAXCB]; int cb_type[HWR_WTF_MAXCB], cb_dir[HWR_WTF_MAXCB];
	void *unrelated[4];            /* poisoned: the function must not touch it */
} hwr_wtf_world_t;
extern hwr_wtf_world_t hwr_wtf_world;
extern "C" void *hwr_sg_wifi_anqpTestFrameHandler(void *arg);
typedef struct {
	const char *test_name;
	int ndg; hwr_wtf_dg_t dg[3];
	int socket_fail, bind_fail, sel0, recvfail;
	int chk_len;                   /* 1: also require the frame length passed to the callback to be the raw TLV length */
	int last;                      /* 1: input that crashes the original, run LAST */
} hwr_wtf_case_t;
extern hwr_wtf_case_t sg_wifi_anqpTestFrameHandler_suite[];
extern "C" void run_all_tests_sg_wifi_anqpTestFrameHandler(void);
#endif
