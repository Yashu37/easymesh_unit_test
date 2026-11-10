/* hwr_wdf.h - plumbing for the sg_wifi_hal_sendDataFrame harness (src/wifi_hal.c).
 * wifi_interface_info_t is a minimal STAND-IN with the members the function uses (interface->index, interface->mac).  get_interface_by_vap_index and the socket calls (socket / bind / close / sendto)
 * are recording stubs over runner data (no raw socket is opened).  The function's three file-scope arrays (g_fd_arr, g_IfIdx_arr, g_vapSmac, MAX_VAP entries) live in the handler file; the helpers below
 * reset / preset / expose them to the runner. */
#ifndef HWR_WDF_H
#define HWR_WDF_H
#include "hwr_defs.h"
#include <stdint.h>
#define HWR_WDF_MAXI 4
#define HWR_WDF_SENT 2048
typedef struct wifi_interface_info_t { unsigned int index; mac_address_t mac; } wifi_interface_info_t;
typedef struct {
	wifi_interface_info_t ifs[HWR_WDF_MAXI];
	unsigned int vap_of[HWR_WDF_MAXI];
	int n_if, sock_fail, bind_fail, sendto_mode, next_fd;
	int socket_calls, bind_calls, close_calls, sendto_calls, last_closed_fd, last_bind_ifindex;
	int sent_len, sent_ifindex, sent_halen, sent_family, sent_proto, sent_fd;
	unsigned char sent[HWR_WDF_SENT], sent_addr[8];
} hwr_wdf_world_t;
extern hwr_wdf_world_t hwr_wdf_world;
extern "C" int hwr_sg_wifi_hal_sendDataFrame(int vap_id, unsigned char *dmac, unsigned char *data_buff, int data_len, BOOL insert_llc, int protocol, int priority);
extern "C" void hwr_wdf_reset_statics(void);
extern "C" void hwr_wdf_preset(int vap_id, int fd, int ifidx, const unsigned char *smac);
extern "C" void hwr_wdf_statics(int **fd, int **idx, unsigned char (**smac)[6], int *max_vap);
typedef struct {
	const char *test_name;
	int vap_id;
	int no_iface;                  /* get_interface_by_vap_index() finds nothing */
	int cached;                    /* g_fd_arr[vap_id] already holds an open socket (and its index / MAC) */
	int sock_fail, bind_fail;
	int dmac_null, data_null;
	int data_len;
	int protocol;
	int sendto_mode;               /* 0 returns the length, 1 returns -1, 2 returns length - 1 */
	int last;                      /* 1: input that crashes the original, run LAST */
} hwr_wdf_case_t;
extern hwr_wdf_case_t sg_wifi_hal_sendDataFrame_suite[];
extern "C" void run_all_tests_sg_wifi_hal_sendDataFrame(void);
#endif
