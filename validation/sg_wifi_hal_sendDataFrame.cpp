/*
 * HANDLER: wifi_hal_sendDataFrame (src/wifi_hal.c)
 *
 * Function copied from rdk-wifi-hal (verbatim apart from fixes 1-4): src/wifi_hal.c:2400-2458 (~/Desktop/G/rdk-wifi-hal) together with its three file-scope arrays (src/wifi_hal.c:105-107).  This file holds the ORIGINAL code with fixes 1-4 applied (start fix n / end fix n markers; the unfixed copy is the reproducer).  It builds an Ethernet frame (source MAC of the VAP, destination dmac, ether type, data) in the 1600-byte stack buffer t_data, opens (once per vap_id) an AF_PACKET raw socket bound to the interface of
 * the VAP and sends the frame with sendto().  The length check is t_len = data_len + sizeof(struct ether_header) compared with sizeof(t_data) (unsigned), vap_id indexes the arrays unchecked, dmac and
 * data_buff are not checked.
 *
 * Scaffolding only: get_interface_by_vap_index / socket / bind / close / sendto are recording stubs over the runner's world (no real socket); the helpers hwr_wdf_reset_statics / preset / statics give the runner
 * access to the static arrays; the *_print macros go to the log sink hwr_print.  Renamed hwr_sg_wifi_hal_sendDataFrame.
 */
#include "hwr_wdf.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

#define MAC_ADDRESS_LEN 6
#define wifi_hal_dbg_print(format, ...)          hwr_print(0, format, ##__VA_ARGS__)
#define get_interface_by_vap_index hwr_wdf_get_interface_by_vap_index
#define socket hwr_wdf_socket
#define bind hwr_wdf_bind
#define close hwr_wdf_close
#define sendto hwr_wdf_sendto
#define wifi_hal_sendDataFrame hwr_sg_wifi_hal_sendDataFrame

hwr_wdf_world_t hwr_wdf_world;

/* src/wifi_hal.c:105-107 */
static int g_fd_arr[MAX_VAP] = {0};
static int g_IfIdx_arr[MAX_VAP] = {0};
static unsigned char g_vapSmac[MAX_VAP][MAC_ADDRESS_LEN] = {'\0'};

extern "C" {
void hwr_wdf_reset_statics(void) { memset(g_fd_arr, 0, sizeof(g_fd_arr)); memset(g_IfIdx_arr, 0, sizeof(g_IfIdx_arr)); memset(g_vapSmac, 0, sizeof(g_vapSmac)); }
void hwr_wdf_preset(int vap_id, int fd, int ifidx, const unsigned char *smac) { g_fd_arr[vap_id] = fd; g_IfIdx_arr[vap_id] = ifidx; memcpy(g_vapSmac[vap_id], smac, 6); }
void hwr_wdf_statics(int **fd, int **idx, unsigned char (**smac)[6], int *max_vap) { *fd = g_fd_arr; *idx = g_IfIdx_arr; *smac = g_vapSmac; *max_vap = MAX_VAP; }
wifi_interface_info_t *get_interface_by_vap_index(unsigned int vap_index)
{
    for (int k = 0; k < hwr_wdf_world.n_if; k++) if (hwr_wdf_world.vap_of[k] == vap_index) return &hwr_wdf_world.ifs[k];
    return NULL;
}
int socket(int domain, int type, int protocol)
{
    hwr_wdf_world.socket_calls++;
    return hwr_wdf_world.sock_fail ? -1 : hwr_wdf_world.next_fd;
}
int bind(int fd, const struct sockaddr *addr, socklen_t len)
{
    hwr_wdf_world.bind_calls++;
    hwr_wdf_world.last_bind_ifindex = ((const struct sockaddr_ll *)addr)->sll_ifindex;
    return hwr_wdf_world.bind_fail ? -1 : 0;
}
int close(int fd) { hwr_wdf_world.close_calls++; hwr_wdf_world.last_closed_fd = fd; return 0; }
ssize_t sendto(int fd, const void *buf, size_t len, int flags, const struct sockaddr *addr, socklen_t alen)
{
    const struct sockaddr_ll *a = (const struct sockaddr_ll *)addr;
    hwr_wdf_world_t *w = &hwr_wdf_world;
    w->sendto_calls++; w->sent_fd = fd; w->sent_len = (int)len;
    if (len <= HWR_WDF_SENT) memcpy(w->sent, buf, len);
    w->sent_ifindex = a->sll_ifindex; w->sent_halen = a->sll_halen; w->sent_family = a->sll_family; w->sent_proto = a->sll_protocol;
    memcpy(w->sent_addr, a->sll_addr, 8);
    return w->sendto_mode == 1 ? -1 : (w->sendto_mode == 2 ? (ssize_t)len - 1 : (ssize_t)len);
}

/* --- wifi_hal.c:2400-2458 --- */
INT wifi_hal_sendDataFrame( int vap_id, unsigned char *dmac, unsigned char *data_buff, int data_len, BOOL insert_llc, int protocol, int priority)
{
    struct sockaddr_ll addr;
    struct ether_header *ethHdr;
    unsigned int t_data[1600/4];
    int t_len=0;
    wifi_interface_info_t *interface = NULL;
    wifi_hal_dbg_print("Entering for %s:%d:for : %d\n", __func__, __LINE__, vap_id);

    /* ---------- start fix 1: a negative data_len (-14..-1) passed the unsigned length check below and reached memcpy. */
    if (data_len < 0) {
        return RETURN_ERR;
    }
    /* ---------- end fix 1 */
    /* ---------- start fix 2: vap_id indexed g_fd_arr / g_IfIdx_arr / g_vapSmac (MAX_VAP entries) unchecked. */
    if (vap_id < 0 || vap_id >= MAX_VAP) {
        return RETURN_ERR;
    }
    /* ---------- end fix 2 */
    /* ---------- start fix 3: a NULL dmac was dereferenced by memcpy. */
    if (dmac == NULL) {
        return RETURN_ERR;
    }
    /* ---------- end fix 3 */
    /* ---------- start fix 4: a NULL data_buff with data_len > 0 was dereferenced by memcpy. */
    if (data_buff == NULL && data_len > 0) {
        return RETURN_ERR;
    }
    /* ---------- end fix 4 */

    if ((t_len = (data_len + sizeof(struct ether_header))) > sizeof(t_data))
         return RETURN_ERR;

    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ALL);

    if(g_fd_arr[vap_id] <= 0 ) {
        g_fd_arr[vap_id] = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (g_fd_arr[vap_id] < 0)
            return RETURN_ERR;

        interface = get_interface_by_vap_index((unsigned int)vap_id);
        if (interface != NULL) {
            g_IfIdx_arr[vap_id] = interface->index;
            memcpy(&g_vapSmac[vap_id][0], interface->mac, sizeof(mac_address_t));
        } else {
            close(g_fd_arr[vap_id]);
            g_fd_arr[vap_id] = -1;
            g_IfIdx_arr[vap_id] = -1;
            return RETURN_ERR;
        }

        addr.sll_ifindex = g_IfIdx_arr[vap_id];
        if (bind(g_fd_arr[vap_id], (const struct sockaddr *)&addr, sizeof(addr)) < 0) {
            close(g_fd_arr[vap_id]);
            g_fd_arr[vap_id] = -1;
            g_IfIdx_arr[vap_id] = -1;
            return RETURN_ERR;
        }
    }

    ethHdr = (struct ether_header *) t_data;
    memcpy(ethHdr->ether_shost, &g_vapSmac[vap_id][0], sizeof(mac_address_t));
    memcpy(ethHdr->ether_dhost, dmac, sizeof(mac_address_t));
    ethHdr->ether_type = htons(protocol);
    ethHdr++;

    memcpy((void *)ethHdr, data_buff, data_len);
    t_len = sizeof(struct ether_header) + data_len;

    addr.sll_ifindex = g_IfIdx_arr[vap_id];
    addr.sll_halen = ETH_ALEN;
    memcpy(addr.sll_addr, dmac, ETH_ALEN);

    if (sendto(g_fd_arr[vap_id], t_data, t_len, 0, (struct sockaddr *)&addr, sizeof(addr)) == t_len) {
        return RETURN_OK;
    }
    return RETURN_ERR;
}
}
