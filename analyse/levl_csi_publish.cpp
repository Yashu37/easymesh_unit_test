/*
 * HANDLER: levl_csi_publish
 *
 * Copied VERBATIM from OneWifi source/apps/levl/wifi_levl.c (no changes).
 * Local array:
 *   - char eventName[MAX_EVENT_NAME_SIZE] : strncpy(..., sizeof(eventName) - 1)
 *     of a fixed 31-char name, so it is bounded.
 * The function also builds the CSI header inside the caller's
 * csi_dev_data->header (CSI_HEADER_SIZE = 30 bytes): "CSI\0" + total_length +
 * time_t + num_clients + sta_mac(6) + csi_data_length writes exactly 30 bytes,
 * and then publishes/writes CSI_HEADER_SIZE + sizeof(wifi_csi_data_t) bytes
 * starting at the header (header and csi are adjacent in the packed struct).
 * -> SAFE (header fits exactly; the read ends at the struct end).
 *
 * Scaffolding (NOT under test): get_wifictrl_obj / get_app_by_inst return the
 * lcp_* buffers; get_bus_descriptor()->bus_raw_event_publish_fn and open() /
 * write() (for the FIFO path) are recording stubs that copy the published
 * bytes into lcp_sink.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include "common.h"

#define WIFI_APPS 0
#ifndef wifi_util_dbg_print
#define wifi_util_dbg_print(m, ...) do {} while (0)
#endif
#define wifi_util_error_print(m, ...) do {} while (0)
#define wifi_app_inst_levl 5
#ifndef MAX_EVENT_NAME_SIZE
#define MAX_EVENT_NAME_SIZE 200
#endif
#define CSI_LEVL_PIPE "/tmp/csi_levl_pipe"

typedef struct { int (*bus_raw_event_publish_fn)(void *handle, const char *name, void *data, unsigned int len); } wifi_bus_desc_t;
static int lcp_bus_publish(void *handle, const char *name, void *data, unsigned int len)
{
    (void)handle;
    lcp_pub_calls++;
    snprintf(lcp_pub_name, sizeof(lcp_pub_name), "%s", name);
    lcp_pub_len = len;
    memcpy(lcp_sink, data, len);                 /* reads exactly len bytes from the header start */
    return 0;
}
static wifi_bus_desc_t lcp_desc = { lcp_bus_publish };
static wifi_bus_desc_t *get_bus_descriptor(void) { return &lcp_desc; }
static wifi_ctrl_t *get_wifictrl_obj(void) { return (wifi_ctrl_t *)lcp_ctrl_buf; }
static wifi_app_t *get_app_by_inst(wifi_apps_mgr_t *m, int inst) { (void)m; (void)inst; return lcp_null_app ? NULL : (wifi_app_t *)lcp_app_buf; }
static int lcp_open(const char *path, int flags) { (void)path; (void)flags; lcp_open_calls++; return lcp_open_ret; }
static long lcp_write(int fd, const void *buf, unsigned long n)
{
    (void)fd;
    lcp_write_calls++; lcp_write_len = (unsigned int)n;
    memcpy(lcp_sink, buf, n);                    /* reads exactly n bytes from the header start */
    return (long)n;
}
#define open(p, f)        lcp_open((p), (f))
#define write(fd, b, n)   lcp_write((fd), (b), (n))

/* ================= VERBATIM from wifi_levl.c ================= */
void levl_csi_publish(mac_address_t mac_address, wifi_csi_dev_t *csi_dev_data)
{
    char eventName[MAX_EVENT_NAME_SIZE];
    wifi_app_t *wifi_app = NULL;
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    wifi_apps_mgr_t *apps_mgr;
    apps_mgr = &ctrl->apps_mgr;
    wifi_app = get_app_by_inst(apps_mgr, wifi_app_inst_levl);
    if (wifi_app == NULL) {
        wifi_util_error_print(WIFI_APPS, "%s:%d NULL wifi_app pointer\n", __func__, __LINE__);
        return;
    }
    // Construct Header.
    unsigned int total_length, num_csi_clients, csi_data_length, curr_length = 0;
    time_t datetime;
    char *header = csi_dev_data->header;
    memcpy(header, "CSI", (strlen("CSI") + 1));
    curr_length = curr_length + strlen("CSI") + 1;
    total_length = sizeof(time_t) + (sizeof(unsigned int)) +
        (1 * (sizeof(mac_addr_t) + sizeof(unsigned int) + sizeof(wifi_csi_data_t)));
    memcpy((header + curr_length), &total_length, sizeof(unsigned int));
    curr_length = curr_length + sizeof(unsigned int);
    datetime = time(NULL);
    memcpy((header + curr_length), &datetime, sizeof(time_t));
    curr_length = curr_length + sizeof(time_t);
    num_csi_clients = 1;
    memcpy((header + curr_length), &num_csi_clients, sizeof(unsigned int));
    curr_length = curr_length + sizeof(unsigned int);
    memcpy((header + curr_length), csi_dev_data->sta_mac, sizeof(mac_addr_t));
    curr_length = curr_length + sizeof(mac_addr_t);
    csi_data_length = sizeof(wifi_csi_data_t);
    memcpy((header + curr_length), &csi_data_length, sizeof(unsigned int));
    int buffer_size = CSI_HEADER_SIZE + sizeof(wifi_csi_data_t);
    wifi_util_dbg_print(WIFI_APPS,
        "%s:%d publish mac:%02x..%02x fifo:%d\n",
        __func__, __LINE__, mac_address[0], mac_address[5], wifi_app->data.u.levl.csi_over_fifo);
    if (wifi_app->data.u.levl.csi_over_fifo == false) {
        strncpy(eventName, "Device.WiFi.X_RDK_CSI_LEVL.data", sizeof(eventName) - 1);
        // Publish using new API
        get_bus_descriptor()->bus_raw_event_publish_fn(&wifi_app->handle, eventName, csi_dev_data->header, buffer_size);
    } else {
        if (wifi_app->data.u.levl.csi_fd < 0) {
            wifi_app->data.u.levl.csi_fd = open(CSI_LEVL_PIPE, O_WRONLY);
            if (wifi_app->data.u.levl.csi_fd < 0) {
                wifi_util_error_print(WIFI_APPS, "%s(): Failed to open pipe reason %s\n", __func__,
                    strerror(errno));
                return;
            }
        }
        if ((write(wifi_app->data.u.levl.csi_fd, header, buffer_size) < 0)) {
            wifi_util_error_print(WIFI_APPS, "%s:%d Messed up write error is %s\n", __func__,
                __LINE__, strerror(errno));
            return;
        }
    }

    return;
}
