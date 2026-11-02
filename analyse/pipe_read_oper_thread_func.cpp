/*
 * HANDLER: pipe_read_oper_thread_func
 *
 * Function copied VERBATIM from OneWifi source/apps/csi/wifi_csi_analytics.c.
 * No fixes. Local arrays: fifo_path[64] (snprintf, bounded) and a VLA
 * buffer[buffer_len] (buffer_len = CSI_HEADER_SIZE + sizeof(wifi_csi_data_t)),
 * filled by read(fd, buffer, sizeof(buffer)) -- bounded by sizeof(buffer).
 *
 * Driven with a real regular file at the computed path, so open() succeeds,
 * read() returns the bytes once then 0 (EOF) and the loop exits (no blocking).
 * Redirect: snprintf()->prt slot(64) for fifo_path; the RUNNER poisons that
 * slot past 64 and the caller p_app past its size. fifo_path / the VLA buffer
 * are ASan-stack guarded (read/memset ASan-intercepted).
 *
 * Scaffolding (NOT the function under test): decode_csi_pipe_msg,
 * process_csi_analytics_data, clean_all_csi_analytics_data are file-local stubs.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include "common.h"

#define WIFI_APPS 0
#define CSI_HEADER_SIZE (4 + sizeof(unsigned int) + sizeof(time_t) + (sizeof(unsigned int)) + (1 *((sizeof(unsigned char)*6) + sizeof(unsigned int))))

static void prt_print(int m,const char*f,...){char sc[512];va_list ap;(void)m;va_start(ap,f);vsnprintf(sc,sizeof(sc),f,ap);va_end(ap);}
#define wifi_util_info_print  prt_print
#define wifi_util_error_print prt_print
static int  decode_csi_pipe_msg(uint8_t*d,wifi_csi_dev_t*p){(void)d;(void)p;prt_decode_calls++;return 0;}
static void process_csi_analytics_data(wifi_app_t*a,wifi_csi_dev_t*c){(void)a;(void)c;prt_process_calls++;}
static void clean_all_csi_analytics_data(wifi_app_t*a){(void)a;prt_clean_calls++;}
static int prt_snprintf(char*out,size_t sz,const char*fmt,...){int r;va_list ap;if(sz>PRT_PATH_SZ)sz=PRT_PATH_SZ;memset(prt_slot,0,sz);va_start(ap,fmt);r=vsnprintf(prt_slot,sz,fmt,ap);va_end(ap);memcpy(out,prt_slot,sz);return r;}
#define snprintf(o,n,...) prt_snprintf((o),(n),__VA_ARGS__)

/* --- copied verbatim from source/apps/csi/wifi_csi_analytics.c --- */
void *pipe_read_oper_thread_func(void *arg)
{
    wifi_app_t *p_app = (wifi_app_t *)arg;
    csi_analytics_info_t *p_info = &p_app->data.u.csi_analytics;
    int buffer_len = CSI_HEADER_SIZE + sizeof(wifi_csi_data_t);
    char buffer[buffer_len];
    char fifo_path[64] = { 0 };

    snprintf(fifo_path, sizeof(fifo_path), "/tmp/csi_motion_pipe%d", p_info->csi_session_index);
    wifi_util_info_print(WIFI_APPS, "csi analytics file open path:%s\n", fifo_path);
    int pipe_read_fd = open(fifo_path, O_RDONLY);
    if (pipe_read_fd < 0) {
        wifi_util_error_print(WIFI_APPS, "Error openning fifo for session number %d %s\n",
            p_info->csi_session_index, strerror(errno));
        return NULL;
    }
    p_info->is_read_oper_thread_enabled = true;
    p_info->pipe_read_fd = pipe_read_fd;

    while (p_info->is_read_oper_thread_enabled) {
        memset(buffer, 0, sizeof(buffer));
        buffer_len = read(pipe_read_fd, buffer, sizeof(buffer));
        if (buffer_len == -1) {
            wifi_util_error_print(WIFI_APPS, "%s:%d Error:%s reading from pipe\n", __func__,
                __LINE__, strerror(errno));
            break;
        } else if (buffer_len == 0) {
            wifi_util_error_print(WIFI_APPS,
                "%s:%d Writer closed pipe. Exiting"
                " blocking reader.\n",
                __func__, __LINE__);
            break;
        } else {
            wifi_csi_dev_t csi_dev_data = { 0 };
            decode_csi_pipe_msg((uint8_t *)buffer, &csi_dev_data);
            process_csi_analytics_data(p_app, &csi_dev_data);
        }
    }

    if (p_info->is_read_oper_thread_enabled) {
        clean_all_csi_analytics_data(p_app);
    }
    return NULL;
}
