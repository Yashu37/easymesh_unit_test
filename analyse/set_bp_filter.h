/* set_bp_filter harness types (namespace sbf). Own header, kept out of common.h so `make` stays incremental. */
#ifndef SET_BP_FILTER_H
#define SET_BP_FILTER_H
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/socket.h>
#include <linux/filter.h>
#include <linux/if_packet.h>
#include "common.h"

namespace sbf {
#define SBF_GUARD 256            /* poisoned bytes before / after m_ruid */
#ifndef ETH_P_1905
#define ETH_P_1905 0x893a
#endif
typedef char em_interface_name_t[32];
typedef unsigned char mac_address_t[6];
typedef struct { em_interface_name_t name; mac_address_t mac; int media; } __attribute__((__packed__)) em_interface_t;

class em_t {
public:
    unsigned char before_ruid[SBF_GUARD];     /* members in front of m_ruid */
    int m_fd;
    em_interface_t m_ruid;
    unsigned char after_ruid[SBF_GUARD];      /* members behind m_ruid */
    int set_bp_filter();
};

#define SBF_MAXCALLS 4
typedef struct { int level, optname; int len; struct sock_filter insn[8]; int ifindex, mr_type; int fd; } sso_rec_t;

typedef struct {
    const char *test_name;
    const char *name;        /* interface name; NULL = 32 non-NUL characters (no terminator) */
    int fd;
    int sso[2];              /* setsockopt results: filter attach, membership (0 ok, -1 fail) */
    int ifindex;             /* what if_nametoindex() returns */
    int expect_ret;
    int expect_calls;        /* setsockopt calls */
    int expect_close;        /* close() calls */
    int expect_ifindex;      /* mr_ifindex of the membership request, -1 unchecked */
    int expect_fd_after;     /* m_fd afterwards, -2 unchecked, -1 = must be reset after close */
    bool check_filter;       /* compare the attached program with the expected 4 instructions */
    bool crash;
} test_case_t;

extern test_case_t suite[];
extern em_t *g_em;
extern sso_rec_t g_rec[SBF_MAXCALLS]; extern int g_ncalls, g_nclose, g_close_fd, g_ret;
void construct_input(const test_case_t *tc);
void invoke(void);
void teardown(void);
}
void run_all_tests_set_bp_filter(void);
#endif
