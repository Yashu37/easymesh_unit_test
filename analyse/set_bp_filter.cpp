/*
 * HANDLER: set_bp_filter
 *
 * Function copied verbatim from unified-wifi-mesh src/em/em.cpp (develop @ 1ba9529), em_t::set_bp_filter.
 * Local data: struct packet_mreq mreq, static struct sock_filter bpfcode[4]. setsockopt(), if_nametoindex() and close() are
 * replaced by recording stand-ins (macros below, only for this file): setsockopt follows the scripted result, and a membership
 * request with mr_ifindex 0 fails like in the kernel (ENODEV); if_nametoindex() copies at most IFNAMSIZ bytes of the name like
 * libc does. The error path prints m_ruid.name with %s.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "set_bp_filter.h"

namespace sbf {
em_t *g_em = NULL;
sso_rec_t g_rec[SBF_MAXCALLS]; int g_ncalls = 0, g_nclose = 0, g_close_fd = -1, g_ret = 0;
int g_sso[2] = {0, 0}; unsigned int g_ifindex = 1;

int setsockopt_stub(int fd, int level, int optname, const void *optval, unsigned int optlen)
{
    if (g_ncalls < SBF_MAXCALLS) {
        sso_rec_t *r = &g_rec[g_ncalls]; memset(r, 0, sizeof(*r));
        r->fd = fd; r->level = level; r->optname = optname;
        if (optname == SO_ATTACH_FILTER && optlen == sizeof(struct sock_fprog)) {
            const struct sock_fprog *p = (const struct sock_fprog *)optval;
            r->len = p->len; for (int k = 0; k < p->len && k < 8; k++) r->insn[k] = p->filter[k];
        } else if (optname == PACKET_ADD_MEMBERSHIP && optlen == sizeof(struct packet_mreq)) {
            const struct packet_mreq *m = (const struct packet_mreq *)optval; r->ifindex = m->mr_ifindex; r->mr_type = m->mr_type;
        }
    }
    int idx = g_ncalls++;
    if (optname == PACKET_ADD_MEMBERSHIP && ((const struct packet_mreq *)optval)->mr_ifindex == 0) { errno = ENODEV; return -1; }
    if (idx < 2 && g_sso[idx] != 0) { errno = ENOBUFS; return -1; }
    return 0;
}
unsigned int if_nametoindex_stub(const char *name)
{
    char tmp[IF_NAMESIZE]; strncpy(tmp, name, IF_NAMESIZE);      /* libc copies at most IFNAMSIZ bytes */
    return g_ifindex;
}
int close_stub(int fd) { g_nclose++; g_close_fd = fd; return 0; }
#define setsockopt setsockopt_stub
#define if_nametoindex if_nametoindex_stub
#define close close_stub

/* --- copied verbatim from src/em/em.cpp --- */
int em_t::set_bp_filter()
{
    struct packet_mreq mreq;
#define OP_LDH (BPF_LD  | BPF_H   | BPF_ABS)
#define OP_LDB (BPF_LD  | BPF_B   | BPF_ABS)
#define OP_JEQ (BPF_JMP | BPF_JEQ | BPF_K)
#define OP_RET (BPF_RET | BPF_K)
    static struct sock_filter bpfcode[4] = {
        { OP_LDH, 0, 0, 12          },  // ldh [12]
        { OP_JEQ, 0, 1, ETH_P_1905  },  // jeq #0x893a, L2, L3
        { OP_RET, 0, 0, 0xffffffff,         },  // ret #0xffffffff
        { OP_RET, 0, 0, 0           },  // ret #0x0
    };
    struct sock_fprog bpf = { 4, bpfcode };

    if (setsockopt(m_fd, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf))) {
        printf("%s:%d: Error in attaching filter, err:%d\n", __func__, __LINE__, errno);
        close(m_fd);
        return -1;
    }

    memset(&mreq, 0, sizeof(mreq));
    mreq.mr_type = PACKET_MR_PROMISC;
    mreq.mr_ifindex = static_cast<int>(if_nametoindex(m_ruid.name));
    if (setsockopt(m_fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, reinterpret_cast<char *>(&mreq), sizeof(mreq))) {
        printf("%s:%d: Error setting promisuous for interface:%s, err:%d\n", __func__, __LINE__, m_ruid.name, errno);
        close(m_fd);
        return -1;
    }

    return 0;
}

#undef setsockopt
#undef if_nametoindex
#undef close

void invoke(void) { g_ret = g_em->set_bp_filter(); }
} /* namespace sbf */
