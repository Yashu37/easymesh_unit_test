/*
 * HANDLER: nodes_listener (fixes 1-2 applied, start fix n / end fix n markers)
 *
 * Functions copied verbatim from unified-wifi-mesh src/em/em_mgr.cpp (develop @ 1ba9529): em_mgr_t::reset_listeners and
 * em_mgr_t::nodes_listener (AL_SAP is not defined, so the raw-socket branch is compiled). Local array in the loop:
 * buff[MAX_EM_BUFF_SZ * EM_MAX_BANDS] (3072 bytes). select() / read() are replaced by scripted stand-ins (macros below,
 * only for this file) and proto_process() by a stub that walks `len` bytes of the data like the real parser does, so a wrong
 * length is reported by ASan. Scaffolding: the em map is a vector, m_rset sits between poisoned guards.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include "nodes_listener.h"

namespace nls {
em_mgr_t *g_mgr = NULL;
std::vector<em_t *> g_ems;
int g_calls = 0; long g_len0 = -1; int g_nfds0 = -1; int g_sel_calls = 0;

/* scripted results, set by construct_input() */
int g_sel[NLS_MAXSCRIPT], g_nsel = 0, g_sel_i = 0;
long g_rd[NLS_MAXSCRIPT]; int g_nrd = 0, g_rd_i = 0;

void *hash_map_get_first(hash_map_t *m) { return m->v.empty() ? NULL : m->v[0]; }
void *hash_map_get_next(hash_map_t *m, void *cur)
{ for (size_t i = 0; i < m->v.size(); i++) if (m->v[i] == cur) return i + 1 < m->v.size() ? m->v[i + 1] : NULL; return NULL; }

int select_stub(int nfds, fd_set *r, fd_set *w, fd_set *e, struct timeval *tm)
{
    (void)w; (void)e; (void)tm;
    if (g_sel_calls++ == 0) g_nfds0 = nfds;
    if (g_sel_i >= g_nsel) { errno = EBADF; return -1; }
    int v = g_sel[g_sel_i++];
    if (v == -2) { errno = EINTR; return -1; }
    if (v == 3) { FD_ZERO(r); return 1; }
    return v;
}
ssize_t read_stub(int fd, void *buf, size_t n)
{
    (void)fd; (void)n;
    if (g_rd_i >= g_nrd) return 0;
    long v = g_rd[g_rd_i++];
    if (v < 0) { errno = EIO; return -1; }
    memset(buf, 0xCD, (size_t)v);
    return (ssize_t)v;
}
#define select select_stub
#define read read_stub

void em_mgr_t::proto_process(unsigned char *data, unsigned int len, em_t *em)
{
    (void)em;
    if (g_calls++ == 0) g_len0 = (long)len;
    volatile unsigned char sum = 0;
    for (unsigned int i = 0; i < len; i++) sum ^= data[i];     /* the real parser walks the frame: a bad len runs off the buffer */
}

/* --- copied verbatim from src/em/em_mgr.cpp --- */
int em_mgr_t::reset_listeners()
{
    int highest_fd = 0, num = 0;
    em_t *em = NULL;

    FD_ZERO(&m_rset);

	pthread_mutex_lock(&m_mutex);
    em = static_cast<em_t *>(hash_map_get_first(m_em_map));
    while (em != NULL) {
/* start fix 2 */
        if (em->is_al_interface_em() == true && em->get_fd() >= 0 && em->get_fd() < FD_SETSIZE) {
/* end fix 2 */
            FD_SET(em->get_fd(), &m_rset);
            num++;
            highest_fd = (em->get_fd() > highest_fd) ? em->get_fd():highest_fd;
        }
        em = static_cast<em_t *>(hash_map_get_next(m_em_map, em));
    }
	pthread_mutex_unlock(&m_mutex);
    return highest_fd;

}

void em_mgr_t::nodes_listener()
{
    em_t *em = NULL;
    struct timeval tm;
    int rc, highest_fd = 0;

    tm.tv_sec = 0;
    tm.tv_usec = m_timeout * 1000;
    highest_fd = reset_listeners();

    while ((rc = select(highest_fd + 1, &m_rset, NULL, NULL, &tm)) >= 0) {
        if (rc == 0) {
            tm.tv_sec = 0;
            tm.tv_usec = m_timeout * 1000;
            highest_fd = reset_listeners();

            continue;
        }

        em = static_cast<em_t *>(hash_map_get_first(m_em_map));
        while (em != NULL) {
            if (em->is_al_interface_em() == true) {
#ifdef AL_SAP
                try{
                    AlServiceDataUnit sdu = g_sap->serviceAccessPointDataIndication();
                    std::vector<unsigned char> payload = sdu.getPayload();
                    // Original implementation expects whole ethernet frame
                    // not just CMDU, so we have to reconstruct it
                    std::vector<unsigned char> reconstructed_eth_frame;
                    auto first_mac = sdu.getSourceAlMacAddress();
                    reconstructed_eth_frame.insert(reconstructed_eth_frame.end(),first_mac.begin(),first_mac.end());
                    auto second_mac = sdu.getDestinationAlMacAddress();
                    reconstructed_eth_frame.insert(reconstructed_eth_frame.end(),second_mac.begin(),second_mac.end());

                    reconstructed_eth_frame.push_back(0x89);
                    reconstructed_eth_frame.push_back(0x3A);

                    reconstructed_eth_frame.insert(reconstructed_eth_frame.end(),payload.begin(),payload.end());
#ifdef DEBUG_MODE
                    em_printfout("First MAC Address: " MACSTRFMT, MAC2STR(first_mac));
                    em_printfout("Second MAC Address: " MACSTRFMT, MAC2STR(second_mac));
                    em_printfout("RECONSTRUCTED_ETH_FRAME: \t");
                    util::print_hex_dump(reconstructed_eth_frame);
#endif
                    proto_process(reconstructed_eth_frame.data(), static_cast<unsigned int>(reconstructed_eth_frame.size()), em);
                } catch (const AlServiceException& e) {
                    if (e.getPrimitiveError() == PrimitiveError::InvalidMessage) {
                        em_printfout("%s. Dropping packet", e.what());
                    } else {
                        em_printfout("%s", e.what());
                        throw e; // rethrow the exception if it's not an indication failure
                    }
                }
#else
                unsigned char buff[MAX_EM_BUFF_SZ*EM_MAX_BANDS];
                pthread_mutex_lock(&m_mutex);
                /* start fix 2 */
                int ret = (em->get_fd() >= 0 && em->get_fd() < FD_SETSIZE) ? FD_ISSET(em->get_fd(), &m_rset) : 0;
/* end fix 2 */
                pthread_mutex_unlock(&m_mutex);
                if (ret)
                {
                    // receive data from this interface
                    memset(buff, 0, MAX_EM_BUFF_SZ*EM_MAX_BANDS);
                    ssize_t len = read(em->get_fd(), buff, MAX_EM_BUFF_SZ*EM_MAX_BANDS);
/* start fix 1 */
                    if (len > 0) {
/* end fix 1 */
                        proto_process(buff, static_cast<unsigned int>(len), em);
                    }
                }
#endif //AL_SAP not defined.
            }
            em = static_cast<em_t *>(hash_map_get_next(m_em_map, em));
        }
        tm.tv_sec = 0;
        tm.tv_usec = m_timeout * 1000;
        highest_fd = reset_listeners();

    }
}
#undef select
#undef read

void invoke(void) { g_mgr->nodes_listener(); }
} /* namespace nls */
