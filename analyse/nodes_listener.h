/* nodes_listener harness types (namespace nls). Own header, kept out of common.h so `make` stays incremental. */
#ifndef NODES_LISTENER_H
#define NODES_LISTENER_H
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <sys/select.h>
#include <sys/types.h>
#include <vector>
#include "common.h"

namespace nls {
#define NLS_GUARD 1024          /* poisoned bytes before / after m_rset (FD_SET of fd >= FD_SETSIZE lands here) */
#define NLS_MAXEM 4
#define NLS_MAXSCRIPT 8
#ifndef MAX_EM_BUFF_SZ
#define MAX_EM_BUFF_SZ 1024
#endif

class em_t {
public:
    int m_fd; bool m_al;
    int get_fd() { return m_fd; }
    bool is_al_interface_em() { return m_al; }
};
typedef struct { std::vector<em_t *> v; } hash_map_t;
void *hash_map_get_first(hash_map_t *m);
void *hash_map_get_next(hash_map_t *m, void *cur);

class em_mgr_t {
public:
    unsigned char before_rset[NLS_GUARD];     /* members in front of m_rset */
    fd_set m_rset;
    unsigned char after_rset[NLS_GUARD];      /* members behind m_rset */
    unsigned int m_timeout;
    pthread_mutex_t m_mutex;
    hash_map_t *m_em_map;
    int reset_listeners();
    void nodes_listener();
    void proto_process(unsigned char *data, unsigned int len, em_t *em = NULL);
};

typedef struct { int fd; bool al; } em_spec_t;
typedef struct {
    const char *test_name;
    int sel[NLS_MAXSCRIPT];  int nsel;     /* select() results: >0 ready, 0 timeout, -2 = -1 with EINTR, 3 = ready but no fd set */
    long rd[NLS_MAXSCRIPT];  int nrd;      /* read() results (-1 = error) */
    em_spec_t ems[NLS_MAXEM]; int nems;
    int expect_calls;        /* proto_process calls */
    long expect_len0;        /* length of the first proto_process call, -1 unchecked */
    int expect_nfds;         /* nfds of the first select call, -1 unchecked */
    bool crash;
} test_case_t;

extern test_case_t suite[];
extern em_mgr_t *g_mgr;
extern std::vector<em_t *> g_ems;
extern int g_calls; extern long g_len0; extern int g_nfds0; extern int g_sel_calls;
void construct_input(const test_case_t *tc);
void invoke(void);
void teardown(void);
}
void run_all_tests_nodes_listener(void);
#endif
