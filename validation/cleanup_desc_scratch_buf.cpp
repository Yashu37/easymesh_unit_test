/*
 * HANDLER: cleanup_desc_scratch_buf
 *
 * Function copied from rdk-wifi-hal: hal_ipc/server/hal_ipc_processors.c:38-42
 * (~/Desktop/G/rdk-wifi-hal).  With RDK_CDS_FIX 0 it is the VERBATIM original;
 * with RDK_CDS_FIX 1 it carries FIX 1 below.
 *
 * Scaffolding only: hal_ipc_processor_desc_t is the scaffold struct from
 * common.h (real leading fields + scratch_buf / scratch_buf_size).  The
 * function is static in the original: cleanup_desc_scratch_buf_entry()
 * forwards to it so the runner can call it.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

/* 1 = with FIX 1, 0 = original unfixed function (set to 0 to reproduce the finding) */
#define RDK_CDS_FIX  1

/* --- copied from hal_ipc_processors.c:38 --- */
static void cleanup_desc_scratch_buf(struct hal_ipc_processor_desc *desc)
{
#if RDK_CDS_FIX
    /* FIX 1: desc was dereferenced unchecked. */
    if (desc == NULL) {
        return;
    }
#endif
    desc->scratch_buf_size = 0;
    desc->scratch_buf = NULL;
}

void cleanup_desc_scratch_buf_entry(hal_ipc_processor_desc_t *d) { cleanup_desc_scratch_buf(d); }
