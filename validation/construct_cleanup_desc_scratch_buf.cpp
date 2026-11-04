/*
 * UNIT TEST (input constructor): construct_cleanup_desc_scratch_buf
 *
 * cleanup_desc_scratch_buf(desc) sets desc->scratch_buf_size = 0 and
 * desc->scratch_buf = NULL (the caller keeps/frees the buffer itself).
 * Nothing else in the descriptor may change.
 *
 * The suite is a table: {name, buf_kind, size, desc_offset, null_desc, calls,
 * expected}.  The runner (cleanup_desc_scratch_buf_test.cpp) builds the
 * descriptor inside the runner-owned, tail-poisoned slab hcd_desc_slab from
 * these fields, poisons, calls the function, unpoisons and verifies.
 * Inputs crossed: scratch_buf {NULL, heap, garbage pointer, pointer into the
 * slab} x scratch_buf_size {0, 1, 100, 10240, UINT_MAX}, descriptor at
 * offsets 0..3 of the slab (packed struct, unaligned access), repeated calls,
 * every other field a canary, and a NULL descriptor (forked, so the SEGV is
 * visible but does not stop the run).
 * Expected result is the SAFE contract, so a FAIL is a finding.
 */
#include <limits.h>
#include <string.h>
#include <stdio.h>
#include "common.h"

unsigned char hcd_desc_slab[sizeof(hal_ipc_processor_desc_t) + 16 + HIPC_PAD];

#define C(n, kind, sz) { "buf_" n "_size_" #sz, kind, sz, 0, 0, 1, 1 }
hcd_test_case_t cleanup_desc_scratch_buf_suite[] = {
	C("null",    HCD_BUF_NULL,    0u),
	C("null",    HCD_BUF_NULL,    1u),
	C("null",    HCD_BUF_NULL,    100u),
	C("null",    HCD_BUF_NULL,    10240u),
	C("null",    HCD_BUF_NULL,    UINT_MAX),
	C("heap",    HCD_BUF_HEAP,    0u),
	C("heap",    HCD_BUF_HEAP,    1u),
	C("heap",    HCD_BUF_HEAP,    100u),
	C("heap",    HCD_BUF_HEAP,    10240u),
	C("heap",    HCD_BUF_HEAP,    UINT_MAX),
	C("garbage", HCD_BUF_GARBAGE, 0u),
	C("garbage", HCD_BUF_GARBAGE, 1u),
	C("garbage", HCD_BUF_GARBAGE, 100u),
	C("garbage", HCD_BUF_GARBAGE, 10240u),
	C("garbage", HCD_BUF_GARBAGE, UINT_MAX),
	C("slab",    HCD_BUF_SLAB,    0u),
	C("slab",    HCD_BUF_SLAB,    1u),
	C("slab",    HCD_BUF_SLAB,    100u),
	C("slab",    HCD_BUF_SLAB,    10240u),
	C("slab",    HCD_BUF_SLAB,    UINT_MAX),
	{ "desc_offset_1_unaligned",           HCD_BUF_HEAP,    100, 1, 0, 1, 1 },
	{ "desc_offset_2_unaligned",           HCD_BUF_HEAP,    100, 2, 0, 1, 1 },
	{ "desc_offset_3_unaligned",           HCD_BUF_GARBAGE, UINT_MAX, 3, 0, 1, 1 },
	{ "desc_offset_16_end_of_pad",         HCD_BUF_HEAP,    100, 16, 0, 1, 1 },
	{ "called_twice_heap",                 HCD_BUF_HEAP,    100, 0, 0, 2, 1 },
	{ "called_three_times_garbage",        HCD_BUF_GARBAGE, UINT_MAX, 0, 0, 3, 1 },
	{ "called_twice_null_buf_size_0",      HCD_BUF_NULL,    0, 0, 0, 2, 1 },
	{ "heap_buf_not_freed_by_function",    HCD_BUF_HEAP,    10240, 0, 0, 1, 1 },
	{ "slab_buf_pointer_not_followed",     HCD_BUF_SLAB,    UINT_MAX, 0, 0, 1, 1 },
	{ "crash_null_desc",                   HCD_BUF_NULL,    0, 0, 1, 1, 1 },
	{ NULL, 0, 0, 0, 0, 0, 0 }
};
