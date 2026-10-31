/*
 * TEST CASES / CONSTRUCTOR: construct_file_get
 *
 * file_get(path) reads the whole file into a heap buffer, 4096 bytes at a
 * time through a local hunk[4096]. The cases create temp files of sizes
 * chosen to stress the hunk boundary and the realloc/memcpy loop: empty,
 * small, exactly one hunk, one-past a hunk, two hunks, and a large
 * multi-hunk file. A missing path exercises the open()-failure branch.
 *
 * size == -1 means "do not create the file" (missing-file case).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

char        fileget_path[256];      /* path handed to file_get()        */
const char *fileget_case_name;
ssize_t     fileget_make_size;      /* <0 => leave missing              */

file_get_test_case_t file_get_suite[] = {
    /* name              size (bytes)   expected_null (1 = expect NULL) */
    { "empty_file",          0,          1 },   /* read()==0 first -> buf stays NULL */
    { "small_10",            10,         0 },
    { "exactly_one_hunk",    4096,       0 },   /* fills hunk, next read == 0 */
    { "one_past_hunk",       4097,       0 },   /* 2nd read returns 1 byte    */
    { "two_hunks",           8192,       0 },
    { "large_multi_hunk",    100000,     0 },   /* ~25 realloc/memcpy rounds  */
    { "missing_file",        -1,         1 },

    { NULL, 0, 0 }  /* sentinel */
};

/* Create (or remove) this case's file and set fileget_path. */
void construct_file_get_input(const file_get_test_case_t *tc)
{
    fileget_case_name = tc->test_name;
    fileget_make_size = tc->size;

    snprintf(fileget_path, sizeof(fileget_path), "/tmp/fileget_%s.dat", tc->test_name);

    /* always start clean */
    remove(fileget_path);

    if (tc->size < 0)
        return;  /* missing-file case: leave it absent */

    FILE *f = fopen(fileget_path, "wb");
    if (!f) { perror("fopen"); return; }
    for (ssize_t i = 0; i < tc->size; i++)
        fputc('A' + (int)(i % 26), f);
    fclose(f);
}
