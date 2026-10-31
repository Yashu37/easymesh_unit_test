/*
 * TEST CASES / CONSTRUCTOR: construct_ds_tree_node_str
 *
 * ds_tree_node_str(root, node) returns either root->ot_str_fn(node) or a
 * "%p" of node->otn_key in node_ptr[22]. Cases: a normal key pointer, a
 * NULL key, the maximum pointer value (longest "%p"), and the custom
 * ot_str_fn path. The node lives in a runner-owned backing buffer so the
 * runner can poison the memory past the struct.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

unsigned char dns_backing[sizeof(ds_tree_node_t) + 64];
ds_tree_t     dns_root;
int           dns_use_strfn;    /* set ot_str_fn? */
const char   *dns_case_name;

/* custom string function for the ot_str_fn path */
static char *dns_strfn(ds_tree_node_t *node)
{
    (void)node;
    static char s[] = "CUSTOM_NODE_NAME";
    return s;
}

ds_node_str_test_case_t ds_node_str_suite[] = {
    /* name              key                     use_strfn  expect (substr/non-null) */
    { "normal_key",      (void *)0x1234,          0,   "0x1234" },
    { "null_key",        (void *)0,               0,   NULL     },   /* "(nil)" or "0x0" -> just non-NULL */
    { "max_ptr",         (void *)~0UL,            0,   NULL     },   /* longest %p; just check non-NULL/bounded */
    { "custom_strfn",    (void *)0xabcd,          1,   "CUSTOM_NODE_NAME" },

    { NULL, NULL, 0, NULL }  /* sentinel */
};

void construct_ds_node_str_input(const ds_node_str_test_case_t *tc)
{
    dns_case_name = tc->test_name;
    memset(dns_backing, 0, sizeof(dns_backing));
    memset(&dns_root, 0, sizeof(dns_root));

    ds_tree_node_t *node = (ds_tree_node_t *)dns_backing;
    node->otn_key = tc->key;

    dns_use_strfn = tc->use_strfn;
    dns_root.ot_str_fn = tc->use_strfn ? dns_strfn : NULL;
}
