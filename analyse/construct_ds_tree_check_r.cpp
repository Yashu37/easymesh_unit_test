/*
 * TEST CASES / CONSTRUCTOR: construct_ds_tree_check_r
 *
 * Builds small red-black trees BY HAND (no insert/balance needed) and runs
 * the validator on them: a single black root, a valid 3-node tree, a tree
 * with a black-height violation, and one with a red-red violation. The
 * malformed ones also exercise ds_tree_node_str (called on violations).
 *
 * ot_str_fn is left NULL so node strings use the bounded "%p" path.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

/* node storage (enough for the largest test tree) */
ds_tree_node_t dsc_nodes[8];
ds_tree_t      dsc_root;
const char    *dsc_case_name;

ds_tree_check_test_case_t ds_tree_check_suite[] = {
    /* name                 kind              expect_ok (1 = check returns >=0) */
    { "single_black",       DSC_SINGLE,        1 },
    { "valid_3node",        DSC_VALID3,        1 },
    { "black_violation",    DSC_BLACKVIOL,     0 },
    { "red_violation",      DSC_REDVIOL,       0 },

    { NULL, 0, 0 }  /* sentinel */
};

static void N(int i, long key, int prop, int parent, int left, int right)
{
    dsc_nodes[i].otn_key    = (void *)key;
    dsc_nodes[i].otn_prop   = prop;   /* 1 = red, 0 = black */
    dsc_nodes[i].otn_parent = (parent < 0) ? NULL : &dsc_nodes[parent];
    dsc_nodes[i].otn_child[0] = (left  < 0) ? NULL : &dsc_nodes[left];
    dsc_nodes[i].otn_child[1] = (right < 0) ? NULL : &dsc_nodes[right];
}

void construct_ds_tree_check_input(const ds_tree_check_test_case_t *tc)
{
    dsc_case_name = tc->test_name;
    memset(dsc_nodes, 0, sizeof(dsc_nodes));
    memset(&dsc_root, 0, sizeof(dsc_root));
    dsc_root.ot_str_fn = NULL;

    switch (tc->kind) {
        case DSC_SINGLE:
            /* one black root, no children */
            N(0, 20, 0, -1, -1, -1);
            dsc_root.ot_root = &dsc_nodes[0];
            break;

        case DSC_VALID3:
            /* black root(20) with red left(10) and red right(30) */
            N(0, 20, 0, -1,  1,  2);
            N(1, 10, 1,  0, -1, -1);
            N(2, 30, 1,  0, -1, -1);
            dsc_root.ot_root = &dsc_nodes[0];
            break;

        case DSC_BLACKVIOL:
            /* black root(20): left is a black node(10), right is NULL ->
               left subtree has +1 black height vs right -> rc[0]!=rc[1] */
            N(0, 20, 0, -1,  1, -1);
            N(1, 10, 0,  0, -1, -1);   /* black child, no sibling */
            dsc_root.ot_root = &dsc_nodes[0];
            break;

        case DSC_REDVIOL:
            /* black root(20), red child(10), red grandchild(5):
               red node with a red child -> red violation */
            N(0, 20, 0, -1,  1, -1);
            N(1, 10, 1,  0,  2, -1);
            N(2,  5, 1,  1, -1, -1);
            dsc_root.ot_root = &dsc_nodes[0];
            break;
    }
}
