/*
 * TEST CASES / CONSTRUCTOR: construct_ds_tree_graphviz_r
 *
 * Builds small trees by hand and lets the graphviz dumper walk them. The
 * dumper only emits text (to a FILE*), so any case that completes without
 * ASan aborting is a pass; cases exercise a single node, a 3-node tree, and
 * a deeper tree (recursion + the null-child path + snode/schild buffers).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

ds_tree_node_t dgv_nodes[8];
ds_tree_t      dgv_root;
const char    *dgv_case_name;

ds_tree_gv_test_case_t ds_tree_gv_suite[] = {
    /* name            kind         */
    { "single",        DGV_SINGLE   },
    { "three_node",    DGV_3NODE    },
    { "deep",          DGV_DEEP     },

    { NULL, 0 }  /* sentinel */
};

static void N(int i, long key, int prop, int parent, int left, int right)
{
    dgv_nodes[i].otn_key    = (void *)key;
    dgv_nodes[i].otn_prop   = prop;
    dgv_nodes[i].otn_parent = (parent < 0) ? NULL : &dgv_nodes[parent];
    dgv_nodes[i].otn_child[0] = (left  < 0) ? NULL : &dgv_nodes[left];
    dgv_nodes[i].otn_child[1] = (right < 0) ? NULL : &dgv_nodes[right];
}

void construct_ds_tree_gv_input(const ds_tree_gv_test_case_t *tc)
{
    dgv_case_name = tc->test_name;
    memset(dgv_nodes, 0, sizeof(dgv_nodes));
    memset(&dgv_root, 0, sizeof(dgv_root));
    dgv_root.ot_str_fn = NULL;

    switch (tc->kind) {
        case DGV_SINGLE:
            N(0, 20, 0, -1, -1, -1);
            dgv_root.ot_root = &dgv_nodes[0];
            break;
        case DGV_3NODE:
            N(0, 20, 0, -1, 1, 2);
            N(1, 10, 1,  0, -1, -1);
            N(2, 30, 1,  0, -1, -1);
            dgv_root.ot_root = &dgv_nodes[0];
            break;
        case DGV_DEEP:
            /* 20 -> (10 -> (5, 15)) , 30 */
            N(0, 20, 0, -1, 1, 4);
            N(1, 10, 1,  0, 2, 3);
            N(2,  5, 0,  1, -1, -1);
            N(3, 15, 0,  1, -1, -1);
            N(4, 30, 1,  0, -1, -1);
            dgv_root.ot_root = &dgv_nodes[0];
            break;
    }
}
