#ifndef	__RB_TREE_H
#define	__RB_TREE_H

#include "../types.h"
#include "debug/debug.h"

#ifndef NULL
#define NULL 0
#endif
#define BOOL int
#define TRUE 1
#define FALSE 0

typedef enum color_t {
	RED = 0,
	BLACK = 1
}color_t; 

typedef unsigned long data_t;

typedef struct RBTreeNode {
	u4					data;
	u4					size;
	u4					tid;
	color_t			color;
	struct RBTreeNode *left;
	struct RBTreeNode *right;
	struct RBTreeNode *parent;
} RBTreeNode, *RBTree;

// Return NULL if it is not found
RBTreeNode *rbSearch(RBTree *rbTree, u4 key);

// Return the smallest node
RBTreeNode *rbMinImum(RBTree *rbTree);

// Return the biggest node
RBTreeNode *rbMaxImum(RBTree *rbTree);

// Return the success node
RBTreeNode *rbSuccessor(RBTreeNode *x);

// Return the predecess node
RBTreeNode *rbPredecessor(RBTreeNode *x);

// Insert one node
bool rbInsertNode(RBTree *rbTree, u4 data, u4 size);

// Delete the node that stores the data
bool rbDeleteNode(RBTree *rbTree, u4 data);

// Inorder traversal
void rbInorderTraversal(RBTree *rbTree, void (*visitor)(RBTreeNode *node));

#endif // __RB_TREE_H
