#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

#include "../types.h"
#include "rbtree.h"
#include "uafdetect.h"

RBTreeNode *rbSearch(RBTree *rbTree, u4 data) {
	TRACE_ENTER;
	RBTreeNode *curNode = NULL;
	curNode = *rbTree;
	while ((curNode != NULL) 
			&& !((data >= curNode->data) 
				&& (data < curNode->data + curNode->size))) {
		if (data < curNode->data) { 
			curNode = curNode->left;
		} else if(data > curNode->data + curNode->size){
			curNode = curNode->right;
		} else {
			//UAF_LOGI("[%s:%d] address 0x%8x is found in node in 0x%8x-0x%8x", FILE, LINE, data,
			//		curNode->data, curNode->data + curNode->size - 1);
			break;
		}
	}
	TRACE_EXIT;
	return curNode;
}

RBTreeNode *rbMinImum(RBTree *rbTree) {
	TRACE_ENTER;
	RBTreeNode *curNode, *targetNode;

	curNode = *rbTree;
	targetNode = NULL;
	while (curNode != NULL) {
		targetNode = curNode;
		curNode = curNode->left;
	}
	TRACE_EXIT;
	return targetNode;
}

RBTreeNode *rbMaxImum(RBTree *rbTree) {
	TRACE_ENTER;
	RBTreeNode *curNode, *targetNode;

	curNode = *rbTree;
	targetNode = NULL;
	while (curNode != NULL) {
		targetNode = curNode;
		curNode = curNode->right;
	}
	TRACE_EXIT;
	return targetNode;
}

RBTreeNode *rbSuccessor(RBTreeNode *x) {
	TRACE_ENTER;
	RBTreeNode *targetNode;

	if (x == NULL) return NULL;
	if (x->right != NULL) {
		targetNode = rbMinImum(&(x->right));
	} else {
		while ( x->parent != NULL && x->parent->left != x) {
			x  = x->parent;
		}
		targetNode = x->parent;
	}

	TRACE_EXIT;
	return targetNode;
}

RBTreeNode *rbPredecessor(RBTreeNode *x) {
	TRACE_ENTER;
	RBTreeNode *targetNode;

	if (x == NULL) return NULL;
	if (x->left != NULL) {
		targetNode = rbMaxImum(&(x->left));
	} else {
		while (x->parent != NULL && x->parent->right != x) {
			x = x->parent;
		}
		targetNode = x->parent;
	}
	TRACE_EXIT;
	return targetNode;
}


/*
*/
static void rbTreeLeftRotate(RBTree *rbTree, RBTreeNode *x);
/*
*/
static void rbTreeRightRotate(RBTree *rbTree, RBTreeNode *x);

/*
*/
static void rbTreeInsertFixup(RBTree *rbTree, RBTreeNode *x);

/*
*/
static void rbTreeDeleteFixup(RBTree *rbTree, RBTreeNode *parent, RBTreeNode *x);

bool rbInsertNode(RBTree *rbTree, u4 data, u4 size) {
	TRACE_ENTER;

	RBTreeNode *node, *p, *curNode;

	node = (RBTreeNode *)malloc(sizeof(RBTreeNode));
	if (node == NULL) 
		return false;

	node->data = data;
	node->size = size;
	node->tid	 = gettid();
	node->color = RED;
	node->left = NULL;
	node->right = NULL;

	curNode = *rbTree;
	p = NULL;

	while (curNode != NULL) {
		p = curNode;
		if (data + size <= curNode->data) {
			curNode = curNode->left;
		} else if (data >= curNode->data + curNode->size) {
			curNode = curNode->right;
		} else {
			UAF_LOGE("[%s:%d] Insert 0x%8x - 0x%8x error[0x%8x - 0x%8x].", FILE, LINE, 
					data, data + size, curNode->data, curNode->data+curNode->size);
			break;
		}
	}
	// Empty tree
	if (p == NULL) {
		*rbTree = node;
	} else {
		if (data + size <= p->data) {
			p->left = node;
		} else if(data >= p->data + p->size){
			p->right = node;
		} else {
			UAF_LOGE("[%s:%d] Insert 0x%8x - 0x%8x error[0x%8x - 0x%8x].", FILE, LINE, 
					data, data + size, curNode->data, curNode->data+curNode->size);
		}
	}
	node->parent = p;

	rbTreeInsertFixup(rbTree, node);

	TRACE_EXIT;
	return true;
}

bool rbDeleteNode(RBTree *rbTree, u4 data) {
	TRACE_ENTER;
	RBTreeNode *target, *realDel, *child;
	target = rbSearch(rbTree, data);
	if (target != NULL) {
		if (target->left == NULL || target->right == NULL) {
			realDel = target;
		} else {
			realDel = rbSuccessor(target);
		}

		if (realDel->left != NULL) {
			child = realDel->left;
		} else {
			child = realDel->right;
		}

		if (child != NULL) {
			child->parent = realDel->parent;
		} 

		if (realDel->parent == NULL) {
			*rbTree = child;
		} else {
			if (realDel->parent->left == realDel) {
				realDel->parent->left = child;
			} else {
				realDel->parent->right = child;
			}
		}

		if (target != realDel) {
			target->data = realDel->data;
		}

		if (realDel->color == BLACK) {
			rbTreeDeleteFixup(rbTree, realDel->parent, child);
		}
		free(realDel);
		TRACE_EXIT;
		return true;
	} else {
		TRACE_EXIT;
		return false;
	}
}

void rbInorderTraversal(RBTree *rbTree, void (*visitor)(RBTreeNode *node)) {
	TRACE_ENTER;
	RBTreeNode *curNode;

	curNode  = *rbTree;
	if (curNode != NULL) {
		rbInorderTraversal(&(curNode->left), visitor);
		visitor(curNode);
		rbInorderTraversal(&(curNode->right), visitor);
	}
	TRACE_EXIT;
}

/*
*/
static void rbTreeInsertFixup(RBTree *rbTree, RBTreeNode *x) {
	TRACE_ENTER;
	RBTreeNode *p, *gparent, *uncle;

	while ((p = x->parent) != NULL && p->color == RED){
		gparent = p->parent;
		if (p == gparent->left) {
			uncle = gparent->right;
			if (uncle != NULL && uncle->color == RED) {
				gparent->color = RED;
				p->color = BLACK;
				uncle->color = BLACK;
				x = gparent;
			} 
			else {
				if (x == p->right) {
					x = p;
					rbTreeLeftRotate(rbTree, x);
					p = x->parent;
				}
				p->color = BLACK;
				gparent->color = RED;
				rbTreeRightRotate(rbTree, gparent);
			}
		} 
		else {
			uncle = gparent->left;
			if (uncle != NULL && uncle->color == RED) {
				gparent->color = RED;
				p->color = BLACK;
				uncle->color = BLACK;
				x = gparent;
			} 
			else {
				if (x == p->left) {
					x = p;
					rbTreeRightRotate(rbTree, x);
					p = x->parent;
				}

				p->color = BLACK;
				gparent->color = RED;

				rbTreeLeftRotate(rbTree, gparent);
			}
		}
	}

	(*rbTree)->color = BLACK;
	TRACE_EXIT;
}

/*
*/
static void rbTreeDeleteFixup(RBTree *rbTree, RBTreeNode *parent, RBTreeNode *x) {
	TRACE_ENTER;
	RBTreeNode *brother;

	//UAF_LOGI("%d %d %d", LINE, x, *rbTree);
	while ((x == NULL || x->color == BLACK) && x != *rbTree) {
		//UAF_LOGI("%d %d %d %d", parent->parent, parent, parent->left, parent->right);
		if (x == parent->left) {
			TRACE_LINE;
			brother = parent->right;
			//UAF_LOGI("%d %d %d %d", brother->parent, brother, brother->left, brother->right);
			if (brother->color == RED) { // case 1: brother is RED
				TRACE_LINE;
				brother->color = BLACK;		//	
				parent->color = RED;
				rbTreeLeftRotate(rbTree, parent);
				brother = parent->right; 
			}
			if ((brother->left == NULL || brother->left->color == BLACK) && 
					(brother->right == NULL || brother->right->color == BLACK)) { 
				// case 2: brother is BLACK, and both its children are BLACK
				TRACE_LINE;
				brother->color = RED;
				x = parent;
				parent = parent->parent;
			} else {
				TRACE_LINE;
				if (brother->right == NULL || brother->right->color == BLACK) {
					// case 3: brother's right child is BLACK
					TRACE_LINE;
					brother->color = RED;
					brother->left->color = BLACK;
					rbTreeRightRotate(rbTree, brother);
					brother = parent->right;
				}
				// case 4: brother's right child is RED
				brother->color = parent->color;
				parent->color = BLACK;
				brother->right->color = BLACK;
				rbTreeLeftRotate(rbTree, parent);

				x = *rbTree;
			}
		} else {
			TRACE_LINE;
			brother = parent->left;
			// State 1
			if (brother->color == RED) {
				brother->color = BLACK;
				parent->color = RED;
				rbTreeRightRotate(rbTree, parent);
				brother = parent->left;
			}
			// State 2
			if ((brother->left == NULL || brother->left->color == BLACK) && 
					(brother->right == NULL || brother->right->color == BLACK)) {
				brother->color = RED;
				x = parent;
				parent = parent->parent;
			} else {
				// State 3
				if (brother->left  == NULL || brother->left->color == BLACK) {
					brother->right->color = BLACK;
					brother->color = RED;
					rbTreeLeftRotate(rbTree, brother);

					brother = parent->left;
				}
				// State 4
				brother->color = parent->color;
				parent->color = BLACK;
				brother->left->color = BLACK;
				rbTreeRightRotate(rbTree, parent);

				x = *rbTree; 
			}
		}
	}
	if (x != NULL) {
		x->color = BLACK;
	}
	TRACE_EXIT;
}

static void rbTreeLeftRotate(RBTree *rbTree, RBTreeNode *x) {
	RBTreeNode *y;
	TRACE_ENTER;

	y = x->right;
	x->right = y->left;
	if (y->left != NULL) {
		y->left->parent = x;
	}
	y->parent = x->parent;

	if (x->parent == NULL) {
		*rbTree = y;
	} else {
		if (x->parent->left == x) {
			x->parent->left = y;
		} else {
			x->parent->right = y;
		}
	}
	y->left = x;
	x->parent = y;
	TRACE_EXIT;
}

static void rbTreeRightRotate(RBTree *rbTree, RBTreeNode *x) {
	RBTreeNode *y;
	TRACE_ENTER;

	y = x->left;

	x->left = y->right;
	if (y->right != NULL) {
		y->right->parent = x;
	}

	y->parent = x->parent;
	if (x->parent == NULL) {
		*rbTree = y;
	} else {
		if (x->parent->left == x) {
			x->parent->left = y;
		} else {
			x->parent->right = y;
		}
	}

	y->right = x;
	x->parent = y;
	TRACE_EXIT;
}
