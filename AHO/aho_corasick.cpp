#include "aho_corasick.h"
#include <stdlib.h>
#include <string.h>

TrieNode* createNode() {
    TrieNode* node = (TrieNode*)malloc(sizeof(TrieNode));
    for (int i = 0; i < ALPHABET_SIZE; i++) {
        node->children[i] = NULL;
    }
    node->failure = NULL;
    node->isEndOfPattern = false;
    return node;
}

void insertPattern(TrieNode* root, const char* pattern) {
    TrieNode* current = root;
    for (int i = 0; pattern[i] != '\0'; i++) {
        int index = (int)pattern[i];
        if (!current->children[index]) {
            current->children[index] = createNode();
        }
        current = current->children[index];
    }
    current->isEndOfPattern = true;
}

void buildFailureFunction(TrieNode* root) {
    TrieNode* queue[1000];
    int front = 0, rear = 0;

    root->failure = root;

    for (int i = 0; i < ALPHABET_SIZE; i++) {
        if (root->children[i]) {
            root->children[i]->failure = root;
            queue[rear++] = root->children[i];
        }
    }

    while (front < rear) {
        TrieNode* current = queue[front++];

        for (int i = 0; i < ALPHABET_SIZE; i++) {
            if (current->children[i]) {
                TrieNode* failure = current->failure;

                while (failure != root && !failure->children[i]) {
                    failure = failure->failure;
                }

                if (failure->children[i] && failure->children[i] != current->children[i]) {
                    failure = failure->children[i];
                }

                current->children[i]->failure = failure;
                queue[rear++] = current->children[i];
            }
        }
    }
}

bool searchPatterns(TrieNode* root, const char* text) {
    TrieNode* current = root;

    for (int i = 0; text[i] != '\0'; i++) {
        int index = (int)text[i];

        while (current != root && !current->children[index]) {
            current = current->failure;
        }

        if (current->children[index]) {
            current = current->children[index];
        }

        if (current->isEndOfPattern) {
            return false;
        }
    }

    return true;
}

void freeTrie(TrieNode* root) {
    for (int i = 0; i < ALPHABET_SIZE; i++) {
        if (root->children[i]) {
            freeTrie(root->children[i]);
        }
    }
    free(root);
}
