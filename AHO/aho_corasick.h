#ifndef AHO_CORASICK_H
#define AHO_CORASICK_H

#include <stdbool.h>

#define ALPHABET_SIZE 128

typedef struct TrieNode {
    struct TrieNode* children[ALPHABET_SIZE];
    struct TrieNode* failure;
    bool isEndOfPattern;
} TrieNode;

TrieNode* createNode();
void insertPattern(TrieNode* root, const char* pattern);
void buildFailureFunction(TrieNode* root);
bool searchPatterns(TrieNode* root, const char* text);
void freeTrie(TrieNode* root);

#endif
