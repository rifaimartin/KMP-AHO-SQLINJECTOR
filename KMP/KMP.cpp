#include <string.h>
#include "KMP.h"

void computeLPSArray(char* pattern, int m, int* lps);

void computeLPSArray(char* pattern, int m, int* lps) {
    int length = 0;
    lps[0] = 0;
    int i = 1;

    while (i < m) {
        if (pattern[i] == pattern[length]) {
            length++;
            lps[i] = length;
            i++;
        } else {
            if (length != 0) {
                length = lps[length - 1];
            } else {
                lps[i] = 0;
                i++;
            }
        }
    }
}

int KMPSearch(const char* text, const char* pattern) {
    int n = strlen(text);
    int m = strlen(pattern);

    int lps[m];
    computeLPSArray((char*)pattern, m, lps);

    int i = 0;
    int j = 0;
    while (i < n) {
        if (pattern[j] == text[i]) {
            j++;
            i++;
        }

        if (j == m) {
            return i - j;
        } else if (i < n && pattern[j] != text[i]) {
            if (j != 0) {
                j = lps[j - 1];
            } else {
                i++;
            }
        }
    }
    return -1;
}
