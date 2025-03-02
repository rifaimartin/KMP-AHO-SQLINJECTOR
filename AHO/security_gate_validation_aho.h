#ifndef SECURITY_GATE_VALIDATION_AHO_H
#define SECURITY_GATE_VALIDATION_AHO_H

#include "aho_corasick.h"
#include <string.h>

class SecurityGateValidationAho
{
private:
    TrieNode *root;

public:
    SecurityGateValidationAho();
    ~SecurityGateValidationAho();

    bool execute(const char* data);
};

#endif
