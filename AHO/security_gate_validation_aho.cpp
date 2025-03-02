#include "security_gate_validation_aho.h"
#include "aho_corasick.h"
#include <string.h>

SecurityGateValidationAho::SecurityGateValidationAho() {
    root = createNode();

    const char *patterns[] = {
        "' or", "\" or", "' ||", "\" ||", "= or", "= ||", "' =", "' >=", "' <=",
        "' <>", "\" =", "\" !=", "= =", "= <", " >=", " <=", "' union", "' select", "' from",
        "union select", "select from", "' convert(", "' avg(", "' round(", "' sum(", "' max(", "' min(",
        ") convert(", ") avg(", ") round(", ") sum(", ") max(", ") min(", "' delete", "' drop",
        "' insert", "' truncate", "' update", "' alter", ", delete", "; drop", "; insert", 
        "' ; delete", ", drop", "; truncate", "' ; update", "like or", "like ||", "' %", 
        "like %", " %", "</script>", "</script >"
    };
    
    for (int i = 0; i < sizeof(patterns) / sizeof(patterns[0]); i++) {
        insertPattern(root, patterns[i]);
    }
    
    buildFailureFunction(root);
}

SecurityGateValidationAho::~SecurityGateValidationAho() {
    freeTrie(root);
}

bool SecurityGateValidationAho::execute(const char* data) {
    return searchPatterns(root, data); 
}
