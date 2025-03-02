#include <stdbool.h>
#include "KMP.h"
#include "security_gate_validation_kmp.h"

bool security_gate_validation_kmp(const char *data)
{
    const char *patterns[] = {
        "' or", "\" or", "' ||", "\" ||", "= or", "= ||", "' =", "' >=", "' <=",
        "' <>", "\" =", "\" !=", "= =", "= <", " >=", " <=", "' union", "' select", "' from",
        "union select", "select from", "' convert(", "' avg(", "' round(", "' sum(", "' max(", "' min(",
        ") convert(", ") avg(", ") round(", ") sum(", ") max(", ") min(", "' delete", "' drop",
        "' insert", "' truncate", "' update", "' alter", ", delete", "; drop", "; insert", 
        "' ; delete", ", drop", "; truncate", "' ; update", "like or", "like ||", "' %", 
        "like %", " %", "</script>", "</script >"
    };

    if (*data != '\0') 
    {
        for (int i = 0; i < sizeof(patterns) / sizeof(patterns[0]); i++)
        {
            if (KMPSearch(data, patterns[i]) >= 0)
            {
                return false;
            }
        }
    }
    return true;
}