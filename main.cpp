#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>
#include <time.h>
#include "KMP/security_gate_validation_kmp.h"
#include "AHO/security_gate_validation_aho.h"

void toLowerString(const char *src, char *dest, int maxSize);

int main(){
    FILE *file = fopen("testscase.txt", "r");
    if (file == NULL) {
        printf("Error: Could not open file testscase.txt\n");
        return 1;
    }
    char line[500];
    int testCount = 0;

    SecurityGateValidationAho security_gate_validation_aho;

    while (fgets(line, sizeof(line), file)) {
        line[strcspn(line, "\n")] = '\0';

        char lowerInput[500];
        toLowerString(line, lowerInput, sizeof(lowerInput));

        printf("Test %d: %s\n", ++testCount, lowerInput);

        clock_t start_kmp = clock();
        bool result_kmp = security_gate_validation_kmp(lowerInput);
        clock_t end_kmp = clock();
        double time_kmp = (double)(end_kmp - start_kmp) / CLOCKS_PER_SEC;

        clock_t start_aho = clock();
        bool result_aho = security_gate_validation_aho.execute(lowerInput);
        clock_t end_aho = clock();
        double time_aho = (double)(end_aho - start_aho) / CLOCKS_PER_SEC;

        printf("KMP Result: %s (Time: %.6f seconds)\n", 
               result_kmp ? "Input is safe." : "Potential injection detected.", time_kmp);

        printf("Aho-Corasick Result: %s (Time: %.6f seconds)\n", 
               result_aho ? "Input is safe." : "Potential injection detected.", time_aho);

        printf("-------------------------------------------------\n");
    }

    fclose(file);

    return 0;
}

void toLowerString(const char *src, char *dest, int maxSize)
{
    for (int i = 0; src[i] && i < maxSize - 1; i++)
    {
        dest[i] = tolower(src[i]);
    }
    dest[strlen(src)] = '\0';
}