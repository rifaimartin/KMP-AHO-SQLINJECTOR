#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <chrono>
#include "KMP/security_gate_validation_kmp.h"
#include "AHO/security_gate_validation_aho.h"

void toLowerString(const char *src, char *dest, int maxSize);

int main() {
    FILE *file = fopen("large_testscase.txt", "r");
    if (file == NULL) {
        printf("Error: Could not open file large_testscase.txt\n");
        return 1;
    }
    
    // Use a larger buffer for the bigger test cases
    char *line = new char[500000];
    int testCount = 0;

    SecurityGateValidationAho security_gate_validation_aho;

    while (fgets(line, 500000, file)) {
        line[strcspn(line, "\n")] = '\0';

        // Allocate a buffer for lowercase conversion
        char *lowerInput = new char[strlen(line) + 1];
        toLowerString(line, lowerInput, strlen(line) + 1);

        // Print a shorter version of the input for display
        char shortDisplay[100];
        strncpy(shortDisplay, lowerInput, 90);
        shortDisplay[90] = '\0';
        if (strlen(lowerInput) > 90) {
            strcat(shortDisplay, "...");
        }

        printf("Test %d: %s (Length: %lu)\n", ++testCount, shortDisplay, strlen(lowerInput));

        // Use high resolution timer for more accurate measurement
        // KMP timing
        auto start_kmp = std::chrono::high_resolution_clock::now();
        const int ITERATIONS = 10; // Repeat test for more accurate timing
        bool result_kmp;
        for (int i = 0; i < ITERATIONS; i++) {
            result_kmp = security_gate_validation_kmp(lowerInput);
        }
        auto end_kmp = std::chrono::high_resolution_clock::now();
        double time_kmp = std::chrono::duration<double>(end_kmp - start_kmp).count() / ITERATIONS;

        // Aho-Corasick timing
        auto start_aho = std::chrono::high_resolution_clock::now();
        bool result_aho;
        for (int i = 0; i < ITERATIONS; i++) {
            result_aho = security_gate_validation_aho.execute(lowerInput);
        }
        auto end_aho = std::chrono::high_resolution_clock::now();
        double time_aho = std::chrono::duration<double>(end_aho - start_aho).count() / ITERATIONS;

        printf("KMP Result: %s (Time: %.6f seconds)\n", 
               result_kmp ? "Input is safe." : "Potential injection detected.", time_kmp);

        printf("Aho-Corasick Result: %s (Time: %.6f seconds)\n", 
               result_aho ? "Input is safe." : "Potential injection detected.", time_aho);

        printf("Speedup: %.2fx\n", time_kmp / time_aho);
        printf("-------------------------------------------------\n");

        // Clean up
        delete[] lowerInput;
    }

    fclose(file);
    delete[] line;

    return 0;
}

void toLowerString(const char *src, char *dest, int maxSize) {
    for (int i = 0; src[i] && i < maxSize - 1; i++) {
        dest[i] = tolower(src[i]);
    }
    dest[strlen(src)] = '\0';
}