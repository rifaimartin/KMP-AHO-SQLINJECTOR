# Security Gate Validation

This project implements security gate validation using two different string matching algorithms: Aho-Corasick and Knuth-Morris-Pratt (KMP). The goal is to detect potential SQL injection patterns in user input.

## Files Description

### Aho-Corasick Implementation

- [AHO_CORASICK/aho_corasick.cpp](AHO_CORASICK/aho_corasick.cpp): Contains the implementation of the Aho-Corasick algorithm.
- [AHO_CORASICK/aho_corasick.h](AHO_CORASICK/aho_corasick.h): Header file for the Aho-Corasick algorithm.
- [AHO_CORASICK/security_gate_validation_aho.cpp](AHO_CORASICK/security_gate_validation_aho.cpp): Uses the Aho-Corasick algorithm to validate input for SQL injection patterns.
- [AHO_CORASICK/security_gate_validation_aho.h](AHO_CORASICK/security_gate_validation_aho.h): Header file for `security_gate_validation_aho.cpp`.

### Knuth-Morris-Pratt (KMP) Implementation

- [KMP/KMP.c](KMP/KMP.c): Contains the implementation of the KMP algorithm.
- [KMP/KMP.h](KMP/KMP.h): Header file for the KMP algorithm.
- [KMP/security_gate_validation_kmp.c](KMP/security_gate_validation_kmp.c): Uses the KMP algorithm to validate input for SQL injection patterns.
- [KMP/security_gate_validation_kmp.h](KMP/security_gate_validation_kmp.h): Header file for `security_gate_validation_kmp.c`.

### Main Files

- [main.c](main.c): Main file to run the security gate validation using the KMP algorithm and compare with using the Aho-Corasick algorithm.
- [testscase.txt]: A text file containing a list of test inputs to validate the capabilities of the KMP and Aho-Corasick algorithms in detecting potential security threats or injections. This file includes various types of data, such as strings with potential SQL injection, XSS scripts, valid safe inputs, and complex text inputs. Each line in the file represents a single test case.

## How to Build and Run

1. Compile the project:
    ```sh
    g++ main.cpp AHO/aho_corasick.cpp AHO/security_gate_validation_aho.cpp KMP/KMP.cpp KMP/security_gate_validation_kmp.cpp -o output
    ```

2. Run the executable:
    ```sh
    ./output
    ```

## Usage

Enter the input string when prompted to check for potential SQL injection patterns. The program will output whether the input is safe or if a potential injection is detected.

## Contributors

Kelompok 1 Design & Analisis Algoritma

## License

This project is licensed under the MIT License.