    #include <stdio.h>
    #include <stdbool.h>
    #include <string.h>
    #include <stdbool.h>
    #include <ctype.h>
    #include <time.h>
    #include "KMP/security_gate_validation_kmp.h"
    #include "AHO/security_gate_validation_aho.h"

    #include <iostream>
    #include <fstream>
    #include <sstream>
    #include <vector>
    #include <numeric>
    #include <chrono>

    using namespace std;
    using namespace std::chrono;

    void toLowerString(const char *src, char *dest, int maxSize);

    template<typename T>
    double getAverage(vector<T> const& v) {
        if (v.empty()) {
            return 0;
        }
        return accumulate(v.begin(), v.end(), 0.0) / v.size();
    }

    int main(){
        FILE *file = fopen("testcase-10char.txt", "r");
        if (file == NULL) {
            printf("Error: Could not open file testscase.txt\n");
            return 1;
        }
        char line[500];
        int testCount = 0;

        SecurityGateValidationAho security_gate_validation_aho;

        vector<int> averageTime_KMP;
        vector<int> averageTime_AHO;

        double count_kmp_attack = 0;
        double count_kmp_non_attack = 0;
        double count_aho_attack = 0;
        double count_aho_non_attack = 0;

        while (fgets(line, sizeof(line), file)) {
            line[strcspn(line, "\n")] = '\0';

            char lowerInput[500];
            toLowerString(line, lowerInput, sizeof(lowerInput));

            // printf("Test %d: %s\n", ++testCount, lowerInput);

            // clock_t start_kmp = clock();

            auto start_kmpp = high_resolution_clock::now();

            bool result_kmp = security_gate_validation_kmp(lowerInput);
            // clock_t end_kmp = clock();

            auto end_kmpp = high_resolution_clock::now();

            // double time_kmp = (double)(end_kmp - start_kmp) / CLOCKS_PER_SEC;
            auto duration_kmp = duration_cast<microseconds>(end_kmpp - start_kmpp);
            averageTime_KMP.push_back(duration_kmp.count());


            // printf("KMP Result: %s (Time: %a seconds)\n", 
            //     result_kmp ? "Input is safe." : "Potential injection detected.", duration_kmp/1000000);


            // clock_t start_aho = clock();

            auto start_ahoo = high_resolution_clock::now();

            bool result_aho = security_gate_validation_aho.execute(lowerInput);
            // clock_t end_aho = clock();

            auto end_ahoo = high_resolution_clock::now();

            // double time_aho = (double)(end_aho - start_aho) / CLOCKS_PER_SEC;

            auto duration_aho = duration_cast<microseconds>(end_ahoo - start_ahoo);
            averageTime_AHO.push_back(duration_aho.count());


            // cout << "KMP Results: " << (result_kmp ? "Input is safe." : "Potential injection detected.");
            // cout << " (Time: " << (duration_kmp/1000000) << " seconds" << endl; 

            // printf("Aho-Corasick Result: %s (Time: %f seconds)\n", 
            //     result_aho ? "Input is safe." : "Potential injection detected.", duration_aho/1000000);

            // printf("-------------------------------------------------\n");

            
            


            if(result_kmp == false){
                count_kmp_attack++;
            }else{
                count_kmp_non_attack++;
            }

            if(result_aho == false){
                count_aho_attack++;
            }else{
                count_aho_non_attack++;
            }

        }

        

        double accuracy_kmp_attack = (count_kmp_attack/70) * 70;
        double accuracy_aho_attack = (count_aho_attack/70) * 70;
        double accuracy_kmp_non_attack = (count_kmp_non_attack/30) * 30;
        double accuracy_aho_non_attack = (count_aho_non_attack/30) * 30;

        //Average Runtime
        auto avg_KMP = getAverage(averageTime_KMP);
        auto avg_AHO = getAverage(averageTime_AHO);  

        cout << "Total Potential Injection Detected for KMP = " << count_kmp_attack << endl;
        cout << "Total Potential Injection Detected for AHO = " << count_aho_attack << endl;
        cout << "Total Non-Potential Injection Detected for KMP = " << count_kmp_non_attack << endl;
        cout << "Total Non-Potential Injection Detected for AHO = " << count_aho_non_attack << endl;
        cout << "Accuracy for KMP = " << accuracy_kmp_attack + accuracy_kmp_non_attack << "%\n";
        cout << "Accuracy for AHO = " << accuracy_aho_attack + accuracy_aho_non_attack << "%\n"; 

        cout << "Average time taken for Knuth Morris Pratt = " << avg_KMP/1000000 << " seconds" << endl;
        cout << "Average time taken for Aho-Corasick = " << avg_AHO/1000000 << " seconds" << endl;

        // printf("Average time taken for Knuth Morris Pratt = %f\n", avg_KMP/1000000);
        // printf("Average time taken for Aho-Corasick = %f\n", avg_AHO/1000000);

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