#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <unordered_map>
#include <unordered_set>
#include <cuda_runtime.h>
#include <chrono>

using namespace std;
using namespace std::chrono;

// Host function to normalize text
string normalize(const string &input) {
    string result = input;
    transform(result.begin(), result.end(), result.begin(), ::tolower);
    return result;
}

// Host function to build LPS array
vector<int> buildLPS(const string &pattern) {
    int m = pattern.length();
    vector<int> lps(m, 0);
    int len = 0, i = 1;
    
    while (i < m) {
        if (pattern[i] == pattern[len]) {
            lps[i] = ++len;
            i++;
        } else {
            if (len != 0) {
                len = lps[len - 1];
            } else {
                lps[i] = 0;
                i++;
            }
        }
    }
    return lps;
}

// CUDA kernel to perform KMP search in parallel (one thread per pattern)
__global__ void KMPSearchKernel(char* text, int textLen, char** patterns, int* patternLens, 
                               int* lps_arrays, int* lps_offsets, char* results, int numPatterns) {
    int tid = blockIdx.x * blockDim.x + threadIdx.x;
    
    if (tid < numPatterns) {
        char* pattern = patterns[tid];
        int patternLen = patternLens[tid];
        int* lps = &lps_arrays[lps_offsets[tid]];
        
        int i = 0; // index for text
        int j = 0; // index for pattern
        
        // KMP algorithm
        while (i < textLen) {
            if (pattern[j] == text[i]) {
                i++;
                j++;
            }
            
            if (j == patternLen) {
                // Pattern found
                results[tid] = 1;
                break;
            } else if (i < textLen && pattern[j] != text[i]) {
                if (j != 0)
                    j = lps[j - 1];
                else
                    i++;
            }
        }
    }
}

// Function to allocate memory and prepare data for CUDA
bool KMPSearchCUDA(const string &text, const vector<string> &patterns, vector<char> &results) {
    int numPatterns = patterns.size();
    results.resize(numPatterns, 0);
    
    // Allocate host memory
    vector<char*> h_patterns(numPatterns);
    vector<int> h_patternLens(numPatterns);
    vector<int> h_lps_offsets(numPatterns, 0);
    vector<int> h_lps_arrays;
    
    // Prepare LPS arrays and pattern data
    int total_lps_size = 0;
    for (int i = 0; i < numPatterns; i++) {
        h_patternLens[i] = patterns[i].length();
        
        // Build LPS array for this pattern
        vector<int> lps = buildLPS(patterns[i]);
        
        // Store offset
        h_lps_offsets[i] = total_lps_size;
        
        // Append to the flattened array
        h_lps_arrays.insert(h_lps_arrays.end(), lps.begin(), lps.end());
        total_lps_size += lps.size();
    }
    
    // Allocate device memory
    char* d_text;
    char** d_patterns;
    int* d_patternLens;
    int* d_lps_arrays;
    int* d_lps_offsets;
    char* d_results;
    
    cudaMalloc(&d_text, text.length() * sizeof(char));
    cudaMalloc(&d_patterns, numPatterns * sizeof(char*));
    cudaMalloc(&d_patternLens, numPatterns * sizeof(int));
    cudaMalloc(&d_lps_arrays, total_lps_size * sizeof(int));
    cudaMalloc(&d_lps_offsets, numPatterns * sizeof(int));
    cudaMalloc(&d_results, numPatterns * sizeof(char));
    
    // Allocate pattern strings on device
    vector<char*> d_pattern_ptrs(numPatterns);
    for (int i = 0; i < numPatterns; i++) {
        cudaMalloc(&d_pattern_ptrs[i], patterns[i].length() * sizeof(char));
        cudaMemcpy(d_pattern_ptrs[i], patterns[i].c_str(), patterns[i].length() * sizeof(char), cudaMemcpyHostToDevice);
    }
    
    // Copy data to device
    cudaMemcpy(d_text, text.c_str(), text.length() * sizeof(char), cudaMemcpyHostToDevice);
    cudaMemcpy(d_patterns, d_pattern_ptrs.data(), numPatterns * sizeof(char*), cudaMemcpyHostToDevice);
    cudaMemcpy(d_patternLens, h_patternLens.data(), numPatterns * sizeof(int), cudaMemcpyHostToDevice);
    cudaMemcpy(d_lps_arrays, h_lps_arrays.data(), total_lps_size * sizeof(int), cudaMemcpyHostToDevice);
    cudaMemcpy(d_lps_offsets, h_lps_offsets.data(), numPatterns * sizeof(int), cudaMemcpyHostToDevice);
    
    // Initialize results to false (0)
    cudaMemset(d_results, 0, numPatterns * sizeof(char));
    
    // Launch kernel
    int blockSize = 256;
    int numBlocks = (numPatterns + blockSize - 1) / blockSize;
    
    KMPSearchKernel<<<numBlocks, blockSize>>>(d_text, text.length(), d_patterns, d_patternLens, 
                                             d_lps_arrays, d_lps_offsets, d_results, numPatterns);
    
    // Copy results back
    cudaMemcpy(results.data(), d_results, numPatterns * sizeof(char), cudaMemcpyDeviceToHost);
    
    // Free device memory
    cudaFree(d_text);
    cudaFree(d_patterns);
    cudaFree(d_patternLens);
    cudaFree(d_lps_arrays);
    cudaFree(d_lps_offsets);
    cudaFree(d_results);
    
    for (int i = 0; i < numPatterns; i++) {
        cudaFree(d_pattern_ptrs[i]);
    }
    
    
    cudaError_t error = cudaGetLastError();
    if (error != cudaSuccess) {
        cerr << "CUDA error: " << cudaGetErrorString(error) << endl;
        return false;
    }
    
    return true;
}

// Risk classification function
string classifyRisk(int riskScore) {
    if (riskScore <= 30)
        return "low";
    else if (riskScore <= 60)
        return "medium";
    else if (riskScore <= 80)
        return "high";
    return "critical";
}

int main() {
    // Define keyword weights (same as in original code)
    unordered_map<string, int> keywordWeights = {
        {"; drop table ", 100},
        {"xp_cmdshell", 100},
        {"outfile '/", 100},
        {"load_file('/", 100},
        {"delete", 15},
        {"insert", 15},
        {"truncate", 15},
        {"update", 15},
        {"alter", 15},
        {"or 1=1", 10},
        {"--", 10},
        {"#", 10},
        {"/*", 10},
        {"*/", 10},
        {"sleep(", 10},
        {"benchmark(", 10},
        {"union", 5},
        {"select", 5},
        {"exists(", 10},
        {"* from users", 10},
        {"select username password from users", 10},
        {"union select", 10},
        {"version(", 20},
        {"current_user", 20},
        {"database(", 25},
        {"information_schema.schemata", 25}
    };

    // Create a vector of patterns from the dictionary
    vector<string> sqli_patterns;
    for (const auto &p : keywordWeights) {
        sqli_patterns.push_back(p.first);
    }

    // Open the CSV File
    ifstream infile("sqli_dataset_Mid_New.csv");
    if (!infile.is_open()) {
        cerr << "Error: Could not open the CSV file." << endl;
        return 1;
    }

    vector<string> queries;
    vector<string> expected_risks;
    
    string line;
    while (getline(infile, line)) {
        if (line.empty()) continue;
        
        stringstream ss(line);
        string query, expectedRisk, expectedScore;
        
        if (!getline(ss, query, ',')) continue;
        if (!getline(ss, expectedRisk, ',')) continue;
        getline(ss, expectedScore, ',');
        
        queries.push_back(query);
        expected_risks.push_back(expectedRisk);
    }
    infile.close();
    
    int totalQueries = queries.size();
    int correctCount = 0;
    
    // Normalize patterns
    vector<string> normalized_patterns;
    for (const string &pattern : sqli_patterns) {
        normalized_patterns.push_back(normalize(pattern));
    }
    
    // Start timing
    auto start = high_resolution_clock::now();
    
    // Process each query
    for (int q = 0; q < totalQueries; q++) {
        string query = queries[q];
        string expectedRisk = expected_risks[q];
        
        // Normalize query
        string normQuery = normalize(query);
        
        // Vector to store results of parallel KMP search
        vector<char> searchResults;
        
        // Perform CUDA KMP search
        KMPSearchCUDA(normQuery, normalized_patterns, searchResults);
        
        // Calculate risk score based on results
        int riskScore = 0;
        unordered_set<string> foundPatterns;
        
        for (int i = 0; i < normalized_patterns.size(); i++) {
            if (searchResults[i] == 1) {
                string pattern = sqli_patterns[i];
                if (foundPatterns.find(pattern) == foundPatterns.end()) {
                    foundPatterns.insert(pattern);
                    riskScore += keywordWeights[pattern];
                }
            }
        }
        
        // Classify risk
        string computedRisk = classifyRisk(riskScore);
        bool match = (computedRisk == expectedRisk);
        
        if (match) {
            correctCount++;
        }
        
        // Print results for first few queries only
        if (q < 5) {
            cout << "Query: " << query << endl;
            cout << "Score: " << riskScore << endl;
            cout << "Expected Risk: " << expectedRisk << " | Computed Risk: " << computedRisk << endl;
            cout << (match ? "Match" : "Mismatch") << "\n--------------------------" << endl;
        }
    }
    
    // End timing
    auto end = high_resolution_clock::now();
    auto duration = duration_cast<milliseconds>(end - start).count();
    
    cout << "\nTotal Queries Processed: " << totalQueries << endl;
    cout << "Matching Classifications: " << correctCount << endl;
    double accuracy = (totalQueries > 0) ? (100.0 * correctCount / totalQueries) : 0.0;
    cout << "Accuracy: " << accuracy << "%" << endl;
    cout << "Execution Time: " << duration << " ms" << endl;
    
    return 0;
}