#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <sstream>
#include <algorithm>    // for std::transform
#include <cctype>       // for ::tolower
#include <unordered_map>
#include <unordered_set>

using namespace std;

// ------------------------
// Normalization Function
// ------------------------
// This function removes common obfuscation tokens (e.g. "/**/")
// and converts the string to lowercase.
string normalize(const string &input) {
    string result = input;
    // const string token = "/**/";
    // size_t pos = 0;
    // while ((pos = result.find(token, pos)) != string::npos) {
    //     result.erase(pos, token.length());
    // }
    // Convert to lowercase
    transform(result.begin(), result.end(), result.begin(), ::tolower);
    return result;
}

// ------------------------
// KMP Functions
// ------------------------

// Build the LPS (Longest Prefix Suffix) array for KMP.
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

// KMP search function returns true if 'pattern' is found in 'text'
bool KMPSearch(const string &text, const string &pattern) {
    int n = text.length();
    int m = pattern.length();
    vector<int> lps = buildLPS(pattern);
    int i = 0, j = 0;  // i -> text index, j -> pattern index
    while (i < n) {
        if (text[i] == pattern[j]) {
            i++;
            j++;
        }
        if (j == m) {
            return true;  // Found the pattern in text
        } else if (i < n && text[i] != pattern[j]) {
            if (j != 0) {
                j = lps[j - 1];
            } else {
                i++;
            }
        }
    }
    return false;
}

// ------------------------
// Risk Classification
// ------------------------
// Map a numeric risk score to a risk label.
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
    // ------------------------
    // Define Keyword Weights
    // ------------------------
    // Adjust these weights based on how critical each keyword is.
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

    // Create a vector of patterns (keys) from the dictionary.
    vector<string> sqli_patterns;
    for (const auto &p : keywordWeights) {
        sqli_patterns.push_back(p.first);
    }

    // ------------------------
    // Open the CSV File
    // ------------------------
    ifstream infile("sqli_dataset_Mid_New.csv");
    if (!infile.is_open()) {
        cerr << "Error: Could not open the CSV file." << endl;
        return 1;
    }

    string line;
    int totalQueries = 0;
    int correctCount = 0;

    // Process each line from the CSV file.
    // CSV format is assumed to be: query,expectedRisk,expectedScore
    while (getline(infile, line)) {
        if (line.empty())
            continue;

        stringstream ss(line);
        string query, expectedRisk, expectedScore;

        // Get the query from CSV.
        if (!getline(ss, query, ',')) continue;
        // Get the expected risk classification.
        if (!getline(ss, expectedRisk, ',')) continue;
        // Optional: get expected score (not used here)
        getline(ss, expectedScore, ',');

        // ------------------------
        // Normalize the query.
        // ------------------------
        string normQuery = normalize(query);

        // ------------------------
        // Compute Risk Score using KMP
        // ------------------------
        // Use an unordered_set to ensure each pattern is only counted once.
        int riskScore = 0;
        unordered_set<string> foundPatterns;
        for (const string &pattern : sqli_patterns) {
            // Normalize the pattern.
            string normPattern = normalize(pattern);
            // If the normalized pattern is found in the normalized query
            // and hasn't been counted yet, add its weight.
            if (KMPSearch(normQuery, normPattern)) {
                if (foundPatterns.find(normPattern) == foundPatterns.end()) {
                    foundPatterns.insert(normPattern);
                    riskScore += keywordWeights[normPattern];
                }
            }
        }

        // Classify the risk based on the computed score.
        string computedRisk = classifyRisk(riskScore);
        bool match = (computedRisk == expectedRisk);
        if (match) {
            correctCount++;
        }
        totalQueries++;

        cout << "Query: " << query << endl;
        cout << "Score : " << riskScore << endl;
        cout << "Expected Risk: " << expectedRisk << " | Computed Risk: " << computedRisk << endl;
        cout << (match ? "Match" : "Mismatch") << "\n--------------------------" << endl;
    }

    infile.close();

    cout << "\nTotal Queries Processed: " << totalQueries << endl;
    cout << "Matching Classifications: " << correctCount << endl;
    double accuracy = (totalQueries > 0) ? (100.0 * correctCount / totalQueries) : 0.0;
    cout << "Accuracy: " << accuracy << "%" << endl;

    return 0;
}
