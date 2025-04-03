#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <sstream>

using namespace std;

// Function to build the KMP "longest prefix suffix" (LPS) array
vector<int> buildLPS(const string& pattern) {
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

// KMP search function to check if a pattern exists in the text
bool KMPSearch(const string& text, const string& pattern) {
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
            return true;  // Found pattern in text
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

// Function to classify risk level based on the number of detected patterns
string classifyRisk(int count) {
    if (count == 0) return "Low";
    if (count <= 2) return "Medium";
    if (count <= 4) return "High";
    return "Critical";
}

int main() {
    // List of SQL Injection attack patterns
    vector<string> sqli_patterns = {
        "UNION", "SELECT", "DROP", "INSERT", "DELETE", "UPDATE",
        "OR 1=1", "--", "#", "/*", "*/", "SLEEP(", "BENCHMARK("
    };

    // Open the CSV file
    ifstream infile("sqli_dataset_Critical.csv");
    if (!infile.is_open()) {
        cerr << "Error: Could not open the CSV file." << endl;
        return 1;
    }

    string line;
    int totalQueries = 0;
    int correctCount = 0;

    // Process each line from the CSV file
    while (getline(infile, line)) {
        if(line.empty())
            continue;

        // Assuming CSV format: query,expectedRisk,expectedScore
        stringstream ss(line);
        string query, expectedRisk, expectedScore;

        // Get query
        if (!getline(ss, query, ',')) continue;
        // Get expected risk classification
        if (!getline(ss, expectedRisk, ',')) continue;
        // Optional: get expected score (not used)
        getline(ss, expectedScore, ',');

        int matchCount = 0;
        // Check for SQLi patterns using KMP
        for (const string& pattern : sqli_patterns) {
            if (KMPSearch(query, pattern)) {
                matchCount++;
            }
        }
        string computedRisk = classifyRisk(matchCount);

        // Check if computed classification matches expected classification
        bool match = (computedRisk == expectedRisk);
        if(match) {
            correctCount++;
        }
        totalQueries++;

        cout << "Query: " << query << endl;
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
