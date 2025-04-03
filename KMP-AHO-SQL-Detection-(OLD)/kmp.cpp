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
    if (count <= 2) return "Mid";
    if (count <= 4) return "High";
    return "Critical";
}

int main() {
    // List of SQL Injection attack patterns
    vector<string> sqli_patterns = {
        "UNION", "SELECT", "DROP", "INSERT", "DELETE", "UPDATE",
        "OR 1=1", "--", "#", "/*", "*/", "SLEEP(", "BENCHMARK("
    };

    // Test SQL queries
    // vector<string> test_queries = {
    //     "SELECT * FROM users WHERE username='admin' --",
    //     "1 OR 1=1",
    //     "UNION SELECT username, password FROM users",
    //     "DROP TABLE students; --",
    //     "SELECT * FROM users WHERE id=1; SLEEP(5);",
    //     "';/**/DROP/**/TABLE/**/users;/**/-- /* test */",
    //     "';/**/EXEC/**/xp_cmdshell('dir/**/C:\')/**/-- /* test */"
    // };

    // Process each test query
    // for (const string& query : test_queries) {
    //     cout << "\nQuery: " << query << endl;
    //     int matchCount = 0;

    //     // Check for SQLi patterns using KMP
    //     for (const string& pattern : sqli_patterns) {
    //         if (KMPSearch(query, pattern)) {
    //             cout << "Detected SQL Pattern: " << pattern << endl;
    //             matchCount++;
    //         }
    //     }

    //     // Output classification
    //     cout << "SQLi Risk Level: " << classifyRisk(matchCount) << endl;
    // }

    ifstream file("sqli_dataset_Low.csv");
    if (!file.is_open()) {
        cerr << "Error: Unable to open CSV file." << endl;
        return 1;
    }
    
    string line;
    while (getline(file, line)) {
        stringstream ss(line);
        string query;
        if (getline(ss, query, ',')) {  // Assuming each query is in a separate column
            cout << "\nQuery: " << query << endl;
            int matchCount = 0;
            for (const string& pattern : sqli_patterns) {
                if (KMPSearch(query, pattern)) {
                    cout << "Detected SQL Pattern: " << pattern << endl;
                    matchCount++;
                }
            }
            cout << "SQLi Risk Level: " << classifyRisk(matchCount) << endl;
        }
    }
    file.close();

    return 0;
}
