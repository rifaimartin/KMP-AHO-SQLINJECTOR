#include <iostream>
#include <vector>
#include <queue>
#include <unordered_map>
#include <fstream>
#include <sstream>

using namespace std;

// Aho-Corasick Trie Node
struct TrieNode {
    unordered_map<char, TrieNode*> children;
    TrieNode* fail;
    vector<string> matchedPatterns;
    
    TrieNode() : fail(nullptr) {}
};

// Aho-Corasick Automaton
class AhoCorasick {
private:
    TrieNode* root;

public:
    AhoCorasick() {
        root = new TrieNode();
    }

    // Insert a keyword into the Trie
    void insert(const string& keyword) {
        TrieNode* node = root;
        for (char ch : keyword) {
            if (!node->children[ch])
                node->children[ch] = new TrieNode();
            node = node->children[ch];
        }
        node->matchedPatterns.push_back(keyword);
    }

    // Build failure links using BFS
    void build() {
        queue<TrieNode*> q;
        root->fail = root;

        for (auto& pair : root->children) {
            pair.second->fail = root;
            q.push(pair.second);
        }

        while (!q.empty()) {
            TrieNode* current = q.front();
            q.pop();

            for (auto& pair : current->children) {
                char ch = pair.first;
                TrieNode* child = pair.second;
                TrieNode* failure = current->fail;

                while (failure != root && failure->children.find(ch) == failure->children.end()) {
                    failure = failure->fail;
                }

                if (failure->children.find(ch) != failure->children.end())
                    child->fail = failure->children[ch];
                else
                    child->fail = root;

                child->matchedPatterns.insert(
                    child->matchedPatterns.end(),
                    child->fail->matchedPatterns.begin(),
                    child->fail->matchedPatterns.end()
                );

                q.push(child);
            }
        }
    }

    // Search for SQL Injection patterns in the input query
    int search(const string& query) {
        TrieNode* node = root;
        int riskScore = 0;

        for (char ch : query) {
            while (node != root && node->children.find(ch) == node->children.end()) {
                node = node->fail;
            }

            if (node->children.find(ch) != node->children.end()) {
                node = node->children[ch];
            }

            if (!node->matchedPatterns.empty()) {
                riskScore += node->matchedPatterns.size() * 10; // Increase risk score
                cout << "Detected SQL Pattern: ";
                for (const string& pattern : node->matchedPatterns) {
                    cout << pattern << " ";
                }
                cout << endl;
            }
        }

        return riskScore;
    }
};

// Function to classify SQLi risk level
string classifyRisk(int riskScore) {
    if (riskScore <= 30) return "Low";
    if (riskScore <= 60) return "Medium";
    if (riskScore <= 80) return "High";
    return "Critical";
}

int main() {
    AhoCorasick detector;

    // Add SQL injection patterns
    vector<string> sqlPatterns = {
        "UNION", "SELECT", "DROP", "INSERT", "DELETE", "UPDATE",
        "OR 1=1", "--", "#", "/*", "*/", "SLEEP(", "BENCHMARK("
    };

    for (const string& pattern : sqlPatterns) {
        detector.insert(pattern);
    }

    // Build the Aho-Corasick automaton
    detector.build();

    // Test queries
    // vector<string> testQueries = {
    //     "SELECT * FROM users WHERE username='admin' --",
    //     "1 OR 1=1",
    //     "UNION SELECT username, password FROM users",
    //     "DROP TABLE students; --",
    //     "SELECT * FROM users WHERE id=1; SLEEP(5);",
    //     "';/**/DROP/**/TABLE/**/users;/**/-- /* test */",
    //     "';/**/EXEC/**/xp_cmdshell('dir/**/C:\')/**/-- /* test */"
    // };

    // for (const string& query : testQueries) {
    //     cout << "\nQuery: " << query << endl;
    //     int riskScore = detector.search(query);
    //     cout << "SQLi Risk Score: " << riskScore << " (" << classifyRisk(riskScore) << ")\n";
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
            int riskScore = detector.search(query);
            cout << "SQLi Risk Score: " << riskScore << " (" << classifyRisk(riskScore) << ")\n";
        }
    }
    file.close();

    return 0;
}
