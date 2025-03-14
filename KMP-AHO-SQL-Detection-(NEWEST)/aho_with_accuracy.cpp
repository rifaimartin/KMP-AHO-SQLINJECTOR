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
            }
        }

        return riskScore;
    }
};

// Function to classify SQLi risk level based on risk score
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

        // Compute risk score and classification using Aho-Corasick search
        int riskScore = detector.search(query);
        string computedRisk = classifyRisk(riskScore);

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
