#include <iostream>
#include <vector>
#include <unordered_map>
#include <queue>
#include <chrono>

using namespace std;
using namespace std::chrono;

// ============================ AHO-CORASICK IMPLEMENTATION ============================
struct TrieNode {
    unordered_map<char, TrieNode*> children;
    TrieNode* fail;
    vector<string> matchedPatterns;
    TrieNode() : fail(nullptr) {}
};

class AhoCorasick {
private:
    TrieNode* root;

public:
    AhoCorasick() { root = new TrieNode(); }

    void insert(const string& keyword) {
        TrieNode* node = root;
        for (char ch : keyword) {
            if (!node->children[ch])
                node->children[ch] = new TrieNode();
            node = node->children[ch];
        }
        node->matchedPatterns.push_back(keyword);
    }

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

    int search(const string& query) {
        TrieNode* node = root;
        int matchCount = 0;

        for (char ch : query) {
            while (node != root && node->children.find(ch) == node->children.end()) {
                node = node->fail;
            }

            if (node->children.find(ch) != node->children.end()) {
                node = node->children[ch];
            }

            matchCount += node->matchedPatterns.size();
        }
        return matchCount;
    }
};

// ============================ KMP IMPLEMENTATION ============================
vector<int> buildLPS(const string& pattern) {
    int m = pattern.length();
    vector<int> lps(m, 0);
    int len = 0, i = 1;

    while (i < m) {
        if (pattern[i] == pattern[len]) {
            lps[i++] = ++len;
        } else {
            len = (len != 0) ? lps[len - 1] : 0;
            if (len == 0) i++;
        }
    }
    return lps;
}

bool KMPSearch(const string& text, const string& pattern) {
    int n = text.length();
    int m = pattern.length();
    vector<int> lps = buildLPS(pattern);

    int i = 0, j = 0;
    while (i < n) {
        if (text[i] == pattern[j]) {
            i++, j++;
        }
        if (j == m) return true;
        else if (i < n && text[i] != pattern[j]) {
            j = (j != 0) ? lps[j - 1] : 0;
            if (j == 0) i++;
        }
    }
    return false;
}

int countKMPOccurrences(const string& query, const vector<string>& patterns) {
    int matchCount = 0;
    for (const string& pattern : patterns) {
        if (KMPSearch(query, pattern))
            matchCount++;
    }
    return matchCount;
}

// ============================ BENCHMARKING CODE ============================
int main() {
    vector<string> sqli_patterns = {
        "UNION", "SELECT", "DROP", "INSERT", "DELETE", "UPDATE",
        "OR 1=1", "--", "#", "/*", "*/", "SLEEP(", "BENCHMARK("
    };

    vector<string> test_queries = {
        "SELECT * FROM users WHERE username='admin' --",
        "1 OR 1=1",
        "UNION SELECT username, password FROM users",
        "DROP TABLE students; --",
        "SELECT * FROM users WHERE id=1; SLEEP(5);"
    };

    AhoCorasick aho;
    for (const string& pattern : sqli_patterns)
        aho.insert(pattern);
    aho.build();

    cout << "\n===== SQL Injection Detection Benchmark =====\n";
    
    // Aho-Corasick Benchmark
    auto start1 = high_resolution_clock::now();
    for (const string& query : test_queries)
        aho.search(query);
    auto end1 = high_resolution_clock::now();
    auto timeAho = duration_cast<microseconds>(end1 - start1).count();
    cout << "Aho-Corasick Execution Time: " << timeAho << " μs\n";

    // KMP Benchmark
    auto start2 = high_resolution_clock::now();
    for (const string& query : test_queries)
        countKMPOccurrences(query, sqli_patterns);
    auto end2 = high_resolution_clock::now();
    auto timeKMP = duration_cast<microseconds>(end2 - start2).count();
    cout << "KMP Execution Time: " << timeKMP << " μs\n";

    // Compare results
    cout << "\n===== Detection Results =====\n";
    for (const string& query : test_queries) {
        int ahoMatches = aho.search(query);
        int kmpMatches = countKMPOccurrences(query, sqli_patterns);
        cout << "Query: " << query << "\n";
        cout << "Aho-Corasick Matches: " << ahoMatches << ", KMP Matches: " << kmpMatches << "\n";
        cout << "Detection Consistency: " << (ahoMatches == kmpMatches ? "✅ Same" : "❌ Different") << "\n\n";
    }

    return 0;
}
