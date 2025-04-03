#include <iostream>
#include <vector>
#include <queue>
#include <unordered_map>
#include <fstream>
#include <sstream>
#include <algorithm>  // for std::transform
#include <cctype>     // for ::tolower

using namespace std;

// ------------------------
// Step 3: Preprocessing
// ------------------------

// Normalize a string: remove common obfuscation tokens and convert to lowercase
string normalize(const string &input) {
    string result = input;
    // Remove common obfuscation token: "/**/"
    // const string token = "/**/";
    // size_t pos = 0;
    // while ((pos = result.find(token, pos)) != string::npos) {
    //     result.erase(pos, token.length());
    // }
    // Optionally, you could remove extra spaces or punctuation here
    // Convert to lowercase
    transform(result.begin(), result.end(), result.begin(), ::tolower);
    return result;
}

// ------------------------
// Aho–Corasick Structures
// ------------------------

// Trie Node structure
struct TrieNode {
    unordered_map<char, TrieNode*> children;
    TrieNode* fail;
    vector<string> matchedPatterns;
    
    TrieNode() : fail(nullptr) {}
};

// Aho–Corasick Automaton Class
class AhoCorasick {
private:
    TrieNode* root;

public:
    AhoCorasick() {
        root = new TrieNode();
    }

    // Insert a keyword (assumed to be normalized already)
    void insert(const string& keyword) {
        TrieNode* node = root;
        for (char ch : keyword) {
            if (!node->children.count(ch))
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
                while (failure != root && !failure->children.count(ch))
                    failure = failure->fail;
                if (failure->children.count(ch))
                    child->fail = failure->children[ch];
                else
                    child->fail = root;
                // Combine matched patterns (could remove duplicates if needed)
                child->matchedPatterns.insert(child->matchedPatterns.end(),
                                              child->fail->matchedPatterns.begin(),
                                              child->fail->matchedPatterns.end());
                q.push(child);
            }
        }
    }

    // ------------------------
    // Step 2: Tuned Scoring Function
    // ------------------------
    // Search for SQLi patterns in the (normalized) query.
    // Uses a map to count each distinct pattern only once.
    int search(const string& query) {
        // Assume query is already normalized
        TrieNode* node = root;
        int riskScore = 0;
        unordered_map<string, bool> patternFound; // track unique patterns

        for (char ch : query) {
            while (node != root && !node->children.count(ch))
                node = node->fail;
            if (node->children.count(ch))
                node = node->children[ch];
            // When matches are found, check each one only once
            if (!node->matchedPatterns.empty()) {
                for (const string& pattern : node->matchedPatterns) {
                    if (!patternFound[pattern]) {
                        patternFound[pattern] = true;
                        // Weighting: assign higher weight for more critical keywords.
                        if (pattern.find("; drop") != string::npos || pattern.find("xp_cmdshell") != string::npos ||
                                pattern.find("; exec") != string::npos || pattern.find("outfile") != string::npos ||
                                pattern.find("load_file") != string::npos)
                            riskScore += 100;
                        else if (pattern.find("; delete") != string::npos || pattern.find("; insert") != string::npos ||
                                 pattern.find("; truncate") != string::npos || pattern.find("; update") != string::npos ||
                                 pattern.find("' alter") != string::npos || pattern.find("sleep(") != string::npos || 
                                 pattern.find("version(") != string::npos || pattern.find("current_user") != string::npos)
                            riskScore += 15;
                        else
                            riskScore += 10;
                    }
                }
            }
        }
        return riskScore;
    }
};

// ------------------------
// Step 2: Recalibrate Thresholds
// ------------------------
// Classify risk level based on risk score.
string classifyRisk(int riskScore) {
    if (riskScore <= 30)
        return "low";
    else if (riskScore <= 70)
        return "medium";
    else if (riskScore <= 90)
        return "high";
    else
        return "critical";
}

int main() {
    AhoCorasick detector;

    // ------------------------
    // Step 1: Review/Set Your Patterns
    // ------------------------
    // Extend the list of SQLi patterns (include both simple and obfuscated forms).
    vector<string> sqlPatterns = {
        "' or", "\" or", "' ||", "\" ||", "= or", "= ||", "' =", "' >=", "' <=",
        "' <>", "\" =", "\" !=", "= =", "= <", " >=", " <=", "' union", "' select", "' from",
        "union select", "select from", "' convert(", "' avg(", "' round(", "' sum(", "' max(", "' min(",
        ") convert(", ") avg(", ") round(", ") sum(", ") max(", ") min(", "' delete", "' drop",
        "' insert", "' truncate", "' update", "' alter", ", delete", "; drop", "; insert", 
        "; delete", ", drop", "; truncate", "' ; update", "like or", "like ||", "' %",
        "like %", " %", "</script>", "</script >",
        "union", "select", "drop", "insert", "delete", "update",
        "or 1=1", "--", "#", "/*", "*/", "sleep(", "benchmark(", "count(*)", "information_schema.schemata",
        "null", "version(", "; exec", "xp_cmdshell", "outfile", "load_file"
    };

    // Insert normalized patterns into the automaton.
    for (const string& pattern : sqlPatterns) {
        string normPattern = normalize(pattern);
        detector.insert(normPattern);
    }

    // Build the Aho–Corasick automaton.
    detector.build();

    // ------------------------
    // Process CSV dataset file
    // ------------------------
    ifstream infile("sqli_dataset_Mid_New.csv");
    if (!infile.is_open()) {
        cerr << "Error: Could not open the CSV file." << endl;
        return 1;
    }

    string line;
    int totalQueries = 0;
    int correctCount = 0;

    // Optional: If the CSV file has a header line, skip it.
    if(getline(infile, line)) {
        // Check if header contains "Query" (you can adjust as needed)
        if (line.find("Query") != string::npos) {
            // header line, do nothing
        } else {
            // not a header, process this line as well later
            // (could push it back or process normally)
        }
    }

    // Process each line from the CSV file.
    while (getline(infile, line)) {
        if (line.empty())
            continue;
        // The CSV format is assumed to be: query,expectedRisk,expectedScore
        stringstream ss(line);
        string query, expectedRisk, expectedScore;
        if (!getline(ss, query, ',')) continue;
        if (!getline(ss, expectedRisk, ',')) continue;
        getline(ss, expectedScore, ',');

        // ------------------------
        // Step 3: Normalize the query before processing
        // ------------------------
        query = normalize(query);

        // Compute risk score and classification using Aho–Corasick search.
        int riskScore = detector.search(query);
        string computedRisk = classifyRisk(riskScore);

        bool match = (computedRisk == expectedRisk);
        if (match)
            correctCount++;
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
