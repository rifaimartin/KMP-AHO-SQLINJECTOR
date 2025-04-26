# SQL Injection Detection System

![SQL Injection](https://img.shields.io/badge/Security-SQL%20Injection%20Detection-blue)
![C++](https://img.shields.io/badge/Language-C%2B%2B-green)
![Python](https://img.shields.io/badge/Language-Python-yellow)

## Overview

This repository contains the implementation and experimental data for our academic paper "Addressing KMP Limits on SQL Injection Detection with Aho-Corasick Algorithm." SQL injection remains one of the most prevalent and damaging security threats to web applications and database systems, ranking consistently in the OWASP Top 10 web application security risks. Our research addresses the limitations of traditional string matching algorithms in detecting increasingly sophisticated SQL injection attacks.

1. **Aho-Corasick Algorithm** - A string-searching algorithm that locates elements of a finite set of strings within an input text
2. **Knuth-Morris-Pratt (KMP) Algorithm** - An efficient string-matching algorithm that uses information about previous partial matches

## Key Features

- Fast and accurate detection of SQL injection patterns
- Risk classification system (low, medium, high, critical)
- Weighted risk scoring based on pattern severity
- Normalization of input queries to catch obfuscated attacks
- Performance benchmarking tools for algorithm comparison
- Dataset generation utilities for testing

## Repository Structure

```
.
├── LATEST/
│   ├── aho-increased-acc.cpp        # Aho-Corasick implementation with accuracy improvements
│   ├── kmp-increased-acc.cpp        # KMP implementation with accuracy improvements
│   ├── newest_benchmarking.cpp      # Performance comparison tools
│   ├── generate-dataset-Latest.py   # Dataset generation script
│   ├── sqli_dataset_Low_New.csv     # Test dataset - low risk queries
│   ├── sqli_dataset_Mid_New.csv     # Test dataset - medium risk queries
│   ├── sqli_dataset_High_New.csv    # Test dataset - high risk queries
│   └── sqli_dataset_Critical_New.csv # Test dataset - critical risk queries
├── Springer_LNFormat_AC-SQLi.docx   # Research paper in DOCX format
```

## Algorithm Comparison

| Feature | Aho-Corasick | KMP |
|---------|--------------|-----|
| Time Complexity | O(n + m + z) | O(n × k) |
| Memory Usage | Higher | Lower |
| Multi-pattern | Native support | Requires multiple passes |
| Best For | Many patterns | Few patterns |

Where:
- n = length of input text
- m = sum of lengths of all patterns
- z = number of pattern occurrences
- k = number of patterns

## How It Works

1. **Preprocessing**: Input queries are normalized to handle common obfuscation techniques
2. **Pattern Matching**: The system uses either Aho-Corasick or KMP to search for SQLi patterns
3. **Risk Scoring**: Detected patterns are assigned weights based on their severity
4. **Classification**: The total risk score determines the risk level (low, medium, high, critical)

## Risk Classification

- **Low** (score ≤ 30): Basic SQLi attempts like simple OR conditions
- **Medium** (score 31-60): More advanced techniques like UNION SELECT statements
- **High** (score 61-80): Dangerous operations involving database metadata or time-based attacks
- **Critical** (score > 80): Destructive operations like DROP TABLE or command execution

## Getting Started

### Prerequisites

- C++ compiler with C++11 support
- Python 3.x (for dataset generation)

### Compilation

```bash
# Compile Aho-Corasick implementation
g++ -std=c++11 -o aho-increased-acc aho-increased-acc.cpp

# Compile KMP implementation
g++ -std=c++11 -o kmp-increased-acc kmp-increased-acc.cpp

# Compile benchmarking tool
g++ -std=c++11 -o newest_benchmarking newest_benchmarking.cpp
```

### Running the Detection System

```bash
# Run with Aho-Corasick algorithm
./aho-increased-acc.exe

# Run with KMP algorithm
./kmp-increased-acc.exe

# Run performance benchmarks
./newest_benchmarking.exe
```

### Generating Custom Datasets

```bash
# Generate a dataset with custom SQLi patterns
python3 generate-dataset-Latest.py
```

## Performance Results

Our benchmarking shows that the Aho-Corasick algorithm generally outperforms KMP for multi-pattern matching scenarios, though it uses more memory. For detailed performance metrics, run the benchmarking tool.

### Research Findings

Based on our experimental evaluation:

- **Runtime Performance**: Aho-Corasick achieves 28% faster execution on average (482.3 μs vs KMP's 669.7 μs)
- **Accuracy**: Aho-Corasick maintains perfect detection (1.0) for high and critical risk patterns, while KMP's accuracy drops to 0.801 and 0.841 respectively
- **Memory Usage**: While Aho-Corasick uses more memory (116-136 KB vs KMP's 48 KB), the performance gain justifies this overhead

## Future Improvements

- Integration with web application firewalls
- Machine learning-based classification for improved accuracy
- Support for more complex obfuscation techniques
- Real-time monitoring and alerting
- API for integration with other security tools

## Authors

- Robertus Hudi - Universitas Pelita Harapan
- Kennedy Suganto - Universitas Pelita Harapan
- Muhammad Rifai - Universitas Pelita Harapan

## Acknowledgments

This research was supported by Universitas Pelita Harapan and the Institute of Research and Community Services (LPPM UPH) with research number P-92-SISTech-VII/2023.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.