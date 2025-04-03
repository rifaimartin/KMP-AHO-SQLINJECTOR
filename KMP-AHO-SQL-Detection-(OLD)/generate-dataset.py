import csv
import random

# SQLi patterns categorized by risk level
sqli_patterns = {
    # "Low": [
    #     "' OR 1=1 --", "' OR 'a'='a'", "' OR TRUE --", "admin' --", "1' OR '1'='1"
    # ]
    # "Medium": [
    #     "' UNION SELECT 1 2 3 --", "' UNION SELECT username password FROM users --",
    #     "admin' -- #", "admin'/*", "' OR EXISTS(SELECT * FROM users) --",
    #     "' OR 1=1; DROP TABLE users; --"
    # ]
    # "High": [
    #     "' UNION SELECT NULL version() current_user --",
    #     "' UNION SELECT NULL database() schema_name FROM information_schema.schemata --",
    #     "' AND 1=(SELECT COUNT(*) FROM users) --",
    #     "1' AND (SELECT sleep(5)) --",
    #     "' OR (SELECT CASE WHEN (1=1) THEN SLEEP(5) ELSE 1 END) --"
    # ]
    "Critical": [
        "'; DROP TABLE users; --", "'; EXEC xp_cmdshell('dir C:\\') --",
        "1; EXEC sp_addlogin 'hacker' 'password' --",
        "1; UNION SELECT LOAD_FILE('/etc/passwd') NULL --",
        "1; UNION SELECT NULL NULL INTO OUTFILE '/var/www/html/shell.php' --"
    ]
}

# Risk score mapping
risk_scores = {"Low": 10, "Medium": 40, "High": 70, "Critical": 100}

# Generate variations of attack queries
def generate_variations(base_query, count=3):
    variations = []
    for _ in range(count):
        altered_query = base_query
        if random.random() > 0.5:
            altered_query = altered_query.replace(" ", "/**/")  # Obfuscation
        if random.random() > 0.7:
            altered_query += " /* test */"  # Comment-based evasion
        variations.append(altered_query)
    return variations

# Generate SQLi dataset
dataset = []
for risk_level, queries in sqli_patterns.items():
    for query in queries:
        dataset.append([query, risk_level, risk_scores[risk_level]])
        for variation in generate_variations(query):
            dataset.append([variation, risk_level, risk_scores[risk_level]])

# Save dataset to CSV file
csv_filename = "sqli_dataset_Critical.csv"
with open(csv_filename, "a", newline="") as file:
    writer = csv.writer(file)
    writer.writerow(["Query", "Risk Level", "Expected Score"])
    writer.writerows(dataset)

print(f"SQL Injection dataset saved as {csv_filename}")
