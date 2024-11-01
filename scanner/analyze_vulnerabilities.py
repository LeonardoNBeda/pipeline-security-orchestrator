import json
import pandas as pd
from transformers import T5Tokenizer, T5ForConditionalGeneration

def load_json(filename):
    with open(filename, 'r') as f:
        return json.load(f)

def summarize_vulnerabilities(vulnerability):
    model_name = "t5-small"
    tokenizer = T5Tokenizer.from_pretrained(model_name)
    model = T5ForConditionalGeneration.from_pretrained(model_name)

    input_text = f"summarize: {json.dumps(vulnerability)}"
    input_ids = tokenizer.encode(input_text, return_tensors='pt', max_length=512, truncation=True)

    outputs = model.generate(input_ids, max_length=150, num_beams=4, early_stopping=True)
    summary = tokenizer.decode(outputs[0], skip_special_tokens=True)
    return summary

def generate_recommendation(vulnerability):
    model_name = "t5-small"
    tokenizer = T5Tokenizer.from_pretrained(model_name)
    model = T5ForConditionalGeneration.from_pretrained(model_name)

    input_text = f"recommend: {json.dumps(vulnerability)}"
    input_ids = tokenizer.encode(input_text, return_tensors='pt', max_length=512, truncation=True)

    outputs = model.generate(input_ids, max_length=150, num_beams=4, early_stopping=True)
    recommendation = tokenizer.decode(outputs[0], skip_special_tokens=True)
    return recommendation

def classify_vulnerabilities(vulnerabilities):
    risk_scores = {
        'Critical': 10,
        'High': 8,
        'Medium': 5,
        'Low': 2,
        'Info': 0
    }
    classified = []
    for vulnerability in vulnerabilities:
        severity = vulnerability.get('severity', 'Info')
        vulnerability['risk_score'] = risk_scores.get(severity, 0)
        classified.append(vulnerability)
    return classified


def compare_vulnerabilities(vulnerabilities):
    model_name = "t5-small"
    tokenizer = T5Tokenizer.from_pretrained(model_name)
    model = T5ForConditionalGeneration.from_pretrained(model_name)

    duplicates = []
    n = len(vulnerabilities)

    for i in range(n):
        for j in range(i + 1, n):
            input_text = f"compare: {json.dumps(vulnerabilities[i])} and {json.dumps(vulnerabilities[j])}"
            input_ids = tokenizer.encode(input_text, return_tensors='pt', max_length=512, truncation=True)

            outputs = model.generate(input_ids, max_length=150, num_beams=4, early_stopping=True)
            result = tokenizer.decode(outputs[0], skip_special_tokens=True)

            if "duplicate" in result.lower(): 
                duplicates.append((vulnerabilities[i], vulnerabilities[j], result))

    return duplicates

def main():
    trivy_data = load_json('trivy_output.json')
    semgrep_data = load_json('semgrep_output.json')
    bearer_data = load_json('bearer_output.json')

    vulnerabilities = trivy_data.get('vulnerabilities', []) + \
                     semgrep_data.get('results', []) + \
                     bearer_data.get('vulnerabilities', [])

    summaries = []
    for vuln in vulnerabilities:
        summary = summarize_vulnerabilities(vuln)
        recommendation = generate_recommendation(vuln)
        summaries.append({
            'original': vuln,
            'summary': summary,
            'recommendation': recommendation
        })

    classified_vulnerabilities = classify_vulnerabilities(vulnerabilities)

    duplicates = compare_vulnerabilities(vulnerabilities)

    df = pd.DataFrame(classified_vulnerabilities)
    df.to_json('combined_vulnerabilities.json', orient='records', lines=True)

    print("Summarized vulnerabilities and recommendations:")
    for entry in summaries:
        print(entry)

    print("\nDuplicated vulnerabilities found:")
    for dup in duplicates:
        print(f"Duplicate: {dup[0]} and {dup[1]} - Reason: {dup[2]}")

    print("\nUnique Vulnerabilities found:")
    print(df)

if __name__ == "__main__":
    main()
