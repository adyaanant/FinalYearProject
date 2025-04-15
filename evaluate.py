import pandas as pd
import requests
import time
from tqdm import tqdm  # Importing tqdm for the progress bar

# Load the dataset (placeholder file name)
df = pd.read_csv("phishing_dataset.csv")

# Normalize label: 0 = phishing=false, 1 = phishing=true
df["expected_label"] = df["Label"].map({0: "phishing=false", 1: "phishing=true"})

results = []

# Initialize tqdm progress bar with total length of dataset
for idx, row in tqdm(df.iterrows(), total=df.shape[0], desc="Processing URLs", unit="url"):
    url = row["URL"]
    expected = row["expected_label"]
    try:
        start = time.time()
        response = requests.post("http://localhost:5000/detect", json={"url": url}, timeout=60)
        end = time.time()
        result = response.json()
        
        is_phishing = result.get("is_phishing", "error")
        reason = result.get("reason", "No reason provided")  # Get the reason from the response, default to "No reason provided"
        duration = round(end - start, 2)

        correct = None
        if expected == "phishing=true" and is_phishing is True:
            correct = True
        elif expected == "phishing=false" and is_phishing is False:
            correct = True
        elif is_phishing in [True, False]:
            correct = False

        # Add the result with a reason for phishing
        results.append({
            "url": url,
            "expected_label": expected,
            "predicted_label": "phishing=true" if is_phishing else "phishing=false",
            "correct_prediction": correct,
            "time_taken_sec": duration,
            "reason": reason  # Add the reason for phishing classification
        })

    except Exception as e:
        results.append({
            "url": url,
            "expected_label": expected,
            "predicted_label": "error",
            "correct_prediction": False,
            "time_taken_sec": None,
            "error": str(e),
            "reason": "Error in detection"
        })

# Save results
results_df = pd.DataFrame(results)
results_df.to_csv("resultsp4_2.csv", index=False)

print("✅ Evaluation complete. Results saved to resultsp4.csv.")
