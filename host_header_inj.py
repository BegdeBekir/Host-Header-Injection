import requests
from concurrent.futures import ThreadPoolExecutor
import csv
import json
import argparse

# --- Argument Parser ---
parser = argparse.ArgumentParser(description="Host Header Injection Scanner")
parser.add_argument("-u", "--url", required=True, help="Target URL (http or https)")
parser.add_argument("-p", "--payloads", help="File containing custom payloads (one per line)")
parser.add_argument("-t", "--threads", type=int, default=10, help="Number of concurrent threads")
parser.add_argument("-o", "--output", default="hhi_results", help="Output file prefix (JSON/CSV)")
args = parser.parse_args()

# --- Payload List ---
default_payloads = [
    "evil.com",
    "attacker.com",
    "127.0.0.1",
    "localhost",
    "www.evil.com"
]

if args.payloads:
    with open(args.payloads, "r") as f:
        payloads = [line.strip() for line in f.readlines()]
else:
    payloads = default_payloads

# --- Results Storage ---
results = []

# --- Test Function ---
def test_host_header(payload):
    headers = {"Host": payload}
    try:
        response = requests.get(args.url, headers=headers, timeout=8, allow_redirects=True)
        status = response.status_code
        redirected = response.url != args.url
        reflected = payload in response.text
        result = {
            "payload": payload,
            "status": status,
            "redirected": redirected,
            "reflected": reflected,
            "final_url": response.url
        }
        results.append(result)
        print(f"[{payload}] Status: {status} | Redirect: {redirected} | Reflected: {reflected}")
    except Exception as e:
        print(f"[{payload}] Error: {e}")

# --- Multi-thread Execution ---
with ThreadPoolExecutor(max_workers=args.threads) as executor:
    executor.map(test_host_header, payloads)

# --- Save Results ---
# JSON
with open(f"{args.output}.json", "w") as f_json:
    json.dump(results, f_json, indent=4)

# CSV
with open(f"{args.output}.csv", "w", newline="") as f_csv:
    writer = csv.DictWriter(f_csv, fieldnames=["payload", "status", "redirected", "reflected", "final_url"])
    writer.writeheader()
    writer.writerows(results)

print(f"\n[+] Scan complete. Results saved to {args.output}.json and {args.output}.csv")
