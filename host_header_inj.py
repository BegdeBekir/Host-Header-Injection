import requests
from concurrent.futures import ThreadPoolExecutor
import csv
import json
import argparse
import re
import os
from datetime import datetime
from rich.console import Console
from rich.table import Table

console = Console()

# --- Argument Parser ---
parser = argparse.ArgumentParser(description="Advanced Host Header Injection Scanner")
parser.add_argument("-u", "--url", required=True, help="Target URL (http or https)")
parser.add_argument("-p", "--payloads", help="File containing custom payloads (one per line)")
parser.add_argument("-t", "--threads", type=int, default=10, help="Number of concurrent threads")
parser.add_argument("-o", "--output", default="hhi_results", help="Output file prefix (JSON/CSV/HTML)")
parser.add_argument("--proxy", help="HTTP proxy (http://127.0.0.1:8080)")
parser.add_argument("--insecure", action="store_true", help="Disable SSL verification")
parser.add_argument("--timeout", type=int, default=8, help="Request timeout in seconds")
parser.add_argument("--verbose", action="store_true", help="Verbose output")
parser.add_argument("--user-agent", default="HHI-Scanner/1.0", help="Custom User-Agent")
args = parser.parse_args()

# --- Prepare Payloads ---
default_payloads = ["evil.com", "attacker.com", "127.0.0.1", "localhost", "www.evil.com"]
if args.payloads and os.path.exists(args.payloads):
    with open(args.payloads, "r") as f:
        payloads = [line.strip() for line in f.readlines() if line.strip()]
else:
    payloads = default_payloads

# --- Results Storage ---
results = []

# --- Headers to test ---
header_variants = ["Host", "X-Forwarded-Host", "Forwarded"]

# --- Regex reflection detection function ---
def is_reflected(payload, text):
    # Simple regex search
    return bool(re.search(re.escape(payload), text, re.IGNORECASE))

# --- Test Function ---
def test_host_header(payload):
    headers = {h: payload for h in header_variants}
    headers["User-Agent"] = args.user_agent
    proxies = {"http": args.proxy, "https": args.proxy} if args.proxy else None
    try:
        response = requests.get(
            args.url,
            headers=headers,
            timeout=args.timeout,
            verify=not args.insecure,
            allow_redirects=True,
            proxies=proxies
        )
        status = response.status_code
        redirected = response.url != args.url
        reflected = is_reflected(payload, response.text)
        location_header = response.headers.get("Location", "")
        server_header = response.headers.get("Server", "")
        set_cookie = response.headers.get("Set-Cookie", "")
        result = {
            "payload": payload,
            "status": status,
            "redirected": redirected,
            "reflected": reflected,
            "final_url": response.url,
            "location": location_header,
            "server": server_header,
            "set_cookie": set_cookie
        }
        results.append(result)
        if args.verbose:
            console.print(f"[bold cyan][{payload}][/bold cyan] Status: {status} | Redirect: {redirected} | Reflected: {reflected}")
    except Exception as e:
        console.print(f"[bold red][{payload}] Error: {e}[/bold red]")

# --- Run Multi-threaded Scan ---
with ThreadPoolExecutor(max_workers=args.threads) as executor:
    executor.map(test_host_header, payloads)

# --- Save JSON ---
with open(f"{args.output}.json", "w") as f_json:
    json.dump(results, f_json, indent=4)

# --- Save CSV ---
with open(f"{args.output}.csv", "w", newline="") as f_csv:
    fieldnames = ["payload", "status", "redirected", "reflected", "final_url", "location", "server", "set_cookie"]
    writer = csv.DictWriter(f_csv, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(results)

# --- Save HTML Report ---
html_table = Table(title=f"HHI Scan Results - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
for col in ["Payload", "Status", "Redirected", "Reflected", "Final URL", "Location", "Server", "Set-Cookie"]:
    html_table.add_column(col, justify="center", style="cyan", no_wrap=True)

for r in results:
    html_table.add_row(
        r["payload"],
        str(r["status"]),
        str(r["redirected"]),
        str(r["reflected"]),
        r["final_url"],
        r["location"],
        r["server"],
        r["set_cookie"]
    )

html_file_path = f"{args.output}.html"
with open(html_file_path, "w") as f_html:
    f_html.write("<html><body>\n")
    f_html.write(f"<h2>HHI Scan Results - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</h2>\n")
    f_html.write("<table border='1' style='border-collapse: collapse;'>\n")
    f_html.write("<tr><th>Payload</th><th>Status</th><th>Redirected</th><th>Reflected</th><th>Final URL</th><th>Location</th><th>Server</th><th>Set-Cookie</th></tr>\n")
    for r in results:
        f_html.write(f"<tr><td>{r['payload']}</td><td>{r['status']}</td><td>{r['redirected']}</td><td>{r['reflected']}</td><td>{r['final_url']}</td><td>{r['location']}</td><td>{r['server']}</td><td>{r['set_cookie']}</td></tr>\n")
    f_html.write("</table>\n</body></html>")

console.print(f"\n[bold green][+] Scan complete![/bold green]")
console.print(f"JSON: {args.output}.json | CSV: {args.output}.csv | HTML: {html_file_path}")
