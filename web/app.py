import json
import re
from pathlib import Path
from flask import Flask, render_template, request

app = Flask(__name__)

PROJECT_DIR = Path(__file__).resolve().parent.parent
RESULTS_FILE = PROJECT_DIR / "reports" / "test_harness" / "results.json"
RULES_FILE = PROJECT_DIR / "rules" / "local.rules"


def load_results():
    if not RESULTS_FILE.exists():
        return {
            "project": "Network IDS Signature Engine",
            "total_pcaps": 0,
            "benign_pcaps": 0,
            "malicious_pcaps": 0,
            "passed": 0,
            "failed": 0,
            "results": []
        }

    with RESULTS_FILE.open("r") as file:
        return json.load(file)


def load_rules(results):
    rules = {}

    if RULES_FILE.exists():
        with RULES_FILE.open("r") as file:
            for line in file:
                sid_match = re.search(r"\bsid\s*:\s*(\d+)", line)
                msg_match = re.search(r'\bmsg\s*:\s*"([^"]+)"', line)
                rev_match = re.search(r"\brev\s*:\s*(\d+)", line)

                if sid_match and msg_match:
                    sid = int(sid_match.group(1))

                    rules[sid] = {
                        "sid": sid,
                        "name": msg_match.group(1),
                        "revision": int(rev_match.group(1))
                        if rev_match else 1,
                        "hits": 0
                    }

    for item in results.get("results", []):
        for alert in item.get("alerts", []):
            sid = int(alert["sid"])

            if sid in rules:
                rules[sid]["hits"] += 1

    return sorted(rules.values(), key=lambda rule: rule["sid"])


@app.route("/")
def dashboard():
    data = load_results()

    search = request.args.get("search", "").strip().lower()
    category = request.args.get("category", "all")

    filtered_results = []

    for item in data["results"]:
        if category != "all" and item["category"].lower() != category:
            continue

        searchable_text = (
            item["pcap"] + " " +
            " ".join(
                str(alert["sid"]) + " " + alert["rule_name"]
                for alert in item["alerts"]
            )
        ).lower()

        if search and search not in searchable_text:
            continue

        filtered_results.append(item)

    return render_template(
        "index.html",
        data=data,
        results=filtered_results,
        search=search,
        category=category
    )


@app.route("/rules")
def rules_page():
    data = load_results()
    rules = load_rules(data)

    return render_template(
        "rules.html",
        data=data,
        rules=rules
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
