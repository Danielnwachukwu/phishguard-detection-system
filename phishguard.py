import os
import re
import time

EMAIL_DIR = "sample_emails"

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"

def analyze_email(file_path):
    findings = []
    score = 0

    with open(file_path, "r") as f:
        content = f.read()

    content_lower = content.lower()

    if "paypa1" in content_lower or "amaz0n" in content_lower:
        findings.append("Spoofed domain detected")
        score += 3

    urls = re.findall(r"http[s]?://\S+", content)
    for url in urls:
        if not any(x in url for x in ["paypal.com", "amazon.com"]):
            findings.append(f"Suspicious URL detected: {url}")
            score += 2

        if re.search(r"http[s]?://\d+\.\d+\.\d+\.\d+", url):
            findings.append("IP-based URL detected")
            score += 2

    if ".exe" in content_lower:
        findings.append("Suspicious attachment (.exe file)")
        score += 3

    if any(w in content_lower for w in ["urgent", "limited", "immediately", "suspended"]):
        findings.append("Urgency language detected")
        score += 1

    return {"file": file_path, "findings": findings, "score": score}


def print_report(result):
    score = result["score"]

    if score >= 5:
        severity = "HIGH"
        color = RED
    elif score >= 3:
        severity = "MEDIUM"
        color = YELLOW
    else:
        severity = "LOW"
        color = GREEN

    print(f"\n{RED}🚨 PHISHING ALERT 🚨{RESET}")
    print(f"{CYAN}File:{RESET} {result['file']}")
    print(f"{CYAN}Severity:{RESET} {color}{severity}{RESET}")
    print(f"{CYAN}Score:{RESET} {score}")
    print(f"{CYAN}MITRE ATT&CK:{RESET} T1566 (Phishing)")
    print(f"{CYAN}Findings:{RESET}")

    for f in result["findings"]:
        print(f" - {f}")

    print(f"{CYAN}{'-'*50}{RESET}")
    print("\a")


def main():
    print(f"{GREEN}🟢 PhishGuard Real-Time Monitoring Started{RESET}")

    processed = set(os.listdir(EMAIL_DIR))  # 🔥 Ignore old files

    while True:
        try:
            current_files = os.listdir(EMAIL_DIR)

            for file in current_files:
                if file.startswith(".") or file.endswith(".swp"):
                    continue

                if file not in processed:
                    path = os.path.join(EMAIL_DIR, file)

                    print(f"\n{YELLOW}📥 New email detected: {file}{RESET}")

                    result = analyze_email(path)
                    print_report(result)

                    processed.add(file)

            time.sleep(0.5)  # 🔥 Faster detection

        except KeyboardInterrupt:
            print(f"\n{YELLOW}Stopped monitoring.{RESET}")
            break


if __name__ == "__main__":
    main()