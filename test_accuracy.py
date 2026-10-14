"""
DNSRadar - Automated Accuracy & Threat Benchmark Verification Suite.
Evaluates the Hybrid Ensemble Detector against balanced and real-world edge cases:
- Benign enterprise & cloud CDN FQDNs
- DGA malware domains (Banjori, Conficker, pseudo-random, hex)
- High-capacity DNS Tunneling / exfiltration channels
- Fast-Flux / Command-and-Control callback beacons
- Targeted Typosquatting / Visual Homoglyph attacks
"""

import sys
import os
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.detector import detector
from backend.dataset_generator import (
    generate_dga_domain, generate_tunneling_query,
    generate_fast_flux_query, generate_typosquatting_query, BENIGN_DOMAINS
)


def run_accuracy_benchmark():
    print("=" * 70)
    print("      DNSRadar Model Accuracy & Threat Classification Benchmark")
    print("=" * 70)

    tests = []
    
    # 1. Standard Benign Domains
    for b in BENIGN_DOMAINS[:25]:
        tests.append((b, "Benign", "A"))

    # 2. Enterprise Cloud & CDN Edge Cases (prevent false positives)
    edge_cases = [
        "whatsapp.com", "instagram.com", "tiktok.com", "microsoft-my.sharepoint.com",
        "prod-westeurope-01.cloudapp.azure.com", "lh3.googleusercontent.com",
        "scontent-frt3-1.xx.fbcdn.net", "e7215.dscg.akamaiedge.net",
        "telemetry.dropbox.com", "update.googleapis.com", "secure.netflix.com",
        "api.apple-cloudkit.com", "portal.azure.com", "registry-1.docker.io"
    ]
    for b in edge_cases:
        tests.append((b, "Benign", "A"))

    # 3. Algorithmically Generated Domains (DGA)
    for _ in range(25):
        tests.append((generate_dga_domain(), "DGA (Algorithmically Generated)", "A"))

    # Real-world DGA samples
    real_dgas = [
        "vjbyhukmnbvc.ru", "qklnszxvpmcq.biz", "mzxvlkjhgfds.cc", "zxcvbnmlkjhg.top",
        "1a2b3c4d5e6f.xyz", "ab34cd56ef78.info", "hygtfrdesw.net", "k198f029vldm4.xyz"
    ]
    for d in real_dgas:
        tests.append((d, "DGA (Algorithmically Generated)", "A"))

    # 4. DNS Tunneling & Exfiltration
    for _ in range(25):
        tests.append((generate_tunneling_query(), "DNS Tunneling", "TXT"))

    # 5. Fast-Flux / C2 Beaconing
    for _ in range(20):
        tests.append((generate_fast_flux_query(), "Fast-Flux / C2 Beacon", "A"))

    # 6. Typosquatting / Brand Impersonation
    for _ in range(20):
        tests.append((generate_typosquatting_query(), "Typosquatting / Brand Impersonation", "A"))

    total = len(tests)
    correct_anomaly = 0
    correct_type = 0
    false_positives = []
    false_negatives = []
    type_mismatches = []

    start_time = time.time()

    for domain, expected_type, record_type in tests:
        res = detector.analyze(domain, record_type=record_type)
        is_threat = (expected_type != "Benign")
        detected_anomaly = res["is_anomaly"]
        pred_type = res["threat_type"]

        if detected_anomaly == is_threat:
            correct_anomaly += 1
        else:
            if detected_anomaly and not is_threat:
                false_positives.append((domain, pred_type, res["anomaly_score"]))
            elif not detected_anomaly and is_threat:
                false_negatives.append((domain, expected_type, pred_type, res["anomaly_score"]))

        if pred_type == expected_type:
            correct_type += 1
        else:
            type_mismatches.append((domain, expected_type, pred_type))

    elapsed = time.time() - start_time
    anomaly_acc = (correct_anomaly / total) * 100.0
    threat_acc = (correct_type / total) * 100.0

    print(f"\n[+] Evaluated {total} DNS queries in {elapsed:.3f}s ({round(total/elapsed)} queries/sec)")
    print("-" * 70)
    print(f"[*] Anomaly Detection Accuracy : {anomaly_acc:.2f}% ({correct_anomaly}/{total})")
    print(f"[*] Threat Classification Acc  : {threat_acc:.2f}% ({correct_type}/{total})")
    print(f"[*] False Positives Count      : {len(false_positives)}")
    print(f"[*] False Negatives Count      : {len(false_negatives)}")
    print(f"[*] Threat Type Mismatches     : {len(type_mismatches)}")
    print("-" * 70)

    if false_positives:
        print("\n[!] False Positives:")
        for fp in false_positives:
            print(f"    - Domain: {fp[0]} | Classified As: {fp[1]} | Score: {fp[2]}")

    if false_negatives:
        print("\n[!] False Negatives:")
        for fn in false_negatives:
            print(f"    - Domain: {fn[0]} | Expected: {fn[1]} | Classified As: {fn[2]} | Score: {fn[3]}")

    print("\n" + "=" * 70)
    if anomaly_acc >= 97.0 and threat_acc >= 95.0 and len(false_positives) == 0:
        print(">>> SUCCESS: Model exceeds target accuracy and zero false positive criteria! <<<")
        print("=" * 70)
        return True
    else:
        print(">>> FAILURE: Model did not meet the accuracy thresholds. <<<")
        print("=" * 70)
        return False


if __name__ == "__main__":
    success = run_accuracy_benchmark()
    sys.exit(0 if success else 1)
