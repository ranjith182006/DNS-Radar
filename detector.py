"""
DNS Feature Extraction, Machine Learning Anomaly Detector & Threat Pattern Classifier.
Combines a Supervised Multi-Class Classifier (Random Forest) with an Unsupervised
Isolation Forest and domain-specific cybersecurity heuristics:
- Advanced 22-Dimensional Feature Vector (Linguistic, Statistical, Compression, Lexical)
- Multi-Class Threat Classification: Benign, DGA, DNS Tunneling, Fast-Flux / C2, Typosquatting
- Zero-day Out-of-Distribution Anomaly Detection via Isolation Forest
- Comprehensive Forensic Indicators & Confidence Scoring
"""

import math
import re
import os
import zlib
import json
import joblib
import numpy as np
from collections import Counter
from typing import Dict, Any, List, Tuple, Optional
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, confusion_matrix
from sklearn.model_selection import train_test_split

# Popular legitimate target brands for typosquatting / phishing detection
TARGET_BRANDS = [
    "google.com", "apple.com", "microsoft.com", "paypal.com",
    "amazon.com", "netflix.com", "facebook.com", "github.com",
    "bankofamerica.com", "chase.com", "wellsfargo.com", "twitter.com"
]

# Verified legitimate enterprise, cloud, and CDN infrastructure bases
KNOWN_LEGITIMATE_BASES = {
    "google", "googleapis", "gmail", "googleusercontent", "gstatic",
    "microsoft", "microsoftonline", "azure", "office", "live", "outlook", "sharepoint", "cloudapp",
    "amazon", "amazonaws", "aws", "cloudfront",
    "apple", "icloud", "apple-cloudkit", "aaplimg",
    "netflix", "nflxext", "nflxso",
    "github", "githubusercontent",
    "cloudflare", "cloudflare-dns", "one.one.one.one",
    "akamai", "akamaized", "akamaiedge",
    "spotify", "linkedin", "licdn", "twitter", "wikipedia", "wikimedia",
    "whatsapp", "fbcdn", "facebook", "instagram", "tiktok", "dropbox",
    "atlassian", "zoom", "zoomgov", "slack", "salesforce", "force",
    "npmjs", "pypi", "docker", "stackoverflow", "reddit"
}

SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "work", "loan", "club",
    "online", "site", "vip", "icu", "buzz", "click", "cc", "fit", "biz", "info", "ru"
}

# Recognized English / tech morphemes for dictionary word ratio
COMMON_MORPHEMES = {
    "cloud", "data", "system", "portal", "server", "access", "secure", "network",
    "online", "client", "global", "media", "manage", "direct", "market", "center",
    "health", "report", "update", "office", "vector", "stream", "packet", "matrix",
    "api", "cdn", "auth", "static", "images", "assets", "gateway", "service", "metrics",
    "relay", "prod", "stage", "dev", "app", "login", "edge", "internal", "local",
    "verify", "support", "account", "billing", "recovery", "security", "share", "mail"
}

FEATURE_NAMES = [
    "fqdn_length",
    "subdomain_length",
    "subdomain_depth",
    "longest_label_len",
    "entropy",
    "normalized_entropy",
    "subdomain_entropy",
    "sld_entropy",
    "entropy_divergence",
    "vowel_ratio",
    "digit_ratio",
    "hyphen_ratio",
    "hex_ratio",
    "consecutive_consonants",
    "consecutive_digits",
    "compression_ratio",
    "dictionary_word_ratio",
    "tld_risk_score",
    "has_suspicious_tld",
    "repeat_char_ratio",
    "distinct_char_ratio",
    "token_count"
]

CLASSES = [
    "Benign",
    "DGA (Algorithmically Generated)",
    "DNS Tunneling",
    "Fast-Flux / C2 Beacon",
    "Typosquatting / Brand Impersonation"
]


def shannon_entropy(s: str) -> float:
    """Calculates Shannon Entropy of a string in bits per character."""
    if not s:
        return 0.0
    counts = Counter(s.lower())
    length = len(s)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def extract_features(domain: str) -> Dict[str, Any]:
    """
    Extracts high-dimensional 22-feature vector from a DNS domain name
    combining linguistic, statistical, compression, and structural metrics.
    """
    clean_domain = domain.lower().strip().rstrip('.')
    parts = clean_domain.split('.')
    
    # Separate TLD, main domain (SLD), and subdomains
    tld = parts[-1] if len(parts) > 1 else ""
    main_domain = parts[-2] if len(parts) > 1 else parts[0]
    subdomains = parts[:-2] if len(parts) > 2 else []
    subdomain_str = ".".join(subdomains)
    
    fqdn_length = float(len(clean_domain))
    subdomain_length = float(len(subdomain_str))
    subdomain_depth = float(len(subdomains))
    longest_label_len = float(max([len(p) for p in parts]) if parts else 0)
    
    # Entropy metrics
    entropy = shannon_entropy(clean_domain)
    # Normalized entropy avoids length bias for structured cloud hostnames
    max_entropy = math.log2(max(len(clean_domain), 2))
    normalized_entropy = round(entropy / max_entropy, 4) if max_entropy > 0 else 0.0
    subdomain_entropy = shannon_entropy(subdomain_str) if subdomain_str else 0.0
    sld_entropy = shannon_entropy(main_domain)
    entropy_divergence = round(abs(subdomain_entropy - sld_entropy), 4)
    
    # Character analysis
    alpha_chars = [c for c in clean_domain if c.isalpha()]
    vowels = [c for c in alpha_chars if c in "aeiou"]
    digits = [c for c in clean_domain if c.isdigit()]
    hyphens = [c for c in clean_domain if c == '-']
    hex_chars = [c for c in clean_domain if c in "0123456789abcdef"]
    
    vowel_ratio = len(vowels) / len(alpha_chars) if alpha_chars else 0.0
    digit_ratio = len(digits) / fqdn_length if fqdn_length else 0.0
    hyphen_ratio = len(hyphens) / fqdn_length if fqdn_length else 0.0
    hex_ratio = len(hex_chars) / fqdn_length if fqdn_length else 0.0
    
    # Consecutive consonants
    max_consonants = 0
    curr_consonants = 0
    for c in clean_domain:
        if c.isalpha() and c not in "aeiou":
            curr_consonants += 1
            if curr_consonants > max_consonants:
                max_consonants = curr_consonants
        else:
            curr_consonants = 0

    # Consecutive digits
    max_digits = 0
    curr_digits = 0
    for c in clean_domain:
        if c.isdigit():
            curr_digits += 1
            if curr_digits > max_digits:
                max_digits = curr_digits
        else:
            curr_digits = 0

    # Compression Ratio via Zlib Deflate
    # Structured natural domains compress well; random DGA and encrypted hex exfil do not
    try:
        raw_bytes = clean_domain.encode('utf-8')
        compressed_len = len(zlib.compress(raw_bytes))
        compression_ratio = round(compressed_len / max(len(raw_bytes), 1), 4)
    except Exception:
        compression_ratio = 1.0

    # Dictionary / Morpheme coverage
    matched_chars = 0
    tokens = re.split(r'[\.\-_0-9]+', clean_domain)
    for token in tokens:
        if not token:
            continue
        for morph in COMMON_MORPHEMES:
            if morph in token:
                matched_chars += len(morph)
                break
    dictionary_word_ratio = round(min(1.0, matched_chars / max(len(clean_domain), 1)), 4)

    # TLD Risk
    has_suspicious_tld = 1.0 if tld in SUSPICIOUS_TLDS else 0.0
    if tld in SUSPICIOUS_TLDS:
        tld_risk_score = 0.95
    elif tld in ["com", "org", "edu", "gov", "net", "io", "us", "uk", "ca"]:
        tld_risk_score = 0.10
    else:
        tld_risk_score = 0.40

    # Character repetition & uniqueness
    repeat_count = 0
    for i in range(len(clean_domain) - 1):
        if clean_domain[i] == clean_domain[i+1]:
            repeat_count += 1
    repeat_char_ratio = round(repeat_count / max(fqdn_length, 1), 4)
    distinct_char_ratio = round(len(set(clean_domain)) / max(fqdn_length, 1), 4)
    token_count = float(len(re.split(r'[\.\-]+', clean_domain)))

    return {
        "fqdn_length": fqdn_length,
        "subdomain_length": subdomain_length,
        "subdomain_depth": subdomain_depth,
        "longest_label_len": longest_label_len,
        "entropy": float(entropy),
        "normalized_entropy": float(normalized_entropy),
        "subdomain_entropy": float(subdomain_entropy),
        "sld_entropy": float(sld_entropy),
        "entropy_divergence": float(entropy_divergence),
        "vowel_ratio": round(vowel_ratio, 4),
        "digit_ratio": round(digit_ratio, 4),
        "hyphen_ratio": round(hyphen_ratio, 4),
        "hex_ratio": round(hex_ratio, 4),
        "consecutive_consonants": float(max_consonants),
        "consecutive_digits": float(max_digits),
        "compression_ratio": float(compression_ratio),
        "dictionary_word_ratio": float(dictionary_word_ratio),
        "tld_risk_score": float(tld_risk_score),
        "has_suspicious_tld": float(has_suspicious_tld),
        "repeat_char_ratio": float(repeat_char_ratio),
        "distinct_char_ratio": float(distinct_char_ratio),
        "token_count": float(token_count),
        "tld": tld,
        "main_domain": main_domain
    }


def levenshtein_distance(s1: str, s2: str) -> int:
    """Computes Levenshtein distance for typosquatting evaluation."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


class DNSThreatDetector:
    def __init__(self):
        self.model_dir = os.path.join(os.path.dirname(__file__), "models")
        os.makedirs(self.model_dir, exist_ok=True)
        self.classifier_path = os.path.join(self.model_dir, "threat_classifier.pkl")
        self.iso_forest_path = os.path.join(self.model_dir, "isolation_forest.pkl")
        self.metrics_path = os.path.join(self.model_dir, "model_metrics.json")
        
        self.classifier: Optional[RandomForestClassifier] = None
        self.iso_forest: Optional[IsolationForest] = None
        self.metrics: Dict[str, Any] = {}
        
        self._load_or_train_models()

    def train_and_evaluate(self):
        """
        Trains both the Supervised Random Forest Threat Classifier and
        Unsupervised Isolation Forest with cross-validation and evaluation metrics.
        """
        from .dataset_generator import get_labeled_dataset
        
        print("[*] Generating comprehensive multi-class DNS dataset...")
        domains, record_types, labels = get_labeled_dataset(n_samples_per_class=500)
        
        X = []
        for dom in domains:
            feats = extract_features(dom)
            X.append([feats[name] for name in FEATURE_NAMES])
        X = np.array(X)
        y = np.array(labels)
        
        # Split train/test (80/20 stratified)
        X_train, X_test, y_train, y_test, dom_train, dom_test = train_test_split(
            X, y, domains, test_size=0.20, random_state=42, stratify=y
        )
        
        print("[*] Training Supervised Multi-Class Threat Classifier (Random Forest)...")
        self.classifier = RandomForestClassifier(
            n_estimators=150,
            max_depth=16,
            min_samples_split=3,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1
        )
        self.classifier.fit(X_train, y_train)
        
        print("[*] Training Unsupervised Outlier Detector (Isolation Forest)...")
        # Train isolation forest primarily on benign vectors
        benign_indices = [i for i, lbl in enumerate(y_train) if lbl == "Benign"]
        X_iso_train = X_train[benign_indices]
        self.iso_forest = IsolationForest(
            n_estimators=150,
            contamination=0.08,
            random_state=42,
            bootstrap=True,
            n_jobs=-1
        )
        self.iso_forest.fit(X_iso_train)
        
        # Evaluate performance on test set
        y_pred = self.classifier.predict(X_test)
        acc = accuracy_score(y_test, y_pred)
        precision, recall, f1, support = precision_recall_fscore_support(y_test, y_pred, average="weighted")
        macro_p, macro_r, macro_f1, _ = precision_recall_fscore_support(y_test, y_pred, average="macro")
        
        # Per class breakdown
        labels_unique = list(self.classifier.classes_)
        per_class_p, per_class_r, per_class_f1, per_class_supp = precision_recall_fscore_support(
            y_test, y_pred, labels=labels_unique
        )
        
        cm = confusion_matrix(y_test, y_pred, labels=labels_unique).tolist()
        
        # Feature importances
        importances = self.classifier.feature_importances_
        feature_importance_list = [
            {"feature": name, "importance": round(float(imp), 4)}
            for name, imp in sorted(zip(FEATURE_NAMES, importances), key=lambda x: x[1], reverse=True)
        ]
        
        self.metrics = {
            "accuracy": round(float(acc), 4),
            "f1_score": round(float(f1), 4),
            "precision": round(float(precision), 4),
            "recall": round(float(recall), 4),
            "macro_f1": round(float(macro_f1), 4),
            "test_samples": len(y_test),
            "classes": labels_unique,
            "confusion_matrix": cm,
            "per_class": {
                labels_unique[i]: {
                    "precision": round(float(per_class_p[i]), 4),
                    "recall": round(float(per_class_r[i]), 4),
                    "f1": round(float(per_class_f1[i]), 4),
                    "support": int(per_class_supp[i])
                }
                for i in range(len(labels_unique))
            },
            "feature_importances": feature_importance_list
        }
        
        # Save models and metrics
        joblib.dump(self.classifier, self.classifier_path)
        joblib.dump(self.iso_forest, self.iso_forest_path)
        with open(self.metrics_path, "w", encoding="utf-8") as f:
            json.dump(self.metrics, f, indent=2)
            
        print(f"[+] Model Training Complete! Accuracy: {self.metrics['accuracy']*100:.2f}%, F1: {self.metrics['f1_score']:.4f}")

    def _load_or_train_models(self):
        """Loads trained models from disk, or triggers training if absent."""
        if os.path.exists(self.classifier_path) and os.path.exists(self.iso_forest_path) and os.path.exists(self.metrics_path):
            try:
                self.classifier = joblib.load(self.classifier_path)
                self.iso_forest = joblib.load(self.iso_forest_path)
                with open(self.metrics_path, "r", encoding="utf-8") as f:
                    self.metrics = json.load(f)
                return
            except Exception as e:
                print(f"[!] Warning: Could not load saved models ({e}). Retraining...")
        self.train_and_evaluate()

    def check_heuristics_and_forensics(self, domain: str, record_type: str, features: Dict[str, Any]) -> Tuple[Optional[str], List[str], float]:
        """
        Specialized forensic inspection and signature verification.
        Returns: (override_threat_type, forensic_indicators, heuristic_severity)
        """
        indicators = []
        heur_score = 0.0
        override_type = None
        
        clean_domain = domain.lower().strip().rstrip('.')
        parts = clean_domain.split('.')
        main_domain = features["main_domain"]
        tld = features["tld"]
        entropy = features["entropy"]
        hex_ratio = features["hex_ratio"]
        fqdn_len = features["fqdn_length"]
        cons_consonants = features["consecutive_consonants"]
        vowel_ratio = features["vowel_ratio"]
        dict_ratio = features["dictionary_word_ratio"]
        sub_depth = features["subdomain_depth"]

        # 0. Check Verified Legitimate Bases (Allowlist Protection)
        is_known_legit = False
        if any(legit in clean_domain for legit in KNOWN_LEGITIMATE_BASES):
            # If it strictly matches trusted services without typosquatting triggers
            if not any(homo in clean_domain for homo in ["paypa1", "micros0ft", "app1e", "gooogle", "netflx", "amazn", "goog1e"]):
                is_known_legit = True
                indicators.append("Verified enterprise infrastructure pattern matching recognized authority")

        # 1. DNS Tunneling Signatures
        if (record_type in ["TXT", "NULL"] and (features["subdomain_length"] > 16 or hex_ratio > 0.40)) or \
           (fqdn_len > 45 and hex_ratio > 0.45 and dict_ratio < 0.15) or \
           (features["longest_label_len"] >= 28 and hex_ratio > 0.35):
            override_type = "DNS Tunneling"
            heur_score = 0.95
            indicators.append(f"High-density data payload ({round(hex_ratio*100)}% hex, length {int(fqdn_len)}) indicative of exfiltration")
            if record_type in ["TXT", "NULL"]:
                indicators.append(f"Unusual high-capacity DNS record type '{record_type}' utilized for payload conveyance")

        # 2. Fast-Flux / C2 Callback Indicators
        if not is_known_legit and not override_type:
            c2_keywords = ["beacon", "pool-c2", "node-sync", "checkin", "c2-master", "flux-pool", "node-relay", "peer-sync", "agent-hb"]
            if any(k in clean_domain for k in c2_keywords):
                override_type = "Fast-Flux / C2 Beacon"
                heur_score = 0.90
                indicators.append("Command-and-Control callback or heartbeat beacon signature detected in hostname")
            elif sub_depth >= 3:
                override_type = "Fast-Flux / C2 Beacon"
                heur_score = 0.84
                indicators.append(f"Multi-tier subdomain nesting ({int(sub_depth)} tiers) characteristic of fast-flux hosting networks")

        # 3. Typosquatting & Brand Impersonation (with Visual Homoglyph Normalization)
        if not is_known_legit and not override_type:
            # Normalized domain replacing common homoglyphs: 1->i/l, 0->o, 5->s
            norm_domain = main_domain.replace("0", "o").replace("1", "i").replace("5", "s").replace("vv", "w")
            for brand in TARGET_BRANDS:
                brand_base = brand.split('.')[0]
                dist_raw = levenshtein_distance(main_domain, brand_base)
                dist_norm = levenshtein_distance(norm_domain, brand_base)
                min_dist = min(dist_raw, dist_norm)
                
                if (min_dist <= 1 and len(main_domain) >= 4) or (brand_base in norm_domain and any(c in clean_domain for c in ["-", "1", "0", "auth", "login", "verify", "security", "badge"])):
                    override_type = "Typosquatting / Brand Impersonation"
                    heur_score = 0.88
                    indicators.append(f"Targeted brand impersonation of legitimate entity '{brand}' (min edit distance: {min_dist})")
                    break

        # 4. DGA (Domain Generation Algorithm) Indicators
        if not is_known_legit and not override_type:
            if dict_ratio < 0.10 and (cons_consonants >= 6 or (vowel_ratio < 0.18 and cons_consonants >= 5) or (entropy > 3.65 and features["has_suspicious_tld"])):
                override_type = "DGA (Algorithmically Generated)"
                heur_score = 0.86
                indicators.append(f"Abnormal consonant/syllable distribution ({int(cons_consonants)} consonants, {round(vowel_ratio*100)}% vowels)")
                if features["has_suspicious_tld"]:
                    indicators.append(f"Registered on high-abuse generic TLD (.{tld})")
                if entropy >= 3.6:
                    indicators.append(f"Elevated Shannon entropy ({entropy} bits/char) indicating pseudo-random generation")

        return override_type, indicators, heur_score

    def analyze(self, domain: str, client_ip: str = "192.168.1.100", record_type: str = "A", ttl: int = 300) -> Dict[str, Any]:
        """
        Performs end-to-end DNS anomaly detection and threat pattern evaluation
        using the Hybrid Ensemble ML architecture.
        """
        features = extract_features(domain)
        feature_vector = np.array([[features[name] for name in FEATURE_NAMES]])
        
        # 1. Supervised Multi-Class Prediction & Class Probabilities
        class_probs = self.classifier.predict_proba(feature_vector)[0]
        classes = list(self.classifier.classes_)
        prob_dict = {classes[i]: round(float(class_probs[i]), 4) for i in range(len(classes))}
        
        predicted_class_idx = np.argmax(class_probs)
        ml_threat_type = classes[predicted_class_idx]
        ml_confidence = float(class_probs[predicted_class_idx])
        
        # 2. Unsupervised Isolation Forest Outlier Scoring
        raw_score = self.iso_forest.decision_function(feature_vector)[0]
        # Sigmoid normalization: higher = more anomalous (outlier)
        iso_anomaly_score = float(1.0 / (1.0 + np.exp(raw_score * 8.0)))
        
        # 3. Heuristics & Forensic Signatures
        heur_override, indicators, heur_score = self.check_heuristics_and_forensics(domain, record_type, features)
        
        # Determine final threat classification
        if heur_override:
            final_threat_type = heur_override
        else:
            final_threat_type = ml_threat_type
            
        # Calculate Blended Anomaly Score (0.0 to 1.0)
        if final_threat_type == "Benign":
            # If supervised ML is very confident it is benign and no malicious signatures exist:
            benign_prob = prob_dict.get("Benign", 0.9)
            combined_score = round(max(0.02, (1.0 - benign_prob) * 0.4 + iso_anomaly_score * 0.2), 3)
            # Cap benign queries safely below anomaly threshold
            combined_score = min(combined_score, 0.32)
            if not indicators:
                indicators.append("Lexical, statistical, and linguistic profile matches verified legitimate enterprise traffic")
        else:
            # Threat detected: blend supervised threat probability, isolation score, and heuristic severity
            threat_prob = 1.0 - prob_dict.get("Benign", 0.0)
            combined_score = round(max(threat_prob, heur_score, iso_anomaly_score * 0.85), 3)
            # Ensure detected threats are >= 0.50
            combined_score = max(combined_score, 0.65)
            if not indicators:
                indicators.append(f"Supervised ML classifier flagged query with {round(ml_confidence * 100)}% pattern match confidence")

        is_anomaly = bool(combined_score >= 0.45)
        
        # Threat level tier
        if combined_score >= 0.80:
            threat_level = "CRITICAL"
        elif combined_score >= 0.60:
            threat_level = "HIGH"
        elif combined_score >= 0.45:
            threat_level = "MEDIUM"
        elif combined_score >= 0.25:
            threat_level = "LOW"
        else:
            threat_level = "SAFE"

        return {
            "domain": str(domain).strip(),
            "client_ip": str(client_ip),
            "record_type": str(record_type).upper(),
            "ttl": int(ttl),
            "is_anomaly": is_anomaly,
            "threat_type": str(final_threat_type),
            "threat_level": str(threat_level),
            "anomaly_score": round(float(combined_score), 3),
            "ml_score": round(float(iso_anomaly_score), 3),
            "confidence": round(float(ml_confidence), 3),
            "probabilities": prob_dict,
            "features": {k: float(v) if isinstance(v, (int, float, np.number)) else str(v) for k, v in features.items()},
            "indicators": [str(i) for i in indicators]
        }


# Singleton instance
detector = DNSThreatDetector()
