"""
Dataset generator & traffic simulator for DNS Query Anomaly Detection.
Provides realistic enterprise baseline DNS traffic and high-fidelity threat samples:
- Benign: Top SaaS, enterprise CDNs, cloud infrastructure, internal Active Directory domains
- Malicious: DGA (Conficker, Banjori-style, hex, hybrid), DNS Tunneling (Iodine/dnscat2 style), Fast-Flux C2, Typosquatting
"""

import random
import string
import numpy as np
from typing import List, Dict, Any, Tuple

# Comprehensive legitimate enterprise, cloud, SaaS, and CDN domains
BENIGN_DOMAINS = [
    "google.com", "www.google.com", "mail.google.com", "accounts.google.com", "drive.google.com",
    "microsoft.com", "login.microsoftonline.com", "azure.microsoft.com", "portal.azure.com", "teams.microsoft.com",
    "github.com", "api.github.com", "raw.githubusercontent.com", "objects.githubusercontent.com",
    "amazon.com", "aws.amazon.com", "s3.amazonaws.com", "ec2.us-east-1.amazonaws.com", "dynamodb.us-west-2.amazonaws.com",
    "cloudflare.com", "one.one.one.one", "cdn.cloudflare.net", "cloudflare-dns.com",
    "wikipedia.org", "en.wikipedia.org", "upload.wikimedia.org",
    "apple.com", "icloud.com", "api.apple-cloudkit.com", "appleid.apple.com", "setup.icloud.com",
    "netflix.com", "assets.nflxext.com", "occ-0-2794-2219.1.nflxso.net", "customerevents.netflix.com",
    "zoom.us", "us04web.zoom.us", "zoomgov.com",
    "slack.com", "edge-chat.slack.com", "app.slack.com",
    "salesforce.com", "login.salesforce.com", "lightning.force.com",
    "spotify.com", "audio-ak-spotify-com.akamaized.net", "apresolve.spotify.com",
    "corp.local", "ldap.internal.net", "intranet.acme-corp.com", "dc01.ad.enterprise.lan", "mail.internal.corp",
    "registry.npmjs.org", "pypi.org", "docker.io", "registry-1.docker.io", "auth.docker.io",
    "stackoverflow.com", "linkedin.com", "cdn.linkedin.com", "media.licdn.com", "reddit.com",
    "nytimes.com", "bbc.co.uk", "cnn.com", "medium.com", "wsj.com",
    "whatsapp.com", "instagram.com", "tiktok.com", "dropbox.com", "telemetry.dropbox.com",
    "atlassian.net", "jira.atlassian.net", "confluence.atlassian.net",
    "prod-westeurope-01.cloudapp.azure.com", "e7215.dscg.akamaiedge.net", "lh3.googleusercontent.com",
    "scontent-frt3-1.xx.fbcdn.net", "update.googleapis.com", "secure.netflix.com"
]

BENIGN_PREFIXES = [
    "api", "cdn", "auth", "static", "images", "assets", "gateway", "service", "metrics",
    "relay", "prod", "stage", "dev", "app", "login", "portal", "cloud", "dns", "edge",
    "us-east-1", "eu-central-1", "monitoring", "telemetry", "secure", "connect"
]

RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "TXT", "PTR", "SRV"]

SAMPLE_IPS = [
    "192.168.1.45", "192.168.1.102", "10.0.4.12", "10.0.12.89",
    "172.16.2.14", "172.16.50.210", "192.168.10.15", "10.100.1.77",
    "192.168.0.55", "10.20.30.40"
]

COMMON_WORDS = [
    "cloud", "data", "system", "portal", "server", "access", "secure", "network",
    "online", "client", "global", "media", "manage", "direct", "market", "center",
    "health", "report", "update", "office", "vector", "stream", "packet", "matrix"
]

# DGA Generators (Multiple Families)
def generate_dga_domain() -> str:
    """Generates a pseudo-random DGA domain reflecting diverse malware families."""
    family = random.choice(["consonant_heavy", "hex_dga", "mixed_random", "syllable_scramble"])
    tld = random.choice(["xyz", "top", "tk", "biz", "info", "ru", "cc", "work", "loan", "club", "vip"])
    
    if family == "consonant_heavy":
        length = random.randint(12, 22)
        consonants = "bcdfghjklmnpqrstvwxyz"
        chars = consonants * 4 + "aeiou" + "0123456789"
        domain_name = "".join(random.choices(chars, k=length))
    elif family == "hex_dga":
        length = random.randint(14, 24)
        domain_name = "".join(random.choices(string.hexdigits.lower(), k=length))
    elif family == "mixed_random":
        length = random.randint(11, 20)
        chars = string.ascii_lowercase + "0123456789"
        domain_name = "".join(random.choices(chars, k=length))
    else: # syllable_scramble with abnormal entropy
        syllables = ["xkr", "plq", "zvt", "mwb", "fgh", "qtz", "jkl", "bnd", "vct", "ndm"]
        domain_name = "".join(random.choices(syllables, k=random.randint(3, 5))) + str(random.randint(10, 99))
        
    return f"{domain_name}.{tld}"


def generate_tunneling_query() -> str:
    """Generates a DNS query characteristic of tunneling tools (Iodine, dnscat2, dns2tcp)."""
    encoding = random.choice(["hex", "base32", "nested_hex"])
    c2_domain = random.choice(["tunnel-data.net", "exfil-route.biz", "dns-pipe.org", "ns1-relay.cc", "hidden-exfil.xyz"])
    
    if encoding == "hex":
        chunks = []
        for _ in range(random.randint(2, 4)):
            chunks.append("".join(random.choices("0123456789abcdef", k=random.randint(18, 30))))
        sub = ".".join(chunks)
    elif encoding == "base32":
        chars = "abcdefghijklmnopqrstuvwxyz234567"
        chunks = ["".join(random.choices(chars, k=random.randint(20, 32))) for _ in range(random.randint(2, 3))]
        sub = ".".join(chunks)
    else: # nested_hex
        sub = f"data-exfil-{''.join(random.choices('0123456789abcdef', k=28))}.p01"
        
    return f"{sub}.{c2_domain}"


def generate_fast_flux_query() -> str:
    """Generates C2 / Fast-Flux style domain with deep nesting or beacon tokens."""
    node_tokens = ["c2-beacon", "peer-sync", "node-relay", "bot-checkin", "c2-master", "flux-pool", "agent-hb"]
    sub_node = random.choice(node_tokens)
    random_token = "".join(random.choices(string.ascii_lowercase + "0123456789", k=random.randint(6, 12)))
    
    # 50% deep nested hierarchy, 50% dynamic flux hostnames
    if random.random() < 0.5:
        tier2 = "".join(random.choices(string.ascii_lowercase + "0123456789", k=6))
        tier3 = "".join(random.choices(string.ascii_lowercase + "0123456789", k=5))
        sub = f"{random_token}.{tier2}.{tier3}"
    else:
        sub = f"{sub_node}-{random_token}"
        
    c2_root = random.choice(["stealth-network.org", "dark-mesh.io", "cloud-pool.cc", "dynamic-host.biz", "ghost-c2.top"])
    return f"{sub}.{c2_root}"


def generate_typosquatting_query() -> str:
    """Generates realistic typosquatting or phishing domains targeting major services."""
    variants = [
        "gooogle-auth.com", "paypa1-security.com", "micros0ft-verify.net",
        "app1e-support-id.com", "netflx-account.org", "amazn-prime-service.cc",
        "chase-online-login.tk", "secure-github-recovery.xyz",
        "wellsfarg0-online.com", "bankofamer1ca-verify.net", "tw1tter-badge.info",
        "logln-micros0ft.com", "netflixx-billing.com", "goog1e-drive-share.com",
        "paypal-login-alert.xyz", "appleid-icloud-verify.top"
    ]
    return random.choice(variants)


def generate_benign_domain() -> str:
    """Generates a realistic enterprise benign domain."""
    base = random.choice(BENIGN_DOMAINS)
    roll = random.random()
    if roll < 0.40:
        prefix = random.choice(BENIGN_PREFIXES)
        return f"{prefix}.{base}"
    elif roll < 0.60:
        p1 = random.choice(BENIGN_PREFIXES)
        p2 = random.choice(BENIGN_PREFIXES)
        return f"{p1}.{p2}.{base}"
    elif roll < 0.75:
        w1 = random.choice(COMMON_WORDS)
        w2 = random.choice(COMMON_WORDS)
        tld = random.choice(["com", "org", "net", "io", "co"])
        return f"{w1}-{w2}.{tld}"
    return base


def get_labeled_dataset(n_samples_per_class: int = 400) -> Tuple[List[str], List[str], List[str]]:
    """
    Generates a balanced multi-class dataset of DNS queries.
    Returns: (domains, record_types, labels)
    """
    domains = []
    record_types = []
    labels = []

    # 1. Benign
    for _ in range(n_samples_per_class * 2):  # Slightly more benign for realistic baseline
        domains.append(generate_benign_domain())
        record_types.append(random.choice(["A", "AAAA", "CNAME", "MX", "A", "A"]))
        labels.append("Benign")

    # 2. DGA
    for _ in range(n_samples_per_class):
        domains.append(generate_dga_domain())
        record_types.append(random.choice(["A", "A", "AAAA", "CNAME"]))
        labels.append("DGA (Algorithmically Generated)")

    # 3. DNS Tunneling
    for _ in range(n_samples_per_class):
        domains.append(generate_tunneling_query())
        record_types.append(random.choice(["TXT", "NULL", "CNAME", "A", "TXT"]))
        labels.append("DNS Tunneling")

    # 4. Fast-Flux / C2 Beacon
    for _ in range(n_samples_per_class):
        domains.append(generate_fast_flux_query())
        record_types.append(random.choice(["A", "A", "AAAA"]))
        labels.append("Fast-Flux / C2 Beacon")

    # 5. Typosquatting / Brand Impersonation
    for _ in range(n_samples_per_class):
        domains.append(generate_typosquatting_query())
        record_types.append("A")
        labels.append("Typosquatting / Brand Impersonation")

    return domains, record_types, labels


def generate_sample_query(threat_category: str = "random") -> Dict[str, Any]:
    """Generates a structured query object for traffic simulation."""
    if threat_category == "random":
        weights = [0.65, 0.12, 0.10, 0.08, 0.05]
        category = random.choices(["benign", "dga", "tunneling", "c2", "typosquatting"], weights=weights)[0]
    else:
        category = threat_category

    record_type = "A"
    ttl = random.choice([60, 300, 1800, 3600])

    if category == "benign":
        domain = generate_benign_domain()
        record_type = random.choice(["A", "AAAA", "CNAME", "A", "A"])
    elif category == "dga":
        domain = generate_dga_domain()
        ttl = random.choice([30, 60, 120])
    elif category == "tunneling":
        domain = generate_tunneling_query()
        record_type = random.choice(["TXT", "NULL", "CNAME", "A"])
        ttl = 10
    elif category == "c2":
        domain = generate_fast_flux_query()
        ttl = 15
    elif category == "typosquatting":
        domain = generate_typosquatting_query()
        record_type = "A"
    else:
        domain = generate_benign_domain()

    client_ip = random.choice(SAMPLE_IPS)
    return {
        "domain": domain,
        "client_ip": client_ip,
        "record_type": record_type,
        "ttl": ttl
    }
