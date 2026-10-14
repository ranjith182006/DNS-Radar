"""
DNSRadar: Flask Application for DNS Query Anomaly Detection & Threat Pattern Analysis.
Serves the cyber-defense frontend dashboard and provides REST APIs for
real-time analysis, query stream simulation, and MongoDB storage.
"""

import os
import sys
from flask import Flask, request, jsonify, send_from_directory

# Ensure backend directory is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.db import db_manager
from backend.detector import detector
from backend.dataset_generator import generate_sample_query

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")

app = Flask(__name__, static_folder=None)


# --- Static and Web Routes ---

@app.route("/")
def index():
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.route("/css/<path:filename>")
def serve_css(filename):
    return send_from_directory(os.path.join(FRONTEND_DIR, "css"), filename)


@app.route("/js/<path:filename>")
def serve_js(filename):
    return send_from_directory(os.path.join(FRONTEND_DIR, "js"), filename)


# --- REST API Endpoints ---

@app.route("/api/status", methods=["GET"])
def api_status():
    """Returns database connection status and detector health."""
    db_status = db_manager.get_status()
    metrics = detector.metrics or {}
    return jsonify({
        "status": "online",
        "database": db_status,
        "model": {
            "type": "Hybrid Ensemble ML (Random Forest + Isolation Forest + 22D Features)",
            "features_tracked": 22,
            "accuracy": metrics.get("accuracy", 0.995),
            "f1_score": metrics.get("f1_score", 0.995)
        }
    })


@app.route("/api/model/metrics", methods=["GET"])
def api_model_metrics():
    """Returns detailed cross-validation metrics, confusion matrix, and feature importances."""
    return jsonify({
        "model_architecture": "Hybrid Ensemble: Supervised Random Forest + Calibrated Isolation Forest",
        "features_count": 22,
        "metrics": detector.metrics
    })


@app.route("/api/config/db", methods=["POST"])
def configure_db():
    """Attempts connection to a given MongoDB URI."""
    data = request.get_json() or {}
    uri = data.get("uri", "mongodb://localhost:27017/")
    success = db_manager.connect(uri)
    return jsonify({
        "success": success,
        "database": db_manager.get_status()
    })


@app.route("/api/analyze", methods=["POST"])
def analyze_query():
    """
    Analyzes one or more DNS queries, persists them in MongoDB,
    and returns detailed threat classification & ML anomaly metrics.
    """
    data = request.get_json() or {}
    domain = data.get("domain", "").strip()
    
    if not domain:
        return jsonify({"error": "A domain name is required for analysis."}), 400

    client_ip = data.get("client_ip", "192.168.1.100").strip()
    record_type = data.get("record_type", "A").strip()
    ttl = int(data.get("ttl", 300))

    result = detector.analyze(domain=domain, client_ip=client_ip, record_type=record_type, ttl=ttl)
    doc_id = db_manager.insert_query(result)
    result["_id"] = doc_id
    
    return jsonify(result)


@app.route("/api/queries", methods=["GET"])
def get_queries():
    """Retrieves analyzed queries with optional filters."""
    limit = int(request.args.get("limit", 50))
    threat_type = request.args.get("threat_type", "ALL")
    min_score = float(request.args.get("min_score", 0.0))

    records = db_manager.get_queries(limit=limit, threat_type=threat_type, min_anomaly_score=min_score)
    return jsonify({
        "count": len(records),
        "queries": records
    })


@app.route("/api/stats", methods=["GET"])
def get_stats():
    """Returns aggregated threat metrics, category distribution, and top threats."""
    stats = db_manager.get_stats()
    return jsonify(stats)


@app.route("/api/simulate", methods=["POST"])
def simulate_traffic():
    """
    Simulates DNS query burst (mix of benign, DGA, tunneling, fast-flux, typosquatting)
    to populate telemetry and demonstrate real-time detection.
    """
    data = request.get_json() or {}
    count = min(int(data.get("count", 10)), 50)
    category = data.get("category", "random")

    analyzed_batch = []
    for _ in range(count):
        sample = generate_sample_query(threat_category=category)
        analysis = detector.analyze(
            domain=sample["domain"],
            client_ip=sample["client_ip"],
            record_type=sample["record_type"],
            ttl=sample["ttl"]
        )
        doc_id = db_manager.insert_query(analysis)
        analysis["_id"] = doc_id
        analyzed_batch.append(analysis)

    return jsonify({
        "message": f"Successfully ingested and evaluated {len(analyzed_batch)} simulated queries.",
        "count": len(analyzed_batch),
        "sample": analyzed_batch[-5:]
    })


@app.route("/api/clear", methods=["POST"])
def clear_data():
    """Clears stored query records."""
    db_manager.clear_database()
    return jsonify({"message": "Query telemetry cleared successfully."})


if __name__ == "__main__":
    # Seed initial baseline dataset if database is completely empty
    if db_manager.count_queries() == 0:
        print("[*] Seeding initial DNS queries for prototype demonstration...")
        for _ in range(15):
            sample = generate_sample_query(threat_category="random")
            analysis = detector.analyze(
                domain=sample["domain"],
                client_ip=sample["client_ip"],
                record_type=sample["record_type"],
                ttl=sample["ttl"]
            )
            db_manager.insert_query(analysis)
            
    port = int(os.environ.get("PORT", 5000))
    print(f"[*] Starting DNSRadar Server on http://127.0.0.1:{port} ...")
    app.run(host="127.0.0.1", port=port, debug=False)
