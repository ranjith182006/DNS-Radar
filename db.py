"""
MongoDB Database adapter with transparent local fallback.
If MongoDB is active (default 'mongodb://localhost:27017/'), it uses pymongo.
If MongoDB is unreachable, it seamlessly stores records in a persistent JSON document store
without crashing the application, and notifies the caller of its connection mode.
"""

import os
import json
import uuid
import datetime
from typing import Dict, List, Any, Optional

try:
    from pymongo import MongoClient, DESCENDING
    from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError
    PYMONGO_AVAILABLE = True
except ImportError:
    PYMONGO_AVAILABLE = False


class DatabaseManager:
    def __init__(self, uri: str = "mongodb://localhost:27017/", db_name: str = "dns_threat_db"):
        self.uri = os.environ.get("MONGO_URI", uri)
        self.db_name = db_name
        self.client: Optional[Any] = None
        self.db: Optional[Any] = None
        self.is_connected: bool = False
        self.connection_error: Optional[str] = None
        
        # Local JSON fallback store path
        self.data_dir = os.path.join(os.path.dirname(__file__), "data")
        os.makedirs(self.data_dir, exist_ok=True)
        self.fallback_file = os.path.join(self.data_dir, "fallback_db.json")
        self._init_fallback()
        
        # Attempt initial Mongo connection
        self.connect(self.uri)

    def _init_fallback(self):
        if not os.path.exists(self.fallback_file):
            default_data = {
                "queries": [],
                "alerts": [],
                "patterns": []
            }
            with open(self.fallback_file, "w", encoding="utf-8") as f:
                json.dump(default_data, f, indent=2)

    def _load_fallback(self) -> Dict[str, List[Any]]:
        try:
            with open(self.fallback_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {"queries": [], "alerts": [], "patterns": []}

    def _save_fallback(self, data: Dict[str, List[Any]]):
        with open(self.fallback_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)

    def connect(self, uri: str) -> bool:
        self.uri = uri
        if not PYMONGO_AVAILABLE:
            self.is_connected = False
            self.connection_error = "pymongo package is not installed."
            return False

        try:
            client = MongoClient(self.uri, serverSelectionTimeoutMS=1500)
            # Ping database to verify connection
            client.admin.command('ping')
            self.client = client
            self.db = client[self.db_name]
            self.is_connected = True
            self.connection_error = None
            
            # Ensure indexes
            self.db.queries.create_index([("timestamp", DESCENDING)])
            self.db.queries.create_index("domain")
            self.db.queries.create_index("threat_type")
            return True
        except (ConnectionFailure, ServerSelectionTimeoutError, Exception) as e:
            self.is_connected = False
            self.client = None
            self.db = None
            self.connection_error = str(e)
            return False

    def get_status(self) -> Dict[str, Any]:
        return {
            "is_mongo_connected": self.is_connected,
            "mode": "MongoDB (" + self.uri + ")" if self.is_connected else "Local File-Backed Mock Store (Active)",
            "db_name": self.db_name,
            "error": self.connection_error,
            "total_queries": self.count_queries()
        }

    def insert_query(self, record: Dict[str, Any]) -> str:
        doc = dict(record)
        if "_id" not in doc:
            doc["_id"] = str(uuid.uuid4())
        if "timestamp" not in doc:
            doc["timestamp"] = datetime.datetime.now(datetime.timezone.utc).isoformat()

        if self.is_connected and self.db is not None:
            try:
                self.db.queries.insert_one(doc)
                return str(doc["_id"])
            except Exception as e:
                # If mongo fails mid-operation, fallback
                self.is_connected = False
                self.connection_error = str(e)

        # Fallback store
        data = self._load_fallback()
        data["queries"].insert(0, doc)
        # Cap local queries to recent 1000 to prevent unbounded file growth
        if len(data["queries"]) > 1000:
            data["queries"] = data["queries"][:1000]
        self._save_fallback(data)
        return str(doc["_id"])

    def insert_queries_batch(self, records: List[Dict[str, Any]]) -> int:
        count = 0
        for r in records:
            self.insert_query(r)
            count += 1
        return count

    def get_queries(self, limit: int = 50, threat_type: Optional[str] = None, min_anomaly_score: float = 0.0) -> List[Dict[str, Any]]:
        if self.is_connected and self.db is not None:
            try:
                filter_q: Dict[str, Any] = {}
                if threat_type and threat_type != "ALL":
                    filter_q["threat_type"] = threat_type
                if min_anomaly_score > 0:
                    filter_q["anomaly_score"] = {"$gte": min_anomaly_score}

                cursor = self.db.queries.find(filter_q).sort("timestamp", DESCENDING).limit(limit)
                docs = list(cursor)
                for d in docs:
                    d["_id"] = str(d["_id"])
                return docs
            except Exception:
                pass

        # Fallback
        data = self._load_fallback()
        results = []
        for q in data.get("queries", []):
            if threat_type and threat_type != "ALL" and q.get("threat_type") != threat_type:
                continue
            if q.get("anomaly_score", 0) < min_anomaly_score:
                continue
            results.append(q)
            if len(results) >= limit:
                break
        return results

    def count_queries(self) -> int:
        if self.is_connected and self.db is not None:
            try:
                return self.db.queries.count_documents({})
            except Exception:
                pass
        data = self._load_fallback()
        return len(data.get("queries", []))

    def get_stats(self) -> Dict[str, Any]:
        queries = self.get_queries(limit=1000)
        total = len(queries)
        if total == 0:
            return {
                "total_queries": 0,
                "anomalies_detected": 0,
                "anomaly_rate": 0.0,
                "threat_breakdown": {},
                "top_anomalous_domains": [],
                "score_distribution": {"safe": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
            }

        anomalies = [q for q in queries if q.get("is_anomaly", False)]
        threat_breakdown: Dict[str, int] = {}
        distribution = {"safe": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}

        for q in queries:
            tt = q.get("threat_type", "Benign")
            threat_breakdown[tt] = threat_breakdown.get(tt, 0) + 1
            
            score = q.get("anomaly_score", 0.0)
            if score < 0.25:
                distribution["safe"] += 1
            elif score < 0.5:
                distribution["low"] += 1
            elif score < 0.7:
                distribution["medium"] += 1
            elif score < 0.85:
                distribution["high"] += 1
            else:
                distribution["critical"] += 1

        top_anomalous = sorted(anomalies, key=lambda x: x.get("anomaly_score", 0.0), reverse=True)[:10]

        return {
            "total_queries": total,
            "anomalies_detected": len(anomalies),
            "anomaly_rate": round((len(anomalies) / total * 100), 2) if total > 0 else 0.0,
            "threat_breakdown": threat_breakdown,
            "top_anomalous_domains": top_anomalous,
            "score_distribution": distribution
        }

    def clear_database(self) -> bool:
        if self.is_connected and self.db is not None:
            try:
                self.db.queries.delete_many({})
            except Exception:
                pass
        self._save_fallback({"queries": [], "alerts": [], "patterns": []})
        return True


# Global instance
db_manager = DatabaseManager()
