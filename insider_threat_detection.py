import time
from collections import defaultdict

# Mock ML WAF function
def predict_request(payload=""):
    """
    Simulates an ML model detecting payload-based attacks.
    Returns (label, confidence) where 1 is malicious and 0 is normal.
    """
    if "<script>" in payload or "UNION SELECT" in payload:
        return (1, 0.95)
    return (0, 0.99)

class InsiderThreatDetector:
    def __init__(self, score_threshold=60, rate_limit_seconds=5, rate_limit_max_requests=20):
        self.score_threshold = score_threshold
        self.rate_limit_seconds = rate_limit_seconds
        self.rate_limit_max_requests = rate_limit_max_requests
        
        # In-memory storage (mocking session/Redis)
        self.request_history = defaultdict(list)
        self.user_scores = defaultdict(int)
        self.endpoint_history = defaultdict(set)
        self.insider_threats = defaultdict(bool)
        
        # Mock MongoDB
        self.mongodb_users = {}

    def get_route_score(self, endpoint, role):
        score = 0
        admin_routes = ["/admin", "/admin/users", "/admin/orders"]
        
        if endpoint in admin_routes and role != "admin":
            score += 50
        elif "unknown" in endpoint:
            score += 20
            
        return score
        
    def check_request_rate(self, user_id):
        current_time = time.time()
        # Clean up old history outside the rate limit window
        self.request_history[user_id] = [
            t for t in self.request_history[user_id] 
            if current_time - t <= self.rate_limit_seconds
        ]
        
        self.request_history[user_id].append(current_time)
        
        # High request rate detected
        if len(self.request_history[user_id]) > self.rate_limit_max_requests:
            return 30 
        return 0

    def analyze_request(self, user_id, role, endpoint, payload=""):
        # 1. Check if user is already blocked
        if self.insider_threats.get(user_id):
            return {"action": "BLOCK", "reason": "User already flagged as insider threat"}

        # 2. Get ML Prediction (Traditional WAF)
        ml_label, ml_confidence = predict_request(payload)
        
        # 3. Calculate Behavioral Score
        behavior_score = 0
        
        # Rule A: Check Route Access/Role Mismatch
        behavior_score += self.get_route_score(endpoint, role)
        
        # Rule B: Check Request Rate (Spike detection)
        behavior_score += self.check_request_rate(user_id)
        
        # Rule C: Deviation from history (Bonus)
        # Penalize if they suddenly start hitting sensitive APIs they haven't used
        if endpoint not in self.endpoint_history[user_id] and endpoint != "/login" and len(self.endpoint_history[user_id]) > 0:
            if "/api/" in endpoint or "/admin" in endpoint:
                behavior_score += 10
            
        self.endpoint_history[user_id].add(endpoint)
        self.user_scores[user_id] += behavior_score
        total_score = self.user_scores[user_id]
        
        # 4. Final Decision combining ML + Behavior
        if total_score > self.score_threshold:
            self.insider_threats[user_id] = True
            self.update_database(user_id, endpoint, total_score, True)
            return {"action": "BLOCK", "reason": f"Behavioral Anomaly! Score: {total_score}", "score": total_score}
            
        if ml_label == 1:
            return {"action": "BLOCK", "reason": "Payload attack detected by ML WAF", "score": total_score}
            
        # 5. Allow request and update DB
        self.update_database(user_id, endpoint, total_score, False)
        return {"action": "ALLOW", "reason": "Normal request", "score": total_score}
        
    def update_database(self, user_id, endpoint, score, is_threat):
        # This simulates updating the MongoDB document for the user
        self.mongodb_users[user_id] = {
            "user_id": user_id,
            "last_endpoint": endpoint,
            "behavior_score": score,
            "is_insider_threat": is_threat
        }

# ==========================================
# 🧪 ATTACK SIMULATION
# ==========================================
def run_simulation():
    waf = InsiderThreatDetector()
    user_id = "user_123"
    role = "normal"
    
    print("--- 1. Normal Login & Browsing ---")
    print(waf.analyze_request(user_id, role, "/login"))
    print(waf.analyze_request(user_id, role, "/products"))
    print(waf.analyze_request(user_id, role, "/cart"))
    print(f"DB state: {waf.mongodb_users[user_id]}\n")
    
    print("--- 2. Accessing Restricted Route (/admin) ---")
    # Score should jump by 50 + 10 (new sensitive route) = 60
    print(waf.analyze_request(user_id, role, "/admin"))
    print(f"DB state: {waf.mongodb_users[user_id]}\n")
    
    print("--- 3. Spamming Requests (Simulating Data Scraping / DDoS) ---")
    # Generating a rapid burst of 25 requests
    for i in range(25):
        res = waf.analyze_request(user_id, role, "/products")
        if res["action"] == "BLOCK":
            print(f"Blocked at request #{i+1} due to rapid spike! Response: {res}")
            break
            
    print(f"\nFinal DB state: {waf.mongodb_users[user_id]}\n")
    
    print("--- 4. Consequent Requests ---")
    print(waf.analyze_request(user_id, role, "/products"))

if __name__ == '__main__':
    run_simulation()
