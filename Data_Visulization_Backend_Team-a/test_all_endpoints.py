import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "backend"))
from app import app

client = app.test_client()

endpoints = [
    ('/api', 'GET'),
    ('/api/events', 'GET'),
    ('/api/stats', 'GET'),
    ('/api/threats', 'GET'),
    ('/api/predictions', 'GET'),
    ('/api/predictions?limit=5', 'GET'),
    ('/api/predictions/EVT00001', 'GET'),
    ('/api/anomalies', 'GET'),
    ('/api/anomalies?limit=5', 'GET'),
    ('/api/model-performance', 'GET'),
    ('/api/threat-summary', 'GET'),
    ('/api/heatmap', 'GET'),
    ('/api/audit', 'GET'),
    ('/api/analytics', 'GET'),
    ('/api/v1/risk/summary', 'GET'),
    ('/api/risk/summary', 'GET'),
    ('/api/v1/risk/high', 'GET'),
    ('/api/risk/high', 'GET'),
    ('/api/v1/incidents', 'GET'),
    ('/api/incidents', 'GET'),
    ('/api/v1/attack-chains', 'GET'),
    ('/api/attack-chains', 'GET'),
    ('/api/me', 'GET'),
]

all_passed = True
print("-" * 75)
print("TESTING ALL BACKEND INTEGRATION ENDPOINTS")
print("-" * 75)

for ep, method in endpoints:
    res = client.get(ep)
    ok = (res.status_code == 200)
    if not ok:
        all_passed = False
    status_sym = "[PASS]" if ok else "[FAIL]"
    print(f"{status_sym} {method:4} {ep:35} -> Status: {res.status_code}, Length: {len(res.data)} bytes")

# Test POST /api/predict
pred_res = client.post('/api/predict', json={'event_type': 'Brute Force', 'failed_login_attempts': 12, 'cvss_score': 8.5, 'severity': 'Critical'})
ok_pred = (pred_res.status_code == 200)
status_pred = "[PASS]" if ok_pred else "[FAIL]"
print(f"{status_pred} POST /api/predict                         -> Status: {pred_res.status_code}, Resp: {pred_res.get_json().get('prediction')}")

# Test POST /api/v1/risk/calculate
risk_res = client.post('/api/v1/risk/calculate', json={'event_type': 'Brute Force', 'severity': 'Critical', 'confidence_score': 92, 'asset_criticality': 'Critical', 'cvss_score': 9.8, 'ioc_match': True})
ok_risk = (risk_res.status_code == 200)
status_risk = "[PASS]" if ok_risk else "[FAIL]"
print(f"{status_risk} POST /api/v1/risk/calculate                -> Status: {risk_res.status_code}, Score: {risk_res.get_json().get('risk_score')}")

# Test POST /api/v1/incidents/INC-0001/status
inc_res = client.post('/api/v1/incidents/INC-0001/status', json={'status': 'In Progress', 'feedback': 'Investigating compromised host'})
ok_inc = (inc_res.status_code == 200)
status_inc = "[PASS]" if ok_inc else "[FAIL]"
print(f"{status_inc} POST /api/v1/incidents/INC-0001/status      -> Status: {inc_res.status_code}, Status: {inc_res.get_json().get('status')}")

# Test Auth POST /api/login (admin)
login_res = client.post('/api/login', json={'identity': 'admin', 'password': 'admin123'})
ok_login = (login_res.status_code == 200)
status_login = "[PASS]" if ok_login else "[FAIL]"
print(f"{status_login} POST /api/login                           -> Status: {login_res.status_code}, User: {login_res.get_json().get('username')}")

total_ok = all_passed and ok_pred and ok_risk and ok_inc and ok_login
print("-" * 75)
print(f"OVERALL INTEGRATION TEST RESULT: {'SUCCESS (ALL PASSED)' if total_ok else 'FAILED'}")
print("-" * 75)
