import urllib.request
import json
import urllib.error
import time

def test():
    import psycopg2
    try:
        conn = psycopg2.connect("postgresql://hydra:hydra_dev_2026@postgres:5432/hydra")
        cur = conn.cursor()
        cur.execute("SELECT id FROM tenants LIMIT 1")
        tenant_id = cur.fetchone()[0]
        conn.close()
        try:
            req_reg = urllib.request.Request('http://api:8090/api/v1/auth/register', json.dumps({
                'display_name': 'Admin User',
                'tenant_id': str(tenant_id),
                'email':'admin@testcorp.com',
                'password':'password123'
            }).encode(), {'Content-Type':'application/json'})
            urllib.request.urlopen(req_reg)
        except urllib.error.HTTPError as e:
            err_body = e.read().decode()
            print("Register failed:", err_body)
            # maybe it alreay exists, proceed to login
            
        req = urllib.request.Request('http://api:8090/api/v1/auth/login', json.dumps({'email':'admin@testcorp.com','password':'password123'}).encode(), {'Content-Type':'application/json'})
        r = urllib.request.urlopen(req)
        data = json.loads(r.read())
        token = data['token']
        
        req = urllib.request.Request('http://api:8090/api/v1/tasks', json.dumps({
            'task_type': 'brute_force',
            'input': {
                'prompt': 'Investigate recent failed login spikes on the external VPN portal from 192.168.1.100.',
                'log_data': ''
            }
        }).encode(), {'Content-Type':'application/json', 'Authorization': f'Bearer {token}'})
        r = urllib.request.urlopen(req)
        task = json.loads(r.read())
        print(f"Created Task: {task}")
    except urllib.error.HTTPError as e:
        print("Failed:", e.read().decode())
    
test()
