const API_URL = 'http://api:8090/api/v1';

async function login(email, password) {
    const res = await fetch(`${API_URL}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
    });
    const data = await res.json();
    return data.token;
}

async function testRBAC() {
    console.log("Starting RBAC Verification...");

    const users = {
        admin: { email: 'admin@testcorp.com', pass: 'password123' },
        analyst: { email: 'demouser2@testcorp.com', pass: 'password123' },
        viewer: { email: 'viewer@testcorp.com', pass: 'password123' }
    };

    const tokens = {};
    for (const [role, creds] of Object.entries(users)) {
        try {
            tokens[role] = await login(creds.email, creds.pass);
            console.log(`[+] Logged in as ${role}`);
            console.log(Buffer.from(tokens[role].split('.')[1], 'base64').toString());
        } catch (e) {
            console.error(`[-] Failed to login as ${role}`);
        }
    }

    // Test POST /playbooks
    console.log("\n--- Testing POST /playbooks ---");
    for (const role of ['admin', 'analyst', 'viewer']) {
        const res = await fetch(`${API_URL}/playbooks`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${tokens[role]}`
            },
            body: JSON.stringify({
                name: `Test Playbook - ${role}`,
                task_type: "log_analysis",
                steps: ["test step"]
            })
        });
        console.log(`[${role.toUpperCase()}] POST /playbooks: HTTP ${res.status}`);
    }

    // Test POST /tasks
    console.log("\n--- Testing POST /tasks ---");
    for (const role of ['admin', 'analyst', 'viewer']) {
        const res = await fetch(`${API_URL}/tasks`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${tokens[role]}`
            },
            body: JSON.stringify({
                task_type: "log_analysis",
                input: { prompt: "Test investigation" }
            })
        });
        console.log(`[${role.toUpperCase()}] POST /tasks: HTTP ${res.status}`);
    }
}

testRBAC();
