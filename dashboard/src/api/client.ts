export const API_BASE_URL = 'http://localhost:8090/api/v1';

let jwtToken: string | null = localStorage.getItem('hydra_token');
let currentUser: any = localStorage.getItem('hydra_user') ? JSON.parse(localStorage.getItem('hydra_user')!) : null;

export const setToken = (token: string, user: any) => {
    jwtToken = token;
    currentUser = user;
    localStorage.setItem('hydra_token', token);
    localStorage.setItem('hydra_user', JSON.stringify(user));
};

export const clearToken = () => {
    jwtToken = null;
    currentUser = null;
    localStorage.removeItem('hydra_token');
    localStorage.removeItem('hydra_user');
};

export const getUser = () => currentUser;

const getHeaders = () => {
    const headers: Record<string, string> = {
        'Content-Type': 'application/json',
    };
    if (jwtToken) {
        headers['Authorization'] = `Bearer ${jwtToken}`;
    }
    return headers;
};

export interface Task {
    id: string;
    status: 'pending' | 'executing' | 'completed' | 'failed' | 'awaiting_approval' | 'rejected';
    task_type: string;
    created_at: string;
    execution_ms?: number;
    severity?: 'critical' | 'high' | 'medium' | 'low' | 'informational';
}

export interface TaskDetail extends Task {
    input: {
        prompt: string;
    };
    output?: {
        code?: string;
        stdout?: string;
        step_count?: number;
    };
    tokens_used_input?: number;
    tokens_used_output?: number;
    step_count?: number;
    current_step?: number;
    approval_status?: string;
    pending_approval_id?: string;
    approval_risk_level?: string;
    approval_reason?: string;
}

export interface ApprovalRequest {
    id: string;
    task_id: string;
    step_number: number;
    requested_at: string;
    status: string;
    risk_level: string;
    action_summary: string;
    generated_code: string;
    task_type: string;
    prompt: string;
    severity?: string;
}

export interface InvestigationStep {
    id: string;
    step_number: number;
    step_type: string;
    prompt: string;
    generated_code?: string;
    output?: string;
    status: string;
    tokens_used_input: number;
    tokens_used_output: number;
    execution_ms?: number;
    created_at: string;
    completed_at?: string;
    execution_mode?: string;
    parameters_used?: any;
}

export interface AuditEntry {
    action: string;
    timestamp: string;
    details: any;
}

export interface Playbook {
    id: string;
    tenant_id?: string;
    name: string;
    description?: string;
    icon: string;
    task_type: string;
    is_template: boolean;
    system_prompt_override?: string;
    steps: string[];
    created_at: string;
}

export interface Stats {
    total_tasks: number;
    completed: number;
    failed: number;
    pending: number;
    executing: number;
    total_tokens_input: number;
    total_tokens_output: number;
    type_distribution: Record<string, number>;
    siem_alerts_total: number;
    siem_alerts_new: number;
    siem_alerts_investigating: number;
    recent_activity: Array<{ id: string; status: string; task_type: string; created_at: string; prompt?: string }>;
}

export interface TaskListResponse {
    tasks: Task[];
    total: number;
    page: number;
    limit: number;
    pages: number;
}

export const fetchTasks = async (params?: Record<string, string>): Promise<TaskListResponse> => {
    let url = `${API_BASE_URL}/tasks`;
    if (params) {
        const qs = new URLSearchParams();
        for (const [k, v] of Object.entries(params)) {
            if (v) qs.set(k, v);
        }
        const str = qs.toString();
        if (str) url += `?${str}`;
    }
    const response = await fetch(url, {
        headers: getHeaders(),
        cache: 'no-store'
    });
    if (response.status === 401 || response.status === 403) throw new Error("Unauthorized");
    if (!response.ok) throw new Error('Failed to fetch tasks');
    return response.json();
};

export const fetchTaskDetail = async (id: string): Promise<TaskDetail> => {
    const response = await fetch(`${API_BASE_URL}/tasks/${id}`, {
        headers: getHeaders(),
        cache: 'no-store'
    });
    if (response.status === 401 || response.status === 403) throw new Error("Unauthorized");
    if (!response.ok) {
        throw new Error('Failed to fetch task details');
    }
    const data = await response.json();
    // Re-map the API's task_id to id for the frontend
    if (data.task_id && !data.id) {
        data.id = data.task_id;
    }
    return data;
};

export const fetchTaskSteps = async (id: string): Promise<InvestigationStep[]> => {
    const response = await fetch(`${API_BASE_URL}/tasks/${id}/steps`, {
        headers: getHeaders(),
        cache: 'no-store'
    });
    if (response.status === 401 || response.status === 403) throw new Error("Unauthorized");
    if (!response.ok) {
        throw new Error('Failed to fetch task steps');
    }
    const data = await response.json();
    return data.steps || [];
};

export interface TimelineEvent {
    id: string;
    timestamp: string;
    type: string;
    icon: string;
    description: string;
    duration_ms?: number;
}

export const fetchTaskTimeline = async (id: string): Promise<TimelineEvent[]> => {
    const response = await fetch(`${API_BASE_URL}/tasks/${id}/timeline`, {
        headers: getHeaders(),
        cache: 'no-store'
    });
    if (response.status === 401 || response.status === 403) throw new Error("Unauthorized");
    if (!response.ok) return [];
    try {
        const data = await response.json();
        return data.timeline || [];
    } catch {
        return [];
    }
};

export const fetchPendingApprovals = async (): Promise<{ approvals: ApprovalRequest[], count: number }> => {
    const response = await fetch(`${API_BASE_URL}/approvals/pending`, {
        headers: getHeaders(),
        cache: 'no-store'
    });
    if (response.status === 401 || response.status === 403) throw new Error("Unauthorized");
    if (!response.ok) throw new Error('Failed to fetch approvals');
    return response.json();
};

export const decideApproval = async (approvalId: string, approved: boolean, comment: string): Promise<any> => {
    const response = await fetch(`${API_BASE_URL}/approvals/${approvalId}/decide`, {
        method: 'POST',
        headers: getHeaders(),
        body: JSON.stringify({ approved, comment })
    });
    if (response.status === 401 || response.status === 403) throw new Error("Unauthorized");
    if (!response.ok) throw new Error('Failed to submit approval decision');
    return response.json();
};

export const createTask = async (prompt: string, taskType: string = 'Log Analysis', playbookId?: string): Promise<{ task_id: string }> => {
    const payload: any = {
        task_type: taskType,
        input: { prompt }
    };
    if (playbookId) {
        payload.input.playbook_id = playbookId;
    }
    const response = await fetch(`${API_BASE_URL}/tasks`, {
        method: 'POST',
        headers: getHeaders(),
        body: JSON.stringify(payload),
    });

    if (!response.ok) {
        throw new Error('Failed to create task');
    }
    return response.json();
};

export const uploadTask = async (
    file: File,
    taskType: string = 'Log Analysis',
    prompt: string = 'Analyze this log file for security anomalies and threats'
): Promise<{ task_id: string }> => {
    const formData = new FormData();
    formData.append('file', file);
    formData.append('task_type', taskType);
    formData.append('prompt', prompt);

    const headers: Record<string, string> = {};
    if (jwtToken) {
        headers['Authorization'] = `Bearer ${jwtToken}`;
    }

    const response = await fetch(`${API_BASE_URL}/tasks/upload`, {
        method: 'POST',
        headers,
        body: formData,
    });

    if (!response.ok) {
        const data = await response.json().catch(() => ({}));
        throw new Error(data.error || 'Failed to upload file');
    }
    return response.json();
};

export const fetchTaskAudit = async (id: string): Promise<AuditEntry[]> => {
    const response = await fetch(`${API_BASE_URL}/tasks/${id}/audit`, {
        headers: getHeaders(),
        cache: 'no-store'
    });
    if (response.status === 401 || response.status === 403) throw new Error("Unauthorized");
    if (!response.ok) {
        throw new Error('Failed to fetch task audit log');
    }
    const data = await response.json();
    return data.audit_trail || [];
};

export const fetchStats = async (): Promise<Stats> => {
    const response = await fetch(`${API_BASE_URL}/stats`, {
        headers: getHeaders(),
        cache: 'no-store'
    });
    if (response.status === 401 || response.status === 403) throw new Error("Unauthorized");
    if (!response.ok) {
        throw new Error('Failed to fetch stats');
    }
    return response.json();
};

export const login = async (email: string, password: string): Promise<any> => {
    const response = await fetch(`${API_BASE_URL}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
    });

    if (!response.ok) {
        throw new Error('Invalid credentials');
    }

    const data = await response.json();
    setToken(data.token, data.user);
    return data.user;
};

export const register = async (email: string, password: string, display_name: string, tenant_id: string): Promise<any> => {
    const response = await fetch(`${API_BASE_URL}/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password, display_name, tenant_id }),
    });

    if (!response.ok) {
        throw new Error('Failed to register');
    }

    return response.json();
};

export const fetchPlaybooks = async (): Promise<Playbook[]> => {
    const response = await fetch(`${API_BASE_URL}/playbooks`, {
        headers: getHeaders(),
        cache: 'no-store'
    });
    if (response.status === 401 || response.status === 403) throw new Error("Unauthorized");
    if (!response.ok) throw new Error('Failed to fetch playbooks');
    return response.json();
};

export const createPlaybook = async (data: any): Promise<Playbook> => {
    const response = await fetch(`${API_BASE_URL}/playbooks`, {
        method: 'POST',
        headers: getHeaders(),
        body: JSON.stringify(data)
    });
    if (response.status === 401 || response.status === 403) throw new Error("Unauthorized");
    if (!response.ok) throw new Error('Failed to create playbook');
    return response.json();
};

export const updatePlaybook = async (id: string, data: any): Promise<any> => {
    const response = await fetch(`${API_BASE_URL}/playbooks/${id}`, {
        method: 'PUT',
        headers: getHeaders(),
        body: JSON.stringify(data)
    });
    if (response.status === 401 || response.status === 403) throw new Error("Unauthorized");
    if (!response.ok) throw new Error('Failed to update playbook');
    return response.json();
};

export const deletePlaybook = async (id: string): Promise<any> => {
    const response = await fetch(`${API_BASE_URL}/playbooks/${id}`, {
        method: 'DELETE',
        headers: getHeaders()
    });
    if (response.status === 401 || response.status === 403) throw new Error("Unauthorized");
    if (!response.ok) throw new Error('Failed to delete playbook');
    return response.json();
};

export interface Skill {
    id: string;
    skill_name: string;
    skill_slug: string;
    threat_types: string[];
    mitre_tactics: string[];
    mitre_techniques: string[];
    severity_default: string;
    investigation_methodology: string;
    detection_patterns: string;
    example_prompt: string;
    times_used: number;
    version: number;
    is_community: boolean;
    has_template?: boolean;
}

export const fetchSkills = async (): Promise<{ skills: Skill[], count: number }> => {
    const response = await fetch(`${API_BASE_URL}/skills`, {
        headers: getHeaders(),
        cache: 'no-store'
    });
    if (response.status === 401 || response.status === 403) throw new Error("Unauthorized");
    if (!response.ok) throw new Error('Failed to fetch skills');
    return response.json();
};

export interface LogSource {
    id: string;
    name: string;
    source_type: string;
    connection_config: Record<string, any>;
    is_active: boolean;
    last_event_at?: string;
    event_count: number;
    created_at: string;
    webhook_url: string;
}

export interface SIEMAlert {
    id: string;
    log_source_id: string;
    task_id?: string;
    alert_name: string;
    severity?: string;
    source_ip?: string;
    dest_ip?: string;
    rule_name?: string;
    status: string;
    auto_investigate: boolean;
    created_at: string;
}

export const fetchLogSources = async (): Promise<{ sources: LogSource[], count: number }> => {
    const response = await fetch(`${API_BASE_URL}/log-sources`, {
        headers: getHeaders(),
        cache: 'no-store'
    });
    if (response.status === 401 || response.status === 403) throw new Error("Unauthorized");
    if (!response.ok) throw new Error('Failed to fetch log sources');
    return response.json();
};

export const createLogSource = async (data: any): Promise<any> => {
    const response = await fetch(`${API_BASE_URL}/log-sources`, {
        method: 'POST',
        headers: getHeaders(),
        body: JSON.stringify(data)
    });
    if (response.status === 401 || response.status === 403) throw new Error("Unauthorized");
    if (!response.ok) throw new Error('Failed to create log source');
    return response.json();
};

export const fetchSIEMAlerts = async (status?: string, sourceId?: string): Promise<{ alerts: SIEMAlert[], count: number }> => {
    let url = `${API_BASE_URL}/siem-alerts`;
    const params = new URLSearchParams();
    if (status) params.set('status', status);
    if (sourceId) params.set('source_id', sourceId);
    const qs = params.toString();
    if (qs) url += `?${qs}`;

    const response = await fetch(url, {
        headers: getHeaders(),
        cache: 'no-store'
    });
    if (response.status === 401 || response.status === 403) throw new Error("Unauthorized");
    if (!response.ok) throw new Error('Failed to fetch SIEM alerts');
    return response.json();
};

export const investigateAlert = async (alertId: string): Promise<any> => {
    const response = await fetch(`${API_BASE_URL}/siem-alerts/${alertId}/investigate`, {
        method: 'POST',
        headers: getHeaders()
    });
    if (response.status === 401 || response.status === 403) throw new Error("Unauthorized");
    if (!response.ok) throw new Error('Failed to investigate alert');
    return response.json();
};

export interface Notification {
    id: string;
    type: 'task_completed' | 'approval_requested' | 'siem_alert';
    message: string;
    task_id?: string;
    timestamp: string;
}

export const fetchNotifications = async (since?: string): Promise<Notification[]> => {
    let url = `${API_BASE_URL}/notifications`;
    if (since) {
        url += `?since=${encodeURIComponent(since)}`;
    }
    const response = await fetch(url, { headers: getHeaders(), cache: 'no-store' });
    if (!response.ok) return [];
    try {
        const data = await response.json();
        return data.notifications || [];
    } catch (e) {
        return [];
    }
};
