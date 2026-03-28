import { useState, useRef, useCallback, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { Rocket, Loader2, Shield, AlertCircle, Upload, FileText, X, BookOpen } from 'lucide-react';
import { fetchPlaybooks, type Playbook, getUser, createTask, uploadTask } from '../api/client';

const INVESTIGATION_TYPES = [
    'Log Analysis',
    'Threat Hunt',
    'Incident Response',
    'Code Audit',
    'IOC Scan',
];

const ACCEPTED_EXTENSIONS = ['.csv', '.json', '.txt', '.log'];
const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB

const formatFileSize = (bytes: number): string => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
};

const NewTask = () => {
    const [prompt, setPrompt] = useState('');
    const [taskType, setTaskType] = useState('Log Analysis');
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [selectedFile, setSelectedFile] = useState<File | null>(null);
    const [dragOver, setDragOver] = useState(false);
    const [uploadProgress, setUploadProgress] = useState(0);
    const [playbookId, setPlaybookId] = useState<string | null>(null);
    const [activePlaybook, setActivePlaybook] = useState<Playbook | null>(null);
    const fileInputRef = useRef<HTMLInputElement>(null);
    const navigate = useNavigate();
    const location = useLocation();

    useEffect(() => {
        const user = getUser();
        if (user && user.role === 'viewer') {
            alert("You don't have permission to create investigations");
            navigate('/tasks');
            return;
        }

        const searchParams = new URLSearchParams(location.search);

        // Handle Quick Actions prefill
        const urlPrompt = searchParams.get('prompt');
        const urlTaskType = searchParams.get('task_type');
        if (urlPrompt) setPrompt(urlPrompt);
        if (urlTaskType) {
            const matchingType = INVESTIGATION_TYPES.find(t => t.toLowerCase() === urlTaskType.replace(/_/g, ' '));
            if (matchingType) setTaskType(matchingType);
        }

        // Handle Playbooks prefill
        const pid = searchParams.get('playbook_id');
        if (pid) {
            setPlaybookId(pid);
            fetchPlaybooks().then(pbs => {
                const pb = pbs.find(p => p.id === pid);
                if (pb) {
                    setActivePlaybook(pb);
                    const matchingType = INVESTIGATION_TYPES.find(t => t.toLowerCase() === pb.task_type.replace(/_/g, ' '));
                    if (matchingType) setTaskType(matchingType);
                    if (pb.steps && pb.steps.length > 0 && !urlPrompt) {
                        setPrompt(pb.steps[0]);
                    }
                }
            }).catch(() => { /* ignore */ });
        }
    }, [location.search, navigate]);

    const validateFile = (file: File): string | null => {
        const ext = '.' + file.name.split('.').pop()?.toLowerCase();
        if (!ACCEPTED_EXTENSIONS.includes(ext)) {
            return `Invalid file type "${ext}". Accepted: ${ACCEPTED_EXTENSIONS.join(', ')}`;
        }
        if (file.size > MAX_FILE_SIZE) {
            return `File is too large (${formatFileSize(file.size)}). Max: 10 MB`;
        }
        return null;
    };

    const handleFileSelect = (file: File) => {
        const err = validateFile(file);
        if (err) {
            setError(err);
            return;
        }
        setError(null);
        setSelectedFile(file);
    };

    const handleDrop = useCallback((e: React.DragEvent) => {
        e.preventDefault();
        setDragOver(false);
        const file = e.dataTransfer.files[0];
        if (file) handleFileSelect(file);
    }, []);

    const handleDragOver = useCallback((e: React.DragEvent) => {
        e.preventDefault();
        setDragOver(true);
    }, []);

    const handleDragLeave = useCallback((e: React.DragEvent) => {
        e.preventDefault();
        setDragOver(false);
    }, []);

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();

        if (!prompt.trim() && !selectedFile) return;

        setLoading(true);
        setError(null);
        setUploadProgress(0);

        try {
            let result;
            if (selectedFile) {
                // Simulate progress for UX
                setUploadProgress(20);
                const uploadPrompt = prompt.trim() || 'Analyze this log file for security anomalies and threats';
                setUploadProgress(40);
                result = await uploadTask(selectedFile, taskType, uploadPrompt);
                setUploadProgress(100);
            } else {
                result = await createTask(prompt, taskType, playbookId || undefined);
            }
            navigate(`/tasks/${result.task_id}`);
        } catch (err: any) {
            setError(err.message || 'Failed to launch investigation');
            setLoading(false);
            setUploadProgress(0);
        }
    };

    return (
        <div className="flex justify-center py-6">
            <div className="w-full max-w-2xl bg-[#1E293B] border border-slate-700/50 rounded-xl shadow-xl overflow-hidden p-8">
                <div className="mb-8 text-center">
                    <h1 className="text-2xl font-semibold text-white tracking-tight flex items-center justify-center">
                        <Shield className="w-5 h-5 mr-3 text-cyan-500" />
                        New Investigation
                    </h1>
                    <p className="text-slate-400 text-sm mt-3">
                        Describe the security investigation or upload a log file for analysis. Zovark will generate and execute detection scripts in an isolated sandbox.
                    </p>
                </div>

                {error && (
                    <div className="mb-6 p-4 bg-rose-500/10 border border-rose-500/20 rounded-lg flex items-start text-rose-300">
                        <AlertCircle className="w-5 h-5 mr-3 flex-shrink-0" />
                        <p className="text-sm font-medium">{error}</p>
                    </div>
                )}

                {activePlaybook && (
                    <div className="mb-6 p-4 bg-cyan-500/10 border border-cyan-500/30 rounded-xl flex items-start">
                        <div className="text-2xl mr-4">{activePlaybook.icon}</div>
                        <div className="flex-1">
                            <h3 className="text-sm font-bold text-cyan-400 flex items-center">
                                <BookOpen className="w-4 h-4 mr-1.5" />
                                Using Playbook: {activePlaybook.name}
                            </h3>
                            <p className="text-xs text-slate-300 mt-1">{activePlaybook.description}</p>
                            <div className="mt-2 flex space-x-2">
                                <span className="text-[10px] uppercase font-bold text-cyan-500/80 bg-cyan-500/10 px-2 py-0.5 rounded">
                                    {activePlaybook.steps?.length} Steps
                                </span>
                            </div>
                        </div>
                        <button
                            type="button"
                            onClick={() => {
                                setPlaybookId(null);
                                setActivePlaybook(null);
                                setPrompt('');
                            }}
                            className="p-1 text-slate-400 hover:text-white"
                        >
                            <X className="w-4 h-4" />
                        </button>
                    </div>
                )}

                <form onSubmit={handleSubmit} className="space-y-6">
                    <div>
                        <label className="block text-sm font-medium text-slate-300 mb-2">Investigation Type</label>
                        <div className="flex flex-wrap gap-3">
                            {INVESTIGATION_TYPES.map((type) => (
                                <label key={type} className="flex items-center space-x-2 cursor-pointer group">
                                    <input
                                        type="radio"
                                        name="taskType"
                                        value={type}
                                        checked={taskType === type}
                                        onChange={(e) => setTaskType(e.target.value)}
                                        className="w-4 h-4 text-cyan-500 bg-[#0B1120] border-slate-700 focus:ring-cyan-500 focus:ring-offset-[#1E293B] form-radio transition-all"
                                    />
                                    <span className={`text-sm font-medium transition-colors ${taskType === type ? 'text-white' : 'text-slate-400 group-hover:text-slate-300'}`}>
                                        {type}
                                    </span>
                                </label>
                            ))}
                        </div>
                    </div>

                    {/* File Upload Zone */}
                    <div>
                        <label className="block text-sm font-medium text-slate-300 mb-2">
                            <Upload className="w-4 h-4 inline mr-1.5 -mt-0.5" />
                            Upload Log File <span className="text-slate-500">(optional)</span>
                        </label>

                        {selectedFile ? (
                            <div className="border border-cyan-500/30 bg-cyan-500/5 rounded-xl p-4 flex items-center justify-between">
                                <div className="flex items-center space-x-3">
                                    <div className="w-10 h-10 bg-cyan-500/10 rounded-lg flex items-center justify-center">
                                        <FileText className="w-5 h-5 text-cyan-400" />
                                    </div>
                                    <div>
                                        <p className="text-sm font-medium text-white">{selectedFile.name}</p>
                                        <p className="text-xs text-slate-400">{formatFileSize(selectedFile.size)}</p>
                                    </div>
                                </div>
                                <button
                                    type="button"
                                    onClick={() => { setSelectedFile(null); setError(null); }}
                                    className="p-1.5 text-slate-400 hover:text-rose-400 hover:bg-rose-500/10 rounded-lg transition-all"
                                >
                                    <X className="w-4 h-4" />
                                </button>
                            </div>
                        ) : (
                            <div
                                onDrop={handleDrop}
                                onDragOver={handleDragOver}
                                onDragLeave={handleDragLeave}
                                onClick={() => fileInputRef.current?.click()}
                                className={`border-2 border-dashed rounded-xl p-6 text-center cursor-pointer transition-all duration-200
                                    ${dragOver
                                        ? 'border-cyan-500 bg-cyan-500/10'
                                        : 'border-slate-700 hover:border-slate-500 bg-[#0B1120]'
                                    }`}
                            >
                                <Upload className={`w-8 h-8 mx-auto mb-3 transition-colors ${dragOver ? 'text-cyan-400' : 'text-slate-600'}`} />
                                <p className="text-sm text-slate-400">
                                    <span className="text-cyan-400 font-medium">Click to upload</span> or drag and drop
                                </p>
                                <p className="text-xs text-slate-600 mt-1">CSV, JSON, TXT, LOG — Max 10 MB</p>
                            </div>
                        )}

                        <input
                            ref={fileInputRef}
                            type="file"
                            accept=".csv,.json,.txt,.log"
                            onChange={(e) => {
                                const file = e.target.files?.[0];
                                if (file) handleFileSelect(file);
                                e.target.value = '';
                            }}
                            className="hidden"
                        />
                    </div>

                    {/* Upload Progress */}
                    {loading && selectedFile && uploadProgress > 0 && uploadProgress < 100 && (
                        <div className="space-y-1">
                            <div className="flex justify-between text-xs text-slate-400">
                                <span>Uploading...</span>
                                <span>{uploadProgress}%</span>
                            </div>
                            <div className="w-full bg-slate-700 rounded-full h-1.5">
                                <div
                                    className="bg-cyan-500 h-1.5 rounded-full transition-all duration-300"
                                    style={{ width: `${uploadProgress}%` }}
                                />
                            </div>
                        </div>
                    )}

                    <div className="relative group">
                        <div className="absolute -inset-0.5 bg-gradient-to-r from-cyan-500/20 to-blue-500/20 rounded-xl blur opacity-0 group-focus-within:opacity-100 transition duration-500"></div>
                        <div className="relative border border-slate-700 rounded-xl shadow-sm focus-within:border-cyan-500 transition-all bg-[#0B1120]">
                            <textarea
                                id="prompt"
                                rows={6}
                                className="w-full bg-transparent text-slate-200 placeholder-slate-600 p-5 border-none focus:ring-0 resize-none text-base rounded-xl leading-relaxed"
                                placeholder={selectedFile
                                    ? "What should Zovark analyze in this file? (leave blank for default analysis)"
                                    : "Describe the security investigation or analysis you need..."
                                }
                                value={prompt}
                                onChange={(e) => setPrompt(e.target.value)}
                                disabled={loading}
                                autoFocus
                            />
                        </div>
                    </div>

                    <div className="pt-2">
                        <button
                            type="submit"
                            disabled={loading || (!prompt.trim() && !selectedFile)}
                            className="w-full flex justify-center items-center py-4 border border-transparent rounded-lg shadow-md text-sm font-semibold text-white bg-cyan-600 hover:bg-cyan-500 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-cyan-500 focus:ring-offset-[#1E293B] disabled:opacity-50 disabled:cursor-not-allowed transition-all"
                        >
                            {loading ? (
                                <>
                                    <Loader2 className="w-5 h-5 mr-2 animate-spin" />
                                    {selectedFile ? 'Uploading & Launching...' : 'Launching...'}
                                </>
                            ) : (
                                <>
                                    {selectedFile ? (
                                        <Upload className="w-5 h-5 mr-2" />
                                    ) : (
                                        <Rocket className="w-5 h-5 mr-2" />
                                    )}
                                    {selectedFile ? 'Upload & Launch Investigation' : 'Launch Investigation'}
                                </>
                            )}
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
};

export default NewTask;
