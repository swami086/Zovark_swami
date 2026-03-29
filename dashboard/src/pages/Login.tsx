import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { login } from '../api/client';
import { Loader2 } from 'lucide-react';

const Login = () => {
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(false);
    const navigate = useNavigate();

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setError('');
        setLoading(true);

        try {
            await login(email, password);
            navigate('/');
        } catch (err: any) {
            setError(err.message || 'Login failed');
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="min-h-screen flex flex-col justify-center py-12 sm:px-6 lg:px-8" style={{background: '#060A14'}}>
            <div className="sm:mx-auto sm:w-full sm:max-w-md text-center">
                <img
                    src="/zovark-logo.png"
                    alt="Zovark"
                    className="w-24 h-24 mx-auto mb-4 object-contain"
                />
                <h1
                    className="text-2xl font-bold tracking-wide text-white"
                    style={{fontFamily: "'JetBrains Mono', monospace"}}
                >
                    Sign in to ZOVARK
                </h1>
                <p
                    className="text-sm mt-1 tracking-[0.15em] uppercase"
                    style={{color: '#00FF88', fontFamily: "'JetBrains Mono', monospace"}}
                >
                    Security Operations Platform
                </p>
            </div>

            <div className="mt-8 sm:mx-auto sm:w-full sm:max-w-md">
                <div className="py-8 px-4 sm:rounded-xl sm:px-10" style={{background: '#0D1117', border: '1px solid #1B2432'}}>
                    <form className="space-y-6" onSubmit={handleSubmit}>
                        {error && (
                            <div className="text-sm font-medium px-4 py-3 rounded-md mb-6" style={{background: 'rgba(255,68,68,0.08)', border: '1px solid rgba(255,68,68,0.3)', color: '#FF4444'}}>
                                {error}
                            </div>
                        )}
                        <div>
                            <label className="block text-[11px] font-medium uppercase tracking-[0.15em] mb-2" style={{color: '#94A3B8', fontFamily: "'JetBrains Mono', monospace"}}>
                                Email address
                            </label>
                            <input
                                type="email"
                                required
                                value={email}
                                onChange={(e) => setEmail(e.target.value)}
                                className="appearance-none block w-full px-4 py-3 rounded-lg text-sm text-white focus:outline-none transition-all"
                                style={{background: '#131B27', border: '1px solid #1B2432', fontFamily: "'JetBrains Mono', monospace"}}
                                onFocus={(e) => e.target.style.borderColor = '#00FF88'}
                                onBlur={(e) => e.target.style.borderColor = '#1B2432'}
                                placeholder="analyst@security.corp"
                            />
                        </div>

                        <div>
                            <label className="block text-[11px] font-medium uppercase tracking-[0.15em] mb-2" style={{color: '#94A3B8', fontFamily: "'JetBrains Mono', monospace"}}>
                                Password
                            </label>
                            <input
                                type="password"
                                required
                                value={password}
                                onChange={(e) => setPassword(e.target.value)}
                                className="appearance-none block w-full px-4 py-3 rounded-lg text-sm text-white focus:outline-none transition-all"
                                style={{background: '#131B27', border: '1px solid #1B2432', fontFamily: "'JetBrains Mono', monospace"}}
                                onFocus={(e) => e.target.style.borderColor = '#00FF88'}
                                onBlur={(e) => e.target.style.borderColor = '#1B2432'}
                                placeholder="••••••••"
                            />
                        </div>

                        <div>
                            <button
                                type="submit"
                                disabled={loading}
                                className="w-full flex justify-center py-3 px-4 rounded-lg text-sm font-semibold uppercase tracking-[0.08em] disabled:opacity-50 disabled:cursor-not-allowed transition-all"
                                style={{
                                    background: 'transparent',
                                    border: '1px solid #00FF88',
                                    color: '#00FF88',
                                    fontFamily: "'JetBrains Mono', monospace",
                                }}
                                onMouseEnter={(e) => (e.target as HTMLElement).style.background = 'rgba(0,255,136,0.1)'}
                                onMouseLeave={(e) => (e.target as HTMLElement).style.background = 'transparent'}
                            >
                                {loading ? <Loader2 className="w-5 h-5 animate-spin" /> : 'SIGN IN'}
                            </button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    );
};

export default Login;
