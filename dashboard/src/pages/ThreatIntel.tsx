import { useEffect, useState } from 'react';
import { Shield, Search, ChevronDown, ChevronUp, Zap, Target, Eye, BookOpen } from 'lucide-react';
import { fetchSkills, type Skill } from '../api/client';

const tacticLabels: Record<string, string> = {
    TA0001: 'Initial Access', TA0002: 'Execution', TA0003: 'Persistence',
    TA0004: 'Privilege Escalation', TA0005: 'Defense Evasion', TA0006: 'Credential Access',
    TA0007: 'Discovery', TA0008: 'Lateral Movement', TA0009: 'Collection',
    TA0010: 'Exfiltration', TA0011: 'Command and Control', TA0040: 'Impact',
    TA0043: 'Reconnaissance',
};

const severityColors: Record<string, string> = {
    critical: 'bg-rose-500/20 text-rose-400 border-rose-500/30',
    high: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
    medium: 'bg-amber-500/20 text-amber-400 border-amber-500/30',
    low: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30',
};

const SkillCard = ({ skill }: { skill: Skill }) => {
    const [expanded, setExpanded] = useState(false);

    return (
        <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl overflow-hidden hover:border-cyan-500/30 transition-all duration-300">
            <div
                className="p-5 cursor-pointer"
                onClick={() => setExpanded(!expanded)}
            >
                <div className="flex items-start justify-between mb-3">
                    <div className="flex items-center space-x-3">
                        <div className="w-10 h-10 rounded-lg bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center">
                            <Shield className="w-5 h-5 text-cyan-400" />
                        </div>
                        <div>
                            <h3 className="text-white font-semibold text-base">{skill.skill_name}</h3>
                            <span className="text-slate-500 text-xs font-mono">{skill.skill_slug}</span>
                        </div>
                    </div>
                    <div className="flex items-center space-x-3">
                        <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full uppercase border ${severityColors[skill.severity_default] || severityColors.medium}`}>
                            {skill.severity_default}
                        </span>
                        {skill.has_template ? (
                            <span className="text-[10px] font-bold px-2 py-0.5 rounded-full uppercase border bg-emerald-500/10 text-emerald-400 border-emerald-500/30">
                                Executable
                            </span>
                        ) : (
                            <span className="text-[10px] font-bold px-2 py-0.5 rounded-full uppercase border bg-slate-500/10 text-slate-400 border-slate-500/30">
                                Methodology Only
                            </span>
                        )}
                        {expanded ? <ChevronUp className="w-4 h-4 text-slate-500" /> : <ChevronDown className="w-4 h-4 text-slate-500" />}
                    </div>
                </div>

                {/* Tags row */}
                <div className="flex flex-wrap gap-1.5 mb-3">
                    {skill.threat_types.map((t: string) => (
                        <span key={t} className="px-2 py-0.5 rounded text-[10px] font-medium bg-violet-500/10 text-violet-400 border border-violet-500/20">
                            {t.replace(/_/g, ' ')}
                        </span>
                    ))}
                </div>

                {/* MITRE row */}
                <div className="flex flex-wrap gap-1.5 mb-3">
                    {skill.mitre_tactics.map((t: string) => (
                        <span key={t} className="px-2 py-0.5 rounded text-[10px] font-medium bg-blue-500/10 text-blue-400 border border-blue-500/20">
                            {tacticLabels[t] || t}
                        </span>
                    ))}
                    {skill.mitre_techniques.map((t: string) => (
                        <span key={t} className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-700/50 text-slate-400 border border-slate-600/30">
                            {t}
                        </span>
                    ))}
                </div>

                {/* Stats row */}
                <div className="flex items-center space-x-4 text-xs text-slate-500">
                    <span className="flex items-center space-x-1">
                        <Zap className="w-3 h-3" />
                        <span>{skill.times_used.toLocaleString()} uses</span>
                    </span>
                    <span className="flex items-center space-x-1">
                        <Target className="w-3 h-3" />
                        <span>v{skill.version}</span>
                    </span>
                    {skill.is_community && (
                        <span className="flex items-center space-x-1 text-emerald-500">
                            <Eye className="w-3 h-3" />
                            <span>Community</span>
                        </span>
                    )}
                </div>
            </div>

            {/* Expanded detail */}
            {expanded && (
                <div className="border-t border-slate-700/50 px-5 py-4 space-y-4 bg-slate-900/30">
                    <div>
                        <h4 className="text-cyan-400 text-xs font-semibold uppercase tracking-wider mb-2 flex items-center space-x-1.5">
                            <BookOpen className="w-3.5 h-3.5" />
                            <span>Investigation Methodology</span>
                        </h4>
                        <pre className="text-slate-300 text-xs leading-relaxed whitespace-pre-wrap font-sans bg-slate-800/50 rounded-lg p-3 border border-slate-700/30 max-h-[300px] overflow-y-auto">
                            {skill.investigation_methodology}
                        </pre>
                    </div>

                    <div>
                        <h4 className="text-amber-400 text-xs font-semibold uppercase tracking-wider mb-2 flex items-center space-x-1.5">
                            <Target className="w-3.5 h-3.5" />
                            <span>Detection Patterns</span>
                        </h4>
                        <pre className="text-slate-300 text-xs leading-relaxed whitespace-pre-wrap font-sans bg-slate-800/50 rounded-lg p-3 border border-slate-700/30 max-h-[250px] overflow-y-auto">
                            {skill.detection_patterns}
                        </pre>
                    </div>

                    <div>
                        <h4 className="text-violet-400 text-xs font-semibold uppercase tracking-wider mb-2">Example Prompt</h4>
                        <p className="text-slate-300 text-sm italic bg-violet-500/5 rounded-lg p-3 border border-violet-500/10">
                            "{skill.example_prompt}"
                        </p>
                    </div>
                </div>
            )}
        </div>
    );
};

const ThreatIntel = () => {
    const [skills, setSkills] = useState<Skill[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [searchTerm, setSearchTerm] = useState('');

    useEffect(() => {
        const load = async () => {
            try {
                setLoading(true);
                const data = await fetchSkills();
                setSkills(data.skills || []);
            } catch (e: any) {
                setError(e.message);
            } finally {
                setLoading(false);
            }
        };
        load();
    }, []);

    const filtered = skills.filter(s => {
        if (!searchTerm) return true;
        const q = searchTerm.toLowerCase();
        return (
            s.skill_name.toLowerCase().includes(q) ||
            s.skill_slug.toLowerCase().includes(q) ||
            s.threat_types.some(t => t.toLowerCase().includes(q)) ||
            s.mitre_techniques.some(t => t.toLowerCase().includes(q)) ||
            s.investigation_methodology.toLowerCase().includes(q)
        );
    });

    // Stats
    const totalUses = skills.reduce((acc, s) => acc + s.times_used, 0);
    const uniqueTactics = new Set(skills.flatMap(s => s.mitre_tactics));
    const uniqueTechniques = new Set(skills.flatMap(s => s.mitre_techniques));

    if (loading) {
        return (
            <div className="flex items-center justify-center h-64">
                <div className="flex items-center space-x-3">
                    <div className="w-6 h-6 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin" />
                    <span className="text-slate-400">Loading threat intelligence...</span>
                </div>
            </div>
        );
    }

    if (error) {
        return (
            <div className="bg-rose-500/10 border border-rose-500/30 rounded-lg p-4 text-rose-400">
                Failed to load skills: {error}
            </div>
        );
    }

    return (
        <div className="space-y-6">
            {/* Header */}
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-2xl font-bold text-white flex items-center space-x-3">
                        <Shield className="w-7 h-7 text-cyan-500" />
                        <span>Threat Intelligence</span>
                    </h1>
                    <p className="text-slate-500 mt-1">AI investigation skills powered by RAG — retrieved automatically during investigations</p>
                </div>
            </div>

            {/* Stats Cards */}
            <div className="grid grid-cols-4 gap-4">
                <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-4">
                    <p className="text-slate-500 text-xs uppercase tracking-wider font-medium">Active Skills</p>
                    <p className="text-2xl font-bold text-white mt-1">{skills.length}</p>
                </div>
                <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-4">
                    <p className="text-slate-500 text-xs uppercase tracking-wider font-medium">Total Uses</p>
                    <p className="text-2xl font-bold text-cyan-400 mt-1">{totalUses.toLocaleString()}</p>
                </div>
                <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-4">
                    <p className="text-slate-500 text-xs uppercase tracking-wider font-medium">MITRE Tactics</p>
                    <p className="text-2xl font-bold text-violet-400 mt-1">{uniqueTactics.size}</p>
                </div>
                <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-4">
                    <p className="text-slate-500 text-xs uppercase tracking-wider font-medium">Techniques</p>
                    <p className="text-2xl font-bold text-amber-400 mt-1">{uniqueTechniques.size}</p>
                </div>
            </div>

            {/* Search */}
            <div className="relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
                <input
                    type="text"
                    placeholder="Search skills by name, threat type, MITRE technique..."
                    className="w-full bg-slate-800/50 border border-slate-700/50 rounded-lg pl-10 pr-4 py-2.5 text-sm text-slate-300 placeholder-slate-600 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/20 transition-all"
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                />
            </div>

            {/* Skills Grid */}
            <div className="space-y-3">
                {filtered.length === 0 ? (
                    <div className="text-center py-12 text-slate-500">
                        <Shield className="w-12 h-12 mx-auto mb-3 opacity-30" />
                        <p>No skills match your search</p>
                    </div>
                ) : (
                    filtered.map(skill => <SkillCard key={skill.id} skill={skill} />)
                )}
            </div>
        </div>
    );
};

export default ThreatIntel;
