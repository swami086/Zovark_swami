import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, Plus, Edit3, Users, X, Loader2, Building2, ChevronRight } from 'lucide-react';
import { getUser, fetchTenants, createTenant, updateTenant, fetchTenantUsers, type Tenant, type TenantUser } from '../api/client';
import { Skeleton } from '../components/Skeleton';

const TIER_OPTIONS = ['free', 'starter', 'professional', 'enterprise'];
const STATUS_OPTIONS = ['active', 'suspended', 'trial'];

const TierBadge = ({ tier }: { tier: string }) => {
    const colors: Record<string, string> = {
        free: 'bg-slate-500/10 text-slate-400 border-slate-500/20',
        starter: 'bg-blue-500/10 text-blue-400 border-blue-500/20',
        professional: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/20',
        enterprise: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
    };
    return (
        <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold border uppercase tracking-wider ${colors[tier] || colors.free}`}>
            {tier}
        </span>
    );
};

const StatusDot = ({ status }: { status: string }) => {
    const colors: Record<string, string> = {
        active: 'bg-emerald-400',
        suspended: 'bg-rose-400',
        trial: 'bg-amber-400',
    };
    return (
        <span className="flex items-center space-x-1.5">
            <span className={`w-2 h-2 rounded-full ${colors[status] || colors.active}`} />
            <span className="text-xs text-slate-400 capitalize">{status}</span>
        </span>
    );
};

export default function AdminPanel() {
    const navigate = useNavigate();
    const user = getUser();
    const [tenants, setTenants] = useState<Tenant[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [showCreateModal, setShowCreateModal] = useState(false);
    const [showEditModal, setShowEditModal] = useState(false);
    const [editTenant, setEditTenant] = useState<Tenant | null>(null);
    const [selectedTenantUsers, setSelectedTenantUsers] = useState<TenantUser[]>([]);
    const [selectedTenantId, setSelectedTenantId] = useState<string | null>(null);
    const [usersLoading, setUsersLoading] = useState(false);

    // Form state
    const [formName, setFormName] = useState('');
    const [formSlug, setFormSlug] = useState('');
    const [formTier, setFormTier] = useState('starter');
    const [formStatus, setFormStatus] = useState('active');
    const [submitting, setSubmitting] = useState(false);

    useEffect(() => {
        if (user?.role !== 'admin') {
            navigate('/');
            return;
        }
        loadTenants();
    }, [user, navigate]);

    const loadTenants = async () => {
        try {
            setLoading(true);
            const data = await fetchTenants();
            setTenants(data);
        } catch (err: any) {
            setError(err.message || 'Failed to load tenants');
        } finally {
            setLoading(false);
        }
    };

    const handleCreateTenant = async (e: React.FormEvent) => {
        e.preventDefault();
        setSubmitting(true);
        try {
            await createTenant({ name: formName, slug: formSlug, tier: formTier });
            setShowCreateModal(false);
            setFormName('');
            setFormSlug('');
            setFormTier('starter');
            await loadTenants();
        } catch (err: any) {
            alert(err.message || 'Failed to create tenant');
        } finally {
            setSubmitting(false);
        }
    };

    const handleEditTenant = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!editTenant) return;
        setSubmitting(true);
        try {
            await updateTenant(editTenant.id, { name: formName, tier: formTier, status: formStatus });
            setShowEditModal(false);
            setEditTenant(null);
            await loadTenants();
        } catch (err: any) {
            alert(err.message || 'Failed to update tenant');
        } finally {
            setSubmitting(false);
        }
    };

    const openEditModal = (tenant: Tenant) => {
        setEditTenant(tenant);
        setFormName(tenant.name);
        setFormTier(tenant.tier);
        setFormStatus(tenant.status);
        setShowEditModal(true);
    };

    const loadTenantUsers = async (tenantId: string) => {
        if (selectedTenantId === tenantId) {
            setSelectedTenantId(null);
            setSelectedTenantUsers([]);
            return;
        }
        setSelectedTenantId(tenantId);
        setUsersLoading(true);
        try {
            const users = await fetchTenantUsers(tenantId);
            setSelectedTenantUsers(users);
        } catch {
            setSelectedTenantUsers([]);
        } finally {
            setUsersLoading(false);
        }
    };

    const autoSlug = (name: string) => {
        setFormName(name);
        setFormSlug(name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, ''));
    };

    if (user?.role !== 'admin') return null;

    return (
        <div className="space-y-6">
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-2xl font-bold text-white tracking-tight flex items-center">
                        <Shield className="w-6 h-6 mr-3 text-cyan-500" />
                        Admin Panel
                    </h1>
                    <p className="text-slate-400 mt-1">Manage tenants, users, and platform configuration</p>
                </div>
                <button
                    onClick={() => { setFormName(''); setFormSlug(''); setFormTier('starter'); setShowCreateModal(true); }}
                    className="flex items-center px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg transition-colors font-medium shadow-lg shadow-cyan-900/20"
                >
                    <Plus className="w-4 h-4 mr-2" />
                    Create Tenant
                </button>
            </div>

            {error && (
                <div className="bg-rose-500/10 border border-rose-500/20 text-rose-400 p-4 rounded-xl">
                    {error}
                </div>
            )}

            {/* Tenant Summary */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                {loading ? (
                    Array.from({ length: 4 }).map((_, i) => (
                        <div key={i} className="bg-[#1E293B] border border-slate-700/50 rounded-xl p-5 space-y-3">
                            <Skeleton className="w-24 h-3" />
                            <Skeleton className="h-8 w-16" />
                        </div>
                    ))
                ) : (
                    <>
                        <div className="bg-[#1E293B] border border-slate-700/50 rounded-xl p-5">
                            <div className="flex items-center text-slate-400 mb-2">
                                <Building2 className="w-4 h-4 mr-2 text-cyan-400" />
                                <span className="text-xs font-medium uppercase tracking-wider">Total Tenants</span>
                            </div>
                            <p className="text-2xl font-bold text-white">{tenants.length}</p>
                        </div>
                        <div className="bg-[#1E293B] border border-slate-700/50 rounded-xl p-5">
                            <div className="flex items-center text-slate-400 mb-2">
                                <span className="w-2 h-2 rounded-full bg-emerald-400 mr-2" />
                                <span className="text-xs font-medium uppercase tracking-wider">Active</span>
                            </div>
                            <p className="text-2xl font-bold text-emerald-400">{tenants.filter(t => t.status === 'active').length}</p>
                        </div>
                        <div className="bg-[#1E293B] border border-slate-700/50 rounded-xl p-5">
                            <div className="flex items-center text-slate-400 mb-2">
                                <span className="w-2 h-2 rounded-full bg-amber-400 mr-2" />
                                <span className="text-xs font-medium uppercase tracking-wider">Enterprise</span>
                            </div>
                            <p className="text-2xl font-bold text-amber-400">{tenants.filter(t => t.tier === 'enterprise').length}</p>
                        </div>
                        <div className="bg-[#1E293B] border border-slate-700/50 rounded-xl p-5">
                            <div className="flex items-center text-slate-400 mb-2">
                                <Users className="w-4 h-4 mr-2 text-violet-400" />
                                <span className="text-xs font-medium uppercase tracking-wider">Total Users</span>
                            </div>
                            <p className="text-2xl font-bold text-violet-400">{tenants.reduce((sum, t) => sum + (t.user_count || 0), 0)}</p>
                        </div>
                    </>
                )}
            </div>

            {/* Tenant Table */}
            <div className="bg-[#1E293B] border border-slate-700/50 rounded-xl overflow-hidden shadow-sm">
                <div className="overflow-x-auto">
                    <table className="min-w-full divide-y divide-slate-700/50">
                        <thead className="bg-[#0F172A]/50">
                            <tr>
                                <th className="px-6 py-4 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">Tenant</th>
                                <th className="px-6 py-4 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">Slug</th>
                                <th className="px-6 py-4 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">Tier</th>
                                <th className="px-6 py-4 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">Status</th>
                                <th className="px-6 py-4 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">Created</th>
                                <th className="px-6 py-4 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">Actions</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-700/50 bg-[#1E293B]">
                            {loading ? (
                                Array.from({ length: 3 }).map((_, i) => (
                                    <tr key={i} className="animate-pulse">
                                        <td className="px-6 py-4"><Skeleton className="h-4 w-32" /></td>
                                        <td className="px-6 py-4"><Skeleton className="h-4 w-24" /></td>
                                        <td className="px-6 py-4"><Skeleton className="h-6 w-20 rounded-full" /></td>
                                        <td className="px-6 py-4"><Skeleton className="h-4 w-16" /></td>
                                        <td className="px-6 py-4"><Skeleton className="h-4 w-24" /></td>
                                        <td className="px-6 py-4"><Skeleton className="h-4 w-20" /></td>
                                    </tr>
                                ))
                            ) : tenants.length === 0 ? (
                                <tr>
                                    <td colSpan={6} className="px-6 py-12 text-center text-sm text-slate-400">
                                        No tenants found. Create one to get started.
                                    </td>
                                </tr>
                            ) : (
                                tenants.map((tenant, idx) => (
                                    <>
                                        <tr key={tenant.id} className={`hover:bg-slate-700/30 transition-colors ${idx % 2 === 0 ? 'bg-[#1E293B]' : 'bg-[#0F172A]/30'}`}>
                                            <td className="px-6 py-4">
                                                <button
                                                    onClick={() => loadTenantUsers(tenant.id)}
                                                    className="flex items-center space-x-2 text-sm font-medium text-slate-200 hover:text-cyan-400 transition-colors"
                                                >
                                                    <ChevronRight className={`w-4 h-4 transition-transform ${selectedTenantId === tenant.id ? 'rotate-90' : ''}`} />
                                                    <span>{tenant.name}</span>
                                                </button>
                                            </td>
                                            <td className="px-6 py-4 text-sm font-mono text-slate-400">{tenant.slug}</td>
                                            <td className="px-6 py-4"><TierBadge tier={tenant.tier} /></td>
                                            <td className="px-6 py-4"><StatusDot status={tenant.status} /></td>
                                            <td className="px-6 py-4 text-sm text-slate-400">
                                                {new Date(tenant.created_at).toLocaleDateString()}
                                            </td>
                                            <td className="px-6 py-4">
                                                <button
                                                    onClick={() => openEditModal(tenant)}
                                                    className="flex items-center space-x-1 px-3 py-1.5 text-xs font-medium text-cyan-400 hover:bg-cyan-500/10 rounded-lg transition-colors"
                                                >
                                                    <Edit3 className="w-3.5 h-3.5" />
                                                    <span>Edit</span>
                                                </button>
                                            </td>
                                        </tr>
                                        {selectedTenantId === tenant.id && (
                                            <tr key={`${tenant.id}-users`}>
                                                <td colSpan={6} className="px-6 py-4 bg-[#0F172A]/50">
                                                    <div className="ml-6">
                                                        <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-3 flex items-center">
                                                            <Users className="w-3.5 h-3.5 mr-1.5" /> Users in {tenant.name}
                                                        </h4>
                                                        {usersLoading ? (
                                                            <div className="space-y-2">
                                                                <Skeleton className="h-4 w-48" />
                                                                <Skeleton className="h-4 w-40" />
                                                            </div>
                                                        ) : selectedTenantUsers.length === 0 ? (
                                                            <p className="text-sm text-slate-500">No users in this tenant</p>
                                                        ) : (
                                                            <div className="space-y-2">
                                                                {selectedTenantUsers.map(u => (
                                                                    <div key={u.id} className="flex items-center justify-between bg-[#1E293B] rounded-lg px-4 py-2.5 border border-slate-700/50">
                                                                        <div className="flex items-center space-x-3">
                                                                            <div className="w-8 h-8 rounded-full bg-slate-700 flex items-center justify-center text-xs font-bold text-slate-300">
                                                                                {u.email.charAt(0).toUpperCase()}
                                                                            </div>
                                                                            <div>
                                                                                <p className="text-sm font-medium text-slate-200">{u.display_name || u.email}</p>
                                                                                <p className="text-xs text-slate-500">{u.email}</p>
                                                                            </div>
                                                                        </div>
                                                                        <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full uppercase ${
                                                                            u.role === 'admin' ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30' :
                                                                            u.role === 'analyst' ? 'bg-blue-500/20 text-blue-400 border border-blue-500/30' :
                                                                            'bg-slate-500/20 text-slate-400 border border-slate-500/30'
                                                                        }`}>
                                                                            {u.role}
                                                                        </span>
                                                                    </div>
                                                                ))}
                                                            </div>
                                                        )}
                                                    </div>
                                                </td>
                                            </tr>
                                        )}
                                    </>
                                ))
                            )}
                        </tbody>
                    </table>
                </div>
            </div>

            {/* Create Tenant Modal */}
            {showCreateModal && (
                <div className="fixed inset-0 bg-slate-900/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
                    <div className="bg-[#0F172A] border border-slate-700 rounded-2xl w-full max-w-lg shadow-2xl">
                        <div className="border-b border-slate-700 p-6 flex justify-between items-center">
                            <h2 className="text-xl font-bold text-white">Create Tenant</h2>
                            <button onClick={() => setShowCreateModal(false)} className="text-slate-400 hover:text-white transition-colors">
                                <X className="w-6 h-6" />
                            </button>
                        </div>
                        <form onSubmit={handleCreateTenant} className="p-6 space-y-5">
                            <div>
                                <label className="block text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">Tenant Name</label>
                                <input
                                    type="text" required value={formName}
                                    onChange={e => autoSlug(e.target.value)}
                                    className="w-full bg-[#1E293B] border border-slate-700 rounded-lg px-4 py-3 text-white focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500"
                                    placeholder="Acme Corporation"
                                />
                            </div>
                            <div>
                                <label className="block text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">Slug</label>
                                <input
                                    type="text" required value={formSlug}
                                    onChange={e => setFormSlug(e.target.value)}
                                    className="w-full bg-[#1E293B] border border-slate-700 rounded-lg px-4 py-3 text-white font-mono focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500"
                                    placeholder="acme-corporation"
                                />
                            </div>
                            <div>
                                <label className="block text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">Tier</label>
                                <select
                                    value={formTier} onChange={e => setFormTier(e.target.value)}
                                    className="w-full bg-[#1E293B] border border-slate-700 rounded-lg px-4 py-3 text-white focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500"
                                >
                                    {TIER_OPTIONS.map(t => (
                                        <option key={t} value={t}>{t.charAt(0).toUpperCase() + t.slice(1)}</option>
                                    ))}
                                </select>
                            </div>
                            <div className="flex justify-end space-x-3 pt-4 border-t border-slate-700">
                                <button type="button" onClick={() => setShowCreateModal(false)}
                                    className="px-5 py-2.5 rounded-lg font-medium text-slate-300 hover:text-white hover:bg-slate-800 transition-colors">
                                    Cancel
                                </button>
                                <button type="submit" disabled={submitting}
                                    className="flex items-center px-5 py-2.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg transition-colors font-medium shadow-lg shadow-cyan-900/20 disabled:opacity-50">
                                    {submitting && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
                                    {submitting ? 'Creating...' : 'Create Tenant'}
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            )}

            {/* Edit Tenant Modal */}
            {showEditModal && editTenant && (
                <div className="fixed inset-0 bg-slate-900/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
                    <div className="bg-[#0F172A] border border-slate-700 rounded-2xl w-full max-w-lg shadow-2xl">
                        <div className="border-b border-slate-700 p-6 flex justify-between items-center">
                            <h2 className="text-xl font-bold text-white">Edit Tenant: {editTenant.name}</h2>
                            <button onClick={() => setShowEditModal(false)} className="text-slate-400 hover:text-white transition-colors">
                                <X className="w-6 h-6" />
                            </button>
                        </div>
                        <form onSubmit={handleEditTenant} className="p-6 space-y-5">
                            <div>
                                <label className="block text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">Tenant Name</label>
                                <input
                                    type="text" required value={formName}
                                    onChange={e => setFormName(e.target.value)}
                                    className="w-full bg-[#1E293B] border border-slate-700 rounded-lg px-4 py-3 text-white focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500"
                                />
                            </div>
                            <div>
                                <label className="block text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">Tier</label>
                                <select
                                    value={formTier} onChange={e => setFormTier(e.target.value)}
                                    className="w-full bg-[#1E293B] border border-slate-700 rounded-lg px-4 py-3 text-white focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500"
                                >
                                    {TIER_OPTIONS.map(t => (
                                        <option key={t} value={t}>{t.charAt(0).toUpperCase() + t.slice(1)}</option>
                                    ))}
                                </select>
                            </div>
                            <div>
                                <label className="block text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">Status</label>
                                <select
                                    value={formStatus} onChange={e => setFormStatus(e.target.value)}
                                    className="w-full bg-[#1E293B] border border-slate-700 rounded-lg px-4 py-3 text-white focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500"
                                >
                                    {STATUS_OPTIONS.map(s => (
                                        <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
                                    ))}
                                </select>
                            </div>
                            <div className="flex justify-end space-x-3 pt-4 border-t border-slate-700">
                                <button type="button" onClick={() => setShowEditModal(false)}
                                    className="px-5 py-2.5 rounded-lg font-medium text-slate-300 hover:text-white hover:bg-slate-800 transition-colors">
                                    Cancel
                                </button>
                                <button type="submit" disabled={submitting}
                                    className="flex items-center px-5 py-2.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg transition-colors font-medium shadow-lg shadow-cyan-900/20 disabled:opacity-50">
                                    {submitting && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
                                    {submitting ? 'Saving...' : 'Save Changes'}
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            )}
        </div>
    );
}
