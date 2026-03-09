import { BrowserRouter as Router, Routes, Route, Link, useLocation, Navigate } from 'react-router-dom';
import React, { useEffect, useState } from 'react';
import { Hexagon, LayoutDashboard, Search, PlusCircle, Settings, LogOut, Shield, BookOpen, Database, Play } from 'lucide-react';
import { getUser, clearToken, fetchPendingApprovals } from './api/client';

import TaskList from './pages/TaskList';
import TaskDetail from './pages/TaskDetail';
import NewTask from './pages/NewTask';
import Playbooks from './pages/Playbooks';
import ThreatIntel from './pages/ThreatIntel';
import LogSources from './pages/LogSources';
import SettingsPage from './pages/Settings';
import Login from './pages/Login';
import DemoPage from './pages/DemoPage';
import Notifications from './components/Notifications';

const Sidebar = () => {
  const location = useLocation();
  const user = getUser();
  const [pendingCount, setPendingCount] = useState(0);

  useEffect(() => {
    if (!user) return;
    const loadCount = async () => {
      try {
        const data = await fetchPendingApprovals();
        setPendingCount(data.count || 0);
      } catch { /* ignore */ }
    };
    loadCount();
    const interval = setInterval(loadCount, 30000);
    return () => clearInterval(interval);
  }, [user]);

  if (!user && location.pathname === '/login') return null;

  const navItems = [
    { name: 'Dashboard', icon: LayoutDashboard, path: '/' },
    { name: 'Investigations', icon: Search, path: '/tasks' },
    ...(user?.role !== 'viewer' ? [{ name: 'New Investigation', icon: PlusCircle, path: '/tasks/new' }] : []),
    { name: 'Demo', icon: Play, path: '/demo' },
    { name: 'Threat Intel', icon: Shield, path: '/threat-intel', placeholder: true },
    { name: 'Playbooks', icon: BookOpen, path: '/playbooks' },
    { name: 'Log Sources', icon: Database, path: '/log-sources', placeholder: true },
    ...(user?.role === 'admin' ? [{ name: 'Settings', icon: Settings, path: '/settings' }] : [])
  ];

  const roleColors: Record<string, string> = {
    admin: "bg-cyan-500/20 text-cyan-400 border border-cyan-500/30",
    analyst: "bg-blue-500/20 text-blue-400 border border-blue-500/30",
    viewer: "bg-slate-500/20 text-slate-400 border border-slate-500/30",
  };

  return (
    <div className="w-[240px] bg-[#0F172A] border-r border-slate-700/50 flex flex-col h-screen fixed top-0 left-0">
      <div className="p-6 flex items-center space-x-3">
        <Hexagon className="w-6 h-6 text-cyan-500 fill-cyan-500/20" />
        <div className="flex flex-col">
          <span className="font-bold text-lg tracking-wider text-white leading-none">HYDRA</span>
          <span className="text-[10px] uppercase tracking-[0.2em] text-cyan-400/70 font-semibold mt-0.5">Security Operations</span>
        </div>
      </div>

      <nav className="flex-1 px-4 space-y-1 mt-4">
        {navItems.map((item) => {
          const isActive = location.pathname === item.path || (item.path === '/' && location.pathname === '/tasks');
          const showBadge = item.name === 'Investigations' && pendingCount > 0;
          return (
            <Link
              key={item.name}
              to={item.path}
              className={`flex items-center space-x-3 px-3 py-2.5 rounded-lg transition-all duration-200 ${isActive
                ? 'bg-slate-800 text-white'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                }`}
            >
              <item.icon className={`w-5 h-5 ${isActive ? 'text-cyan-500' : 'text-slate-500'}`} />
              <span className="font-medium flex-1">{item.name}</span>
              {showBadge && (
                <span className="bg-amber-500 text-[10px] font-bold text-black w-5 h-5 rounded-full flex items-center justify-center animate-pulse">
                  {pendingCount}
                </span>
              )}
            </Link>
          );
        })}
      </nav>

      {user && (
        <div className="p-4 border-t border-slate-700/50">
          <div className="flex flex-col space-y-3">
            <div className="flex items-center justify-between mb-2 px-2">
              <span className="text-slate-400 text-sm truncate font-medium">{user.email}</span>
              <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full uppercase ${roleColors[user.role] || roleColors.viewer}`}>
                {user.role}
              </span>
            </div>
            <button
              onClick={() => { clearToken(); window.location.href = '/login'; }}
              className="flex items-center space-x-3 px-3 py-2.5 rounded-lg text-slate-400 hover:text-rose-400 hover:bg-slate-800/50 transition-all duration-200 w-full"
            >
              <LogOut className="w-5 h-5" />
              <span className="font-medium text-sm">Logout</span>
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

const ProtectedRoute = ({ children }: { children: React.ReactNode }) => {
  const user = getUser();
  if (!user) {
    return <Navigate to="/login" replace />;
  }
  return children;
};

function App() {
  const user = getUser();
  return (
    <Router>
      <div className="min-h-screen bg-[#0B1120] text-slate-400 font-sans flex text-sm">
        <Sidebar />
        <main className="flex-1 ml-[240px] min-h-screen">
          {/* Main content area with padding and max width */}
          <div className="max-w-[1200px] mx-auto px-8 py-6">
            <Routes>
              <Route path="/login" element={<Login />} />
              <Route path="/" element={<ProtectedRoute><TaskList /></ProtectedRoute>} />
              <Route path="/tasks" element={<ProtectedRoute><TaskList /></ProtectedRoute>} />
              <Route path="/tasks/new" element={<ProtectedRoute><NewTask /></ProtectedRoute>} />
              <Route path="/tasks/:id" element={<ProtectedRoute><TaskDetail /></ProtectedRoute>} />
              <Route path="/demo" element={<ProtectedRoute><DemoPage /></ProtectedRoute>} />
              <Route path="/demo/:scenario" element={<ProtectedRoute><DemoPage /></ProtectedRoute>} />
              <Route path="/playbooks" element={<ProtectedRoute><Playbooks /></ProtectedRoute>} />
              <Route path="/threat-intel" element={<ProtectedRoute><ThreatIntel /></ProtectedRoute>} />
              <Route path="/log-sources" element={<ProtectedRoute><LogSources /></ProtectedRoute>} />
              <Route path="/settings" element={<ProtectedRoute><SettingsPage /></ProtectedRoute>} />
            </Routes>
            {user && <Notifications />}
          </div>
        </main>
      </div>
    </Router>
  );
}

export default App;
