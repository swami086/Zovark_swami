import { BrowserRouter as Router, Routes, Route, Link, useLocation, Navigate } from 'react-router-dom';
import React, { useEffect, useState } from 'react';
import { Hexagon, LayoutDashboard, Search, PlusCircle, Settings, LogOut, Shield, BookOpen, Database, Play, ShieldAlert, DollarSign, Share2, AlertTriangle, Sun, Moon, Users } from 'lucide-react';
import { getUser, clearToken, fetchPendingApprovals } from './api/client';
import { ThemeContext, useThemeProvider, useTheme } from './hooks/useTheme';

import TaskList from './pages/TaskList';
import TaskDetail from './pages/TaskDetail';
import NewTask from './pages/NewTask';
import Playbooks from './pages/Playbooks';
import ThreatIntel from './pages/ThreatIntel';
import LogSources from './pages/LogSources';
import SettingsPage from './pages/Settings';
import Login from './pages/Login';
import DemoPage from './pages/DemoPage';
import AdminPanel from './pages/AdminPanel';
import ApprovalQueue from './pages/ApprovalQueue';
import CostDashboard from './pages/CostDashboard';
import EntityGraph from './pages/EntityGraph';
import PlaybookBuilder from './pages/PlaybookBuilder';
import SIEMAlerts from './pages/SIEMAlerts';
import Notifications from './components/Notifications';

const Sidebar = () => {
  const location = useLocation();
  const user = getUser();
  const { theme, toggleTheme } = useTheme();
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
    { name: 'Approvals', icon: ShieldAlert, path: '/approvals' },
    { name: 'SIEM Alerts', icon: AlertTriangle, path: '/siem-alerts' },
    { name: 'Demo', icon: Play, path: '/demo' },
    { name: 'Threat Intel', icon: Shield, path: '/threat-intel' },
    { name: 'Playbooks', icon: BookOpen, path: '/playbooks' },
    { name: 'Entity Graph', icon: Share2, path: '/entity-graph' },
    { name: 'Cost Tracking', icon: DollarSign, path: '/costs' },
    { name: 'Log Sources', icon: Database, path: '/log-sources' },
    ...(user?.role === 'admin' ? [
      { name: 'Admin Panel', icon: Users, path: '/admin' },
      { name: 'Settings', icon: Settings, path: '/settings' },
    ] : [])
  ];

  const roleColors: Record<string, string> = {
    admin: "bg-cyan-500/20 text-cyan-400 border border-cyan-500/30",
    analyst: "bg-blue-500/20 text-blue-400 border border-blue-500/30",
    viewer: "bg-slate-500/20 text-slate-400 border border-slate-500/30",
  };

  return (
    <div className="w-[240px] sidebar-bg border-r sidebar-border flex flex-col h-screen fixed top-0 left-0">
      <div className="p-6 flex items-center space-x-3">
        <Hexagon className="w-6 h-6 text-cyan-500 fill-cyan-500/20" />
        <div className="flex flex-col">
          <span className="font-bold text-lg tracking-wider sidebar-title leading-none">ZOVARC</span>
          <span className="text-[10px] uppercase tracking-[0.2em] text-cyan-400/70 font-semibold mt-0.5">Security Operations</span>
        </div>
      </div>

      <nav className="flex-1 px-4 space-y-1 mt-4 overflow-y-auto">
        {navItems.map((item) => {
          const isActive = location.pathname === item.path || (item.path === '/' && location.pathname === '/tasks');
          const showBadge = item.name === 'Approvals' && pendingCount > 0;
          return (
            <Link
              key={item.name}
              to={item.path}
              className={`flex items-center space-x-3 px-3 py-2 rounded-lg transition-all duration-200 ${isActive
                ? 'nav-active'
                : 'nav-inactive'
                }`}
            >
              <item.icon className={`w-4 h-4 ${isActive ? 'text-cyan-500' : 'nav-icon'}`} />
              <span className="font-medium text-[13px] flex-1">{item.name}</span>
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
        <div className="p-4 border-t sidebar-border">
          <div className="flex flex-col space-y-3">
            <div className="flex items-center justify-between mb-2 px-2">
              <span className="text-slate-400 text-sm truncate font-medium">{user.email}</span>
              <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full uppercase ${roleColors[user.role] || roleColors.viewer}`}>
                {user.role}
              </span>
            </div>
            {/* Theme toggle */}
            <button
              onClick={toggleTheme}
              className="flex items-center space-x-3 px-3 py-2 rounded-lg text-slate-400 hover:text-cyan-400 hover:bg-slate-800/50 transition-all duration-200 w-full"
            >
              {theme === 'dark' ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
              <span className="font-medium text-sm">{theme === 'dark' ? 'Light Mode' : 'Dark Mode'}</span>
            </button>
            <button
              onClick={() => { clearToken(); window.location.href = '/login'; }}
              className="flex items-center space-x-3 px-3 py-2 rounded-lg text-slate-400 hover:text-rose-400 hover:bg-slate-800/50 transition-all duration-200 w-full"
            >
              <LogOut className="w-4 h-4" />
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

function AppContent() {
  const user = getUser();
  return (
    <Router>
      <div className="min-h-screen app-bg app-text font-sans flex text-sm">
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
              <Route path="/playbooks/builder" element={<ProtectedRoute><PlaybookBuilder /></ProtectedRoute>} />
              <Route path="/threat-intel" element={<ProtectedRoute><ThreatIntel /></ProtectedRoute>} />
              <Route path="/log-sources" element={<ProtectedRoute><LogSources /></ProtectedRoute>} />
              <Route path="/approvals" element={<ProtectedRoute><ApprovalQueue /></ProtectedRoute>} />
              <Route path="/siem-alerts" element={<ProtectedRoute><SIEMAlerts /></ProtectedRoute>} />
              <Route path="/entity-graph" element={<ProtectedRoute><EntityGraph /></ProtectedRoute>} />
              <Route path="/costs" element={<ProtectedRoute><CostDashboard /></ProtectedRoute>} />
              <Route path="/admin" element={<ProtectedRoute><AdminPanel /></ProtectedRoute>} />
              <Route path="/settings" element={<ProtectedRoute><SettingsPage /></ProtectedRoute>} />
            </Routes>
            {user && <Notifications />}
          </div>
        </main>
      </div>
    </Router>
  );
}

function App() {
  const themeCtx = useThemeProvider();
  return (
    <ThemeContext.Provider value={themeCtx}>
      <AppContent />
    </ThemeContext.Provider>
  );
}

export default App;
