import { useEffect, useState, useRef } from 'react';
import { fetchNotifications, type Notification } from '../api/client';
import { Bell, CheckCircle, AlertTriangle, ShieldAlert, X } from 'lucide-react';
import { useNavigate } from 'react-router-dom';

export default function Notifications() {
    const [notifications, setNotifications] = useState<(Notification & { visible: boolean })[]>([]);
    const lastFetchRef = useRef<string>(new Date().toISOString());
    const navigate = useNavigate();

    useEffect(() => {
        const poll = async () => {
            try {
                const now = new Date().toISOString();
                const newNotifs = await fetchNotifications(lastFetchRef.current);
                lastFetchRef.current = now;

                if (newNotifs.length > 0) {
                    setNotifications(prev => {
                        const added = newNotifs.map(n => ({ ...n, visible: true }));
                        return [...prev, ...added];
                    });
                }
            } catch (error) {
                console.error("Failed to fetch notifications", error);
            }
        };

        const interval = setInterval(poll, 10000);
        poll(); // Initial poll
        return () => clearInterval(interval);
    }, []);

    // Auto-dismiss logic
    useEffect(() => {
        const activeNotifs = notifications.filter(n => n.visible);
        if (activeNotifs.length === 0) return;

        const timer = setTimeout(() => {
            setNotifications(prev => prev.map(n => ({ ...n, visible: false })));
        }, 5000);

        return () => clearTimeout(timer);
    }, [notifications]);

    const handleDismiss = (id: string, e: React.MouseEvent) => {
        e.stopPropagation();
        setNotifications(prev => prev.map(n => n.id === id ? { ...n, visible: false } : n));
    };

    const handleClick = (n: Notification) => {
        handleDismiss(n.id, { stopPropagation: () => { } } as any);
        if (n.task_id) {
            navigate(`/tasks/${n.task_id}`);
        } else if (n.type === 'siem_alert') {
            navigate('/');
        }
    };

    const visibleNotifs = notifications.filter(n => n.visible);

    if (visibleNotifs.length === 0) return null;

    return (
        <div className="fixed bottom-4 right-4 z-50 flex flex-col gap-2">
            {visibleNotifs.map(n => {
                let Icon = Bell;
                let bgClass = "bg-slate-800 border-slate-700 text-white";

                if (n.type === 'task_completed') {
                    Icon = CheckCircle;
                    bgClass = "bg-emerald-900/90 border-emerald-700/50 text-emerald-50";
                } else if (n.type === 'approval_requested') {
                    Icon = AlertTriangle;
                    bgClass = "bg-amber-900/90 border-amber-700/50 text-amber-50";
                } else if (n.type === 'siem_alert') {
                    Icon = ShieldAlert;
                    bgClass = "bg-red-900/90 border-red-700/50 text-red-50";
                }

                return (
                    <div
                        key={n.id}
                        onClick={() => handleClick(n)}
                        className={`flex items-center p-4 rounded-lg shadow-lg border backdrop-blur-md cursor-pointer hover:opacity-90 transition-all min-w-[300px] max-w-sm ${bgClass}`}
                    >
                        <Icon className="w-5 h-5 mr-3 flex-shrink-0" />
                        <span className="text-sm font-medium flex-grow truncate">{n.message}</span>
                        <button
                            onClick={(e) => handleDismiss(n.id, e)}
                            className="ml-4 text-white/70 hover:text-white transition-colors"
                        >
                            <X className="w-4 h-4" />
                        </button>
                    </div>
                );
            })}
        </div>
    );
}
