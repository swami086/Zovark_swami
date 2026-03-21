import { useEffect, useState, useRef, useCallback } from 'react';
import { Share2, Filter, Loader2, Info, X } from 'lucide-react';
import { fetchEntities, type Entity, type EntityGraphData } from '../api/client';

const ENTITY_COLORS: Record<string, { fill: string; stroke: string; text: string; bg: string }> = {
    ip: { fill: '#06b6d4', stroke: '#0891b2', text: 'text-cyan-400', bg: 'bg-cyan-500/10 border-cyan-500/20' },
    domain: { fill: '#a78bfa', stroke: '#8b5cf6', text: 'text-violet-400', bg: 'bg-violet-500/10 border-violet-500/20' },
    user: { fill: '#f59e0b', stroke: '#d97706', text: 'text-amber-400', bg: 'bg-amber-500/10 border-amber-500/20' },
    hash: { fill: '#f43f5e', stroke: '#e11d48', text: 'text-rose-400', bg: 'bg-rose-500/10 border-rose-500/20' },
};

const ENTITY_TYPE_OPTIONS = [
    { value: '', label: 'All Types' },
    { value: 'ip', label: 'IP Address' },
    { value: 'domain', label: 'Domain' },
    { value: 'user', label: 'User' },
    { value: 'hash', label: 'Hash' },
];

interface NodePos {
    x: number;
    y: number;
    vx: number;
    vy: number;
    entity: Entity;
}

const RiskBar = ({ score }: { score: number }) => {
    const color = score >= 80 ? 'bg-rose-500' : score >= 50 ? 'bg-amber-500' : 'bg-emerald-500';
    return (
        <div className="flex items-center space-x-2">
            <div className="w-20 h-2 bg-slate-700/50 rounded-full overflow-hidden">
                <div className={`h-full ${color} rounded-full`} style={{ width: `${score}%` }} />
            </div>
            <span className="text-xs font-mono text-slate-400">{score}</span>
        </div>
    );
};

export default function EntityGraph() {
    const [graphData, setGraphData] = useState<EntityGraphData | null>(null);
    const [loading, setLoading] = useState(true);
    const [filter, setFilter] = useState('');
    const [selectedEntity, setSelectedEntity] = useState<Entity | null>(null);
    const [nodes, setNodes] = useState<NodePos[]>([]);
    const svgRef = useRef<SVGSVGElement>(null);
    const animFrameRef = useRef<number>(0);
    const [dimensions, setDimensions] = useState({ width: 800, height: 500 });

    useEffect(() => {
        const load = async () => {
            try {
                setLoading(true);
                const data = await fetchEntities(filter || undefined);
                setGraphData(data);
            } catch {
                setGraphData(null);
            } finally {
                setLoading(false);
            }
        };
        load();
    }, [filter]);

    // Initialize node positions
    useEffect(() => {
        if (!graphData) return;
        const centerX = dimensions.width / 2;
        const centerY = dimensions.height / 2;
        const radius = Math.min(dimensions.width, dimensions.height) * 0.35;

        const initialNodes: NodePos[] = graphData.entities.map((entity, i) => {
            const angle = (2 * Math.PI * i) / graphData.entities.length;
            return {
                x: centerX + radius * Math.cos(angle) + (Math.random() - 0.5) * 40,
                y: centerY + radius * Math.sin(angle) + (Math.random() - 0.5) * 40,
                vx: 0,
                vy: 0,
                entity,
            };
        });
        setNodes(initialNodes);
    }, [graphData, dimensions]);

    // Simple force simulation
    useEffect(() => {
        if (nodes.length === 0 || !graphData) return;

        let iterationsLeft = 120;
        const nodesCopy = nodes.map(n => ({ ...n }));

        const simulate = () => {
            if (iterationsLeft <= 0) return;
            iterationsLeft--;

            const centerX = dimensions.width / 2;
            const centerY = dimensions.height / 2;

            // Repulsion between all nodes
            for (let i = 0; i < nodesCopy.length; i++) {
                for (let j = i + 1; j < nodesCopy.length; j++) {
                    const dx = nodesCopy[j].x - nodesCopy[i].x;
                    const dy = nodesCopy[j].y - nodesCopy[i].y;
                    const dist = Math.max(Math.sqrt(dx * dx + dy * dy), 1);
                    const force = 2000 / (dist * dist);
                    const fx = (dx / dist) * force;
                    const fy = (dy / dist) * force;
                    nodesCopy[i].vx -= fx;
                    nodesCopy[i].vy -= fy;
                    nodesCopy[j].vx += fx;
                    nodesCopy[j].vy += fy;
                }
            }

            // Attraction along edges
            if (graphData.edges) {
                for (const edge of graphData.edges) {
                    const sourceIdx = nodesCopy.findIndex(n => n.entity.id === edge.source_id);
                    const targetIdx = nodesCopy.findIndex(n => n.entity.id === edge.target_id);
                    if (sourceIdx === -1 || targetIdx === -1) continue;
                    const dx = nodesCopy[targetIdx].x - nodesCopy[sourceIdx].x;
                    const dy = nodesCopy[targetIdx].y - nodesCopy[sourceIdx].y;
                    const dist = Math.max(Math.sqrt(dx * dx + dy * dy), 1);
                    const force = (dist - 120) * 0.01;
                    const fx = (dx / dist) * force;
                    const fy = (dy / dist) * force;
                    nodesCopy[sourceIdx].vx += fx;
                    nodesCopy[sourceIdx].vy += fy;
                    nodesCopy[targetIdx].vx -= fx;
                    nodesCopy[targetIdx].vy -= fy;
                }
            }

            // Center gravity
            for (const node of nodesCopy) {
                node.vx += (centerX - node.x) * 0.002;
                node.vy += (centerY - node.y) * 0.002;
                node.vx *= 0.85;
                node.vy *= 0.85;
                node.x += node.vx;
                node.y += node.vy;
                // Clamp to bounds
                node.x = Math.max(40, Math.min(dimensions.width - 40, node.x));
                node.y = Math.max(40, Math.min(dimensions.height - 40, node.y));
            }

            setNodes([...nodesCopy]);
            animFrameRef.current = requestAnimationFrame(simulate);
        };

        animFrameRef.current = requestAnimationFrame(simulate);
        return () => cancelAnimationFrame(animFrameRef.current);
    // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [graphData, dimensions]);

    // Resize observer
    const containerRef = useRef<HTMLDivElement>(null);
    useEffect(() => {
        const el = containerRef.current;
        if (!el) return;
        const obs = new ResizeObserver(entries => {
            for (const entry of entries) {
                setDimensions({
                    width: Math.max(entry.contentRect.width, 400),
                    height: Math.max(entry.contentRect.height, 300),
                });
            }
        });
        obs.observe(el);
        return () => obs.disconnect();
    }, []);

    const getNodeById = useCallback((id: string) => nodes.find(n => n.entity.id === id), [nodes]);

    return (
        <div className="space-y-6">
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-2xl font-bold text-white tracking-tight flex items-center">
                        <Share2 className="w-6 h-6 mr-3 text-violet-400" />
                        Entity Graph
                    </h1>
                    <p className="text-slate-400 mt-1">Visualize relationships between entities across investigations</p>
                </div>
                <div className="flex items-center space-x-3">
                    <Filter className="w-4 h-4 text-slate-500" />
                    <select
                        value={filter}
                        onChange={e => setFilter(e.target.value)}
                        className="bg-slate-800/50 border border-slate-700/50 rounded-lg px-3 py-2 text-xs text-slate-300 focus:outline-none focus:border-cyan-500/50"
                    >
                        {ENTITY_TYPE_OPTIONS.map(o => (
                            <option key={o.value} value={o.value}>{o.label}</option>
                        ))}
                    </select>
                </div>
            </div>

            {/* Legend */}
            <div className="flex items-center space-x-4">
                {Object.entries(ENTITY_COLORS).map(([type, colors]) => (
                    <div key={type} className="flex items-center space-x-1.5">
                        <span className="w-3 h-3 rounded-full" style={{ backgroundColor: colors.fill }} />
                        <span className="text-xs text-slate-400 capitalize">{type}</span>
                    </div>
                ))}
                <span className="text-xs text-slate-600 ml-4">Click a node for details</span>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
                {/* Graph */}
                <div
                    ref={containerRef}
                    className="lg:col-span-3 bg-[#1E293B] border border-slate-700/50 rounded-xl overflow-hidden"
                    style={{ minHeight: '500px' }}
                >
                    {loading ? (
                        <div className="flex items-center justify-center h-[500px]">
                            <Loader2 className="w-8 h-8 text-cyan-500 animate-spin" />
                        </div>
                    ) : (
                        <svg
                            ref={svgRef}
                            width={dimensions.width}
                            height={dimensions.height}
                            className="w-full h-full"
                        >
                            {/* Edges */}
                            {graphData?.edges.map(edge => {
                                const source = getNodeById(edge.source_id);
                                const target = getNodeById(edge.target_id);
                                if (!source || !target) return null;
                                return (
                                    <g key={edge.id}>
                                        <line
                                            x1={source.x}
                                            y1={source.y}
                                            x2={target.x}
                                            y2={target.y}
                                            stroke="#334155"
                                            strokeWidth={1.5}
                                            strokeOpacity={0.6}
                                        />
                                        <text
                                            x={(source.x + target.x) / 2}
                                            y={(source.y + target.y) / 2 - 6}
                                            textAnchor="middle"
                                            fill="#64748b"
                                            fontSize="9"
                                            fontFamily="monospace"
                                        >
                                            {edge.relationship}
                                        </text>
                                    </g>
                                );
                            })}

                            {/* Nodes */}
                            {nodes.map(node => {
                                const colors = ENTITY_COLORS[node.entity.entity_type] || ENTITY_COLORS.ip;
                                const isSelected = selectedEntity?.id === node.entity.id;
                                const radius = isSelected ? 22 : 18;
                                return (
                                    <g
                                        key={node.entity.id}
                                        className="cursor-pointer"
                                        onClick={() => setSelectedEntity(node.entity)}
                                    >
                                        {/* Glow ring for selected */}
                                        {isSelected && (
                                            <circle
                                                cx={node.x}
                                                cy={node.y}
                                                r={radius + 4}
                                                fill="none"
                                                stroke={colors.fill}
                                                strokeWidth={2}
                                                strokeOpacity={0.4}
                                            />
                                        )}
                                        {/* Risk ring */}
                                        {node.entity.risk_score && node.entity.risk_score >= 70 && (
                                            <circle
                                                cx={node.x}
                                                cy={node.y}
                                                r={radius + 6}
                                                fill="none"
                                                stroke="#f43f5e"
                                                strokeWidth={1}
                                                strokeOpacity={0.3}
                                                strokeDasharray="3 3"
                                            />
                                        )}
                                        <circle
                                            cx={node.x}
                                            cy={node.y}
                                            r={radius}
                                            fill={colors.fill}
                                            fillOpacity={0.15}
                                            stroke={colors.stroke}
                                            strokeWidth={2}
                                        />
                                        <text
                                            x={node.x}
                                            y={node.y + 1}
                                            textAnchor="middle"
                                            dominantBaseline="middle"
                                            fill={colors.fill}
                                            fontSize="8"
                                            fontWeight="bold"
                                            fontFamily="monospace"
                                        >
                                            {node.entity.entity_type.toUpperCase().slice(0, 4)}
                                        </text>
                                        <text
                                            x={node.x}
                                            y={node.y + radius + 14}
                                            textAnchor="middle"
                                            fill="#94a3b8"
                                            fontSize="10"
                                            fontFamily="monospace"
                                        >
                                            {node.entity.value.length > 18 ? node.entity.value.slice(0, 16) + '...' : node.entity.value}
                                        </text>
                                    </g>
                                );
                            })}
                        </svg>
                    )}
                </div>

                {/* Detail Panel */}
                <div className="lg:col-span-1 space-y-4">
                    {selectedEntity ? (
                        <div className="bg-[#1E293B] border border-slate-700/50 rounded-xl p-5">
                            <div className="flex items-center justify-between mb-4">
                                <h3 className="text-sm font-bold text-white">Entity Details</h3>
                                <button onClick={() => setSelectedEntity(null)} className="text-slate-500 hover:text-slate-300">
                                    <X className="w-4 h-4" />
                                </button>
                            </div>
                            <div className="space-y-3">
                                <div>
                                    <p className="text-[10px] text-slate-500 uppercase tracking-wider font-bold">Type</p>
                                    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-bold border mt-1 ${ENTITY_COLORS[selectedEntity.entity_type]?.bg || 'bg-slate-500/10 border-slate-500/20'}`}>
                                        {selectedEntity.entity_type}
                                    </span>
                                </div>
                                <div>
                                    <p className="text-[10px] text-slate-500 uppercase tracking-wider font-bold">Value</p>
                                    <p className="text-sm text-white font-mono mt-1 break-all">{selectedEntity.value}</p>
                                </div>
                                <div>
                                    <p className="text-[10px] text-slate-500 uppercase tracking-wider font-bold">Risk Score</p>
                                    <div className="mt-1">
                                        <RiskBar score={selectedEntity.risk_score || 0} />
                                    </div>
                                </div>
                                <div>
                                    <p className="text-[10px] text-slate-500 uppercase tracking-wider font-bold">Investigations</p>
                                    <p className="text-sm text-white font-bold mt-1">{selectedEntity.investigation_count}</p>
                                </div>
                                <div>
                                    <p className="text-[10px] text-slate-500 uppercase tracking-wider font-bold">First Seen</p>
                                    <p className="text-xs text-slate-400 mt-1">{new Date(selectedEntity.first_seen).toLocaleString()}</p>
                                </div>
                                <div>
                                    <p className="text-[10px] text-slate-500 uppercase tracking-wider font-bold">Last Seen</p>
                                    <p className="text-xs text-slate-400 mt-1">{new Date(selectedEntity.last_seen).toLocaleString()}</p>
                                </div>
                                {/* Connections */}
                                <div className="pt-3 border-t border-slate-700/50">
                                    <p className="text-[10px] text-slate-500 uppercase tracking-wider font-bold mb-2">Connections</p>
                                    {graphData?.edges
                                        .filter(e => e.source_id === selectedEntity.id || e.target_id === selectedEntity.id)
                                        .map(edge => {
                                            const otherId = edge.source_id === selectedEntity.id ? edge.target_id : edge.source_id;
                                            const other = graphData.entities.find(e => e.id === otherId);
                                            return (
                                                <div
                                                    key={edge.id}
                                                    className="flex items-center justify-between py-1.5 text-xs cursor-pointer hover:bg-slate-800/50 rounded px-2 -mx-2"
                                                    onClick={() => other && setSelectedEntity(other)}
                                                >
                                                    <span className="text-slate-300 font-mono truncate">{other?.value || otherId}</span>
                                                    <span className="text-slate-500 ml-2 whitespace-nowrap">{edge.relationship}</span>
                                                </div>
                                            );
                                        })}
                                </div>
                            </div>
                        </div>
                    ) : (
                        <div className="bg-[#1E293B] border border-slate-700/50 rounded-xl p-5 text-center">
                            <Info className="w-8 h-8 text-slate-600 mx-auto mb-3" />
                            <p className="text-sm text-slate-400">Click a node on the graph to view entity details</p>
                        </div>
                    )}

                    {/* Entity Stats */}
                    {graphData && (
                        <div className="bg-[#1E293B] border border-slate-700/50 rounded-xl p-5">
                            <h3 className="text-sm font-bold text-white mb-3">Statistics</h3>
                            <div className="space-y-2">
                                <div className="flex justify-between">
                                    <span className="text-xs text-slate-400">Total Entities</span>
                                    <span className="text-xs font-bold text-white">{graphData.entities.length}</span>
                                </div>
                                <div className="flex justify-between">
                                    <span className="text-xs text-slate-400">Total Edges</span>
                                    <span className="text-xs font-bold text-white">{graphData.edges.length}</span>
                                </div>
                                {Object.entries(ENTITY_COLORS).map(([type, colors]) => {
                                    const count = graphData.entities.filter(e => e.entity_type === type).length;
                                    if (count === 0) return null;
                                    return (
                                        <div key={type} className="flex justify-between">
                                            <span className={`text-xs ${colors.text} capitalize`}>{type}s</span>
                                            <span className="text-xs font-bold text-white">{count}</span>
                                        </div>
                                    );
                                })}
                                <div className="flex justify-between pt-2 border-t border-slate-700/50">
                                    <span className="text-xs text-slate-400">High Risk</span>
                                    <span className="text-xs font-bold text-rose-400">
                                        {graphData.entities.filter(e => (e.risk_score || 0) >= 70).length}
                                    </span>
                                </div>
                            </div>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}
