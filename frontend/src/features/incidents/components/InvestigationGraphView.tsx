import React, { useState, useEffect } from 'react';
import {
  Network,
  ShieldAlert,
  AlertTriangle,
  GitFork,
  Repeat,
  Server,
  User,
  Globe,
  FileText,
  Info,
  ArrowRight,
  RefreshCw,
} from 'lucide-react';
import {
  InvestigationGraphData,
  BlastRadiusAnalysis,
  CycleDetectionResult,
  DfsPathResult,
  GraphNode,
} from '../../../types';
import {
  getIncidentGraphApi,
  getIncidentBlastRadiusApi,
  getIncidentCyclesApi,
  getIncidentPathsApi,
} from '../../../services/api';

interface InvestigationGraphViewProps {
  incidentId: string;
}

export const InvestigationGraphView: React.FC<InvestigationGraphViewProps> = ({
  incidentId,
}) => {
  const [activeTab, setActiveTab] = useState<'blast-radius' | 'paths' | 'cycles' | 'topology'>(
    'blast-radius',
  );

  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const [graphData, setGraphData] = useState<InvestigationGraphData | null>(null);
  const [blastRadius, setBlastRadius] = useState<BlastRadiusAnalysis | null>(null);
  const [cycleResult, setCycleResult] = useState<CycleDetectionResult | null>(null);
  const [pathResult, setPathResult] = useState<DfsPathResult | null>(null);

  const [maxHops, setMaxHops] = useState<number>(2);

  const loadInvestigationData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [graphRes, blastRes, cycleRes] = await Promise.all([
        getIncidentGraphApi(incidentId, { maxHops, timeWindowHours: 24, includeEvents: true }),
        getIncidentBlastRadiusApi(incidentId, { maxHops, timeWindowHours: 24 }),
        getIncidentCyclesApi(incidentId),
      ]);

      setGraphData(graphRes);
      setBlastRadius(blastRes);
      setCycleResult(cycleRes);

      // Attempt to find attack paths if source IP and target asset exist
      if (graphRes.nodes && graphRes.nodes.length > 0) {
        const ipNode = graphRes.nodes.find((n: GraphNode) => n.nodeType === 'IP_ADDRESS');
        const assetNode = graphRes.nodes.find((n: GraphNode) => n.nodeType === 'ASSET');

        if (ipNode && assetNode) {
          try {
            const paths = await getIncidentPathsApi(incidentId, {
              sourceId: ipNode.id,
              targetId: assetNode.id,
              maxDepth: 4,
            });
            setPathResult(paths);
          } catch {
            setPathResult(null);
          }
        }
      }
    } catch (err: any) {
      setError(err?.response?.data?.message || 'Failed to load investigation graph telemetry.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadInvestigationData();
  }, [incidentId, maxHops]);

  const getNodeIcon = (type: string) => {
    switch (type) {
      case 'USER':
        return <User className="w-3.5 h-3.5 text-blue-500" />;
      case 'ASSET':
        return <Server className="w-3.5 h-3.5 text-purple-500" />;
      case 'IP_ADDRESS':
        return <Globe className="w-3.5 h-3.5 text-amber-500" />;
      case 'SECURITY_EVENT':
        return <FileText className="w-3.5 h-3.5 text-slate-500" />;
      case 'INCIDENT':
        return <ShieldAlert className="w-3.5 h-3.5 text-red-500" />;
      default:
        return <Network className="w-3.5 h-3.5 text-slate-400" />;
    }
  };

  if (loading) {
    return (
      <div className="p-8 text-center space-y-3 bg-slate-50 rounded-xl border border-slate-100">
        <RefreshCw className="w-6 h-6 animate-spin text-slate-400 mx-auto" />
        <p className="text-xs text-slate-500 font-medium">
          Traversing entity graph and calculating blast radius...
        </p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-6 bg-red-50/70 border border-red-200 rounded-xl space-y-3">
        <div className="flex items-center space-x-2 text-red-700 font-semibold text-xs">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          <span>Investigation Graph Error</span>
        </div>
        <p className="text-xs text-red-600">{error}</p>
        <button
          onClick={loadInvestigationData}
          className="text-xs px-3 py-1 bg-white border border-red-200 text-red-700 rounded-md font-semibold hover:bg-red-50 transition-colors"
        >
          Retry Investigation Query
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-4 pt-2">
      {/* Top Metrics Banner */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
        <div className="bg-slate-50 border border-slate-200/70 rounded-xl p-3">
          <span className="text-[11px] font-medium text-slate-400 block">Graph Topology</span>
          <div className="flex items-baseline space-x-1.5 mt-0.5">
            <span className="text-base font-bold text-slate-900 font-mono">
              {graphData?.metadata.nodeCount || 0}
            </span>
            <span className="text-[11px] text-slate-500">nodes</span>
            <span className="text-slate-300">/</span>
            <span className="text-base font-bold text-slate-900 font-mono">
              {graphData?.metadata.edgeCount || 0}
            </span>
            <span className="text-[11px] text-slate-500">edges</span>
          </div>
        </div>

        <div className="bg-red-50/60 border border-red-200/70 rounded-xl p-3">
          <span className="text-[11px] font-medium text-red-600 block">Directly Implicated</span>
          <div className="flex items-baseline space-x-1.5 mt-0.5">
            <span className="text-base font-bold text-red-700 font-mono">
              {blastRadius?.directlyAffectedCount || 0}
            </span>
            <span className="text-[11px] text-red-600">Tier 1 entities</span>
          </div>
        </div>

        <div className="bg-amber-50/60 border border-amber-200/70 rounded-xl p-3">
          <span className="text-[11px] font-medium text-amber-600 block">Potentially Exposed</span>
          <div className="flex items-baseline space-x-1.5 mt-0.5">
            <span className="text-base font-bold text-amber-700 font-mono">
              {blastRadius?.potentiallyExposedCount || 0}
            </span>
            <span className="text-[11px] text-amber-600">Tier 2 entities</span>
          </div>
        </div>

        <div className="bg-slate-50 border border-slate-200/70 rounded-xl p-3">
          <span className="text-[11px] font-medium text-slate-400 block">Lateral Movement Loops</span>
          <div className="flex items-baseline space-x-1.5 mt-0.5">
            <span
              className={`text-base font-bold font-mono ${
                cycleResult?.hasCycles ? 'text-orange-600' : 'text-emerald-600'
              }`}
            >
              {cycleResult?.cycleCount || 0}
            </span>
            <span className="text-[11px] text-slate-500">
              {cycleResult?.hasCycles ? 'detected' : 'acyclic'}
            </span>
          </div>
        </div>
      </div>

      {/* Tab Controls & Depth Selector */}
      <div className="flex items-center justify-between border-b border-slate-200 pb-2">
        <div className="flex space-x-2">
          <button
            onClick={() => setActiveTab('blast-radius')}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center space-x-1.5 transition-colors ${
              activeTab === 'blast-radius'
                ? 'bg-slate-900 text-white'
                : 'text-slate-600 hover:bg-slate-100'
            }`}
          >
            <ShieldAlert className="w-3.5 h-3.5" />
            <span>Blast Radius</span>
          </button>

          <button
            onClick={() => setActiveTab('paths')}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center space-x-1.5 transition-colors ${
              activeTab === 'paths'
                ? 'bg-slate-900 text-white'
                : 'text-slate-600 hover:bg-slate-100'
            }`}
          >
            <GitFork className="w-3.5 h-3.5" />
            <span>Attack Paths ({pathResult?.paths.length || 0})</span>
          </button>

          <button
            onClick={() => setActiveTab('cycles')}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center space-x-1.5 transition-colors ${
              activeTab === 'cycles'
                ? 'bg-slate-900 text-white'
                : 'text-slate-600 hover:bg-slate-100'
            }`}
          >
            <Repeat className="w-3.5 h-3.5" />
            <span>Cycle Detection</span>
          </button>

          <button
            onClick={() => setActiveTab('topology')}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center space-x-1.5 transition-colors ${
              activeTab === 'topology'
                ? 'bg-slate-900 text-white'
                : 'text-slate-600 hover:bg-slate-100'
            }`}
          >
            <Network className="w-3.5 h-3.5" />
            <span>Entity Table</span>
          </button>
        </div>

        <div className="flex items-center space-x-2 text-xs text-slate-500">
          <span>Hops:</span>
          <select
            value={maxHops}
            onChange={(e) => setMaxHops(parseInt(e.target.value, 10))}
            className="border border-slate-200 rounded-md bg-white px-2 py-1 text-xs font-mono font-bold text-slate-700"
          >
            <option value={1}>1 Hop</option>
            <option value={2}>2 Hops</option>
            <option value={3}>3 Hops</option>
            <option value={4}>4 Hops</option>
          </select>
        </div>
      </div>

      {/* TAB 1: BLAST RADIUS */}
      {activeTab === 'blast-radius' && (
        <div className="space-y-3">
          {/* Critical Assets Alert */}
          {blastRadius && blastRadius.criticalAssetsAtRisk.length > 0 && (
            <div className="bg-red-50 border border-red-200 rounded-xl p-3.5 flex items-start space-x-3">
              <AlertTriangle className="w-4 h-4 text-red-600 shrink-0 mt-0.5" />
              <div className="space-y-1">
                <span className="text-xs font-bold text-red-900 block">
                  Critical Infrastructure Assets in Exposure Path
                </span>
                <div className="flex flex-wrap gap-2">
                  {blastRadius.criticalAssetsAtRisk.map((item, idx) => (
                    <span
                      key={idx}
                      className="px-2 py-0.5 bg-red-100 text-red-800 text-[11px] font-mono rounded-md font-semibold"
                    >
                      {item.assetNode.label} (Distance: {item.hopDistance} hops)
                    </span>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* Tiered Entity Breakdown */}
          <div className="border border-slate-200 rounded-xl overflow-hidden divide-y divide-slate-100 bg-white">
            <div className="bg-slate-50 px-4 py-2 text-[11px] font-bold uppercase text-slate-500 tracking-wider">
              Reachable Entities & Exposure Classification
            </div>

            {blastRadius?.entities.length === 0 ? (
              <div className="p-4 text-xs text-slate-400 text-center">
                No reachable entities found within {maxHops} hops.
              </div>
            ) : (
              blastRadius?.entities.map((entity, idx) => (
                <div
                  key={idx}
                  className="px-4 py-2.5 flex items-center justify-between text-xs hover:bg-slate-50/50"
                >
                  <div className="flex items-center space-x-3">
                    <span className="p-1.5 bg-slate-100 rounded-md">
                      {getNodeIcon(entity.node.nodeType)}
                    </span>
                    <div>
                      <span className="font-semibold text-slate-900 block">
                        {entity.node.label}
                      </span>
                      <span className="text-[11px] text-slate-500">{entity.reason}</span>
                    </div>
                  </div>

                  <div className="flex items-center space-x-2">
                    <span
                      className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded-full ${
                        entity.tier === 'CONFIRMED_OBSERVED'
                          ? 'bg-red-100 text-red-700'
                          : entity.tier === 'POTENTIALLY_EXPOSED'
                          ? 'bg-amber-100 text-amber-700'
                          : 'bg-slate-100 text-slate-600'
                      }`}
                    >
                      {entity.tier === 'CONFIRMED_OBSERVED'
                        ? 'Tier 1 Observed'
                        : entity.tier === 'POTENTIALLY_EXPOSED'
                        ? 'Tier 2 Exposed'
                        : 'Tier 3 Perimeter'}
                    </span>
                    <span className="text-[11px] font-mono text-slate-400">
                      {entity.hopDistance}h
                    </span>
                  </div>
                </div>
              ))
            )}
          </div>

          {/* Explicit Disclaimer Notice */}
          <div className="bg-slate-50 rounded-xl p-3 border border-slate-100 flex items-start space-x-2.5 text-[11px] text-slate-500">
            <Info className="w-4 h-4 text-slate-400 shrink-0 mt-0.5" />
            <span className="leading-relaxed">{blastRadius?.disclaimer}</span>
          </div>
        </div>
      )}

      {/* TAB 2: ATTACK PATHS */}
      {activeTab === 'paths' && (
        <div className="space-y-3">
          <div className="border border-slate-200 rounded-xl overflow-hidden divide-y divide-slate-100 bg-white">
            <div className="bg-slate-50 px-4 py-2 text-[11px] font-bold uppercase text-slate-500 tracking-wider">
              Iterative DFS Attack Propagation Corridors
            </div>

            {!pathResult || pathResult.paths.length === 0 ? (
              <div className="p-6 text-xs text-slate-400 text-center">
                No continuous directed path discovered between external ingress IP and internal target asset.
              </div>
            ) : (
              pathResult.paths.map((path, idx) => (
                <div key={idx} className="p-4 space-y-2.5 hover:bg-slate-50/50">
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-bold text-slate-800">
                      Attack Path #{idx + 1} ({path.hopCount} Hops)
                    </span>
                    <span className="font-mono text-emerald-600 font-bold text-[11px]">
                      Confidence: {(path.totalConfidence * 100).toFixed(0)}%
                    </span>
                  </div>

                  {/* Path Steps */}
                  <div className="flex flex-wrap items-center gap-2 pt-1">
                    {path.nodes.map((node, nodeIdx) => (
                      <React.Fragment key={nodeIdx}>
                        <div className="flex items-center space-x-1.5 px-2.5 py-1 bg-slate-100 border border-slate-200 rounded-md text-xs font-mono">
                          {getNodeIcon(node.nodeType)}
                          <span className="font-semibold text-slate-900">{node.label}</span>
                        </div>
                        {nodeIdx < path.nodes.length - 1 && (
                          <ArrowRight className="w-3.5 h-3.5 text-slate-400" />
                        )}
                      </React.Fragment>
                    ))}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {/* TAB 3: CYCLES */}
      {activeTab === 'cycles' && (
        <div className="space-y-3">
          <div
            className={`border rounded-xl p-4 space-y-2 ${
              cycleResult?.hasCycles
                ? 'bg-orange-50/60 border-orange-200'
                : 'bg-emerald-50/60 border-emerald-200'
            }`}
          >
            <div className="flex items-center space-x-2 text-xs font-bold uppercase tracking-wider">
              <Repeat
                className={`w-4 h-4 ${
                  cycleResult?.hasCycles ? 'text-orange-600' : 'text-emerald-600'
                }`}
              />
              <span
                className={cycleResult?.hasCycles ? 'text-orange-900' : 'text-emerald-900'}
              >
                Directed Cycle Analysis Status
              </span>
            </div>
            <p
              className={`text-xs leading-relaxed ${
                cycleResult?.hasCycles ? 'text-orange-800' : 'text-emerald-800'
              }`}
            >
              {cycleResult?.analysisSummary}
            </p>
          </div>

          {cycleResult?.cycles && cycleResult.cycles.length > 0 && (
            <div className="border border-slate-200 rounded-xl overflow-hidden divide-y divide-slate-100 bg-white">
              <div className="bg-slate-50 px-4 py-2 text-[11px] font-bold uppercase text-slate-500 tracking-wider">
                Detected Cyclic Paths
              </div>
              {cycleResult.cycles.map((cycle, idx) => (
                <div key={idx} className="p-4 space-y-2 text-xs">
                  <span className="font-bold text-slate-900">Cycle #{idx + 1}</span>
                  <p className="font-mono text-slate-600 text-[11px] bg-slate-50 p-2 rounded-lg border border-slate-200">
                    {cycle.explanation}
                  </p>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* TAB 4: ENTITY & RELATIONSHIP TABLE */}
      {activeTab === 'topology' && (
        <div className="space-y-3">
          <div className="border border-slate-200 rounded-xl overflow-hidden bg-white max-h-64 overflow-y-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-50 border-b border-slate-200 text-slate-500 font-semibold sticky top-0">
                <tr>
                  <th className="py-2 px-3">Type</th>
                  <th className="py-2 px-3">Entity Identifier</th>
                  <th className="py-2 px-3">Properties</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 font-mono text-[11px]">
                {graphData?.nodes.map((node) => (
                  <tr key={node.id} className="hover:bg-slate-50/50">
                    <td className="py-2 px-3 font-semibold text-slate-700 flex items-center space-x-1.5">
                      {getNodeIcon(node.nodeType)}
                      <span>{node.nodeType}</span>
                    </td>
                    <td className="py-2 px-3 font-bold text-slate-900">{node.label}</td>
                    <td className="py-2 px-3 text-slate-500 truncate max-w-xs">
                      {JSON.stringify(node.properties)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};
