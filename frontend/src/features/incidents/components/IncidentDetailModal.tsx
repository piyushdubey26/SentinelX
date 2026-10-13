import React, { useState } from 'react';
import { X, ShieldAlert, Network, FileText } from 'lucide-react';
import { Incident, IncidentStatus } from '../../../types';
import { updateIncidentStatusApi } from '../../../services/api';
import { InvestigationGraphView } from './InvestigationGraphView';

interface IncidentDetailModalProps {
  incident: Incident;
  onClose: () => void;
  onStatusUpdated: (updated: Incident) => void;
}

export const IncidentDetailModal: React.FC<IncidentDetailModalProps> = ({
  incident,
  onClose,
  onStatusUpdated,
}) => {
  const [updating, setUpdating] = useState(false);
  const [modalTab, setModalTab] = useState<'overview' | 'graph'>('overview');

  const handleStatusChange = async (newStatus: IncidentStatus) => {
    setUpdating(true);
    try {
      const updated = await updateIncidentStatusApi(incident.id, newStatus);
      onStatusUpdated(updated);
    } catch (err) {
      console.error('Failed to update status', err);
    } finally {
      setUpdating(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-slate-900/40 backdrop-blur-xs flex items-center justify-center p-4">
      <div className="bg-white rounded-2xl border border-slate-200 shadow-xl w-full max-w-3xl overflow-hidden animate-in fade-in zoom-in-95 duration-150">
        {/* Modal Header */}
        <div className="px-6 py-4 border-b border-slate-100 flex items-center justify-between bg-slate-50/50">
          <div className="flex items-center space-x-3">
            <span className="font-mono text-sm font-bold bg-slate-900 text-white px-2.5 py-1 rounded-md">
              {incident.code}
            </span>
            <span
              className={`text-xs uppercase font-bold tracking-wider px-2 py-0.5 rounded-full ${
                incident.severity === 'CRITICAL'
                  ? 'bg-red-100 text-red-700'
                  : 'bg-orange-100 text-orange-700'
              }`}
            >
              {incident.severity}
            </span>
          </div>

          {/* Navigation Tabs */}
          <div className="flex bg-slate-100 p-0.5 rounded-lg border border-slate-200 text-xs">
            <button
              onClick={() => setModalTab('overview')}
              className={`px-3 py-1 rounded-md font-semibold flex items-center space-x-1.5 transition-colors ${
                modalTab === 'overview'
                  ? 'bg-white text-slate-900 shadow-xs'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              <FileText className="w-3.5 h-3.5" />
              <span>Overview</span>
            </button>
            <button
              onClick={() => setModalTab('graph')}
              className={`px-3 py-1 rounded-md font-semibold flex items-center space-x-1.5 transition-colors ${
                modalTab === 'graph'
                  ? 'bg-white text-slate-900 shadow-xs'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              <Network className="w-3.5 h-3.5 text-blue-600" />
              <span>Graph Investigation</span>
            </button>
          </div>

          <button
            onClick={onClose}
            className="p-1 rounded-md text-slate-400 hover:text-slate-600 hover:bg-slate-100 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 space-y-5 max-h-[75vh] overflow-y-auto">
          {modalTab === 'graph' ? (
            <InvestigationGraphView incidentId={incident.id} />
          ) : (
            <>
              <div>
                <h3 className="text-lg font-bold text-slate-900">{incident.title}</h3>
                <p className="text-xs text-slate-500 mt-1 leading-relaxed">{incident.summary}</p>
              </div>

          {/* Incident Metadata Grid */}
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 bg-slate-50 rounded-xl p-4 border border-slate-100 text-xs">
            <div>
              <span className="text-slate-400 block font-medium">Status</span>
              <span className="font-bold text-slate-900 font-mono mt-0.5 block">
                {incident.status}
              </span>
            </div>
            <div>
              <span className="text-slate-400 block font-medium">Source IP</span>
              <span className="font-bold text-slate-900 font-mono mt-0.5 block">
                {incident.sourceIp || 'N/A'}
              </span>
            </div>
            <div>
              <span className="text-slate-400 block font-medium">Created Time</span>
              <span className="text-slate-700 mt-0.5 block font-mono text-[11px]">
                {new Date(incident.createdAt).toLocaleTimeString()}
              </span>
            </div>
          </div>

          {/* Linked Detection Evidence */}
          {incident.detection && (
            <div className="border border-slate-200 rounded-xl p-4 space-y-3 bg-white">
              <div className="flex items-center space-x-2 text-slate-900 font-semibold text-xs uppercase tracking-wider">
                <ShieldAlert className="w-4 h-4 text-red-500" />
                <span>Deterministic Detection Evidence</span>
              </div>

              <div className="space-y-1.5 text-xs text-slate-600">
                <div className="flex justify-between">
                  <span className="text-slate-400">Trigger Rule:</span>
                  <span className="font-mono font-medium text-slate-900">
                    {incident.detection.ruleId} — {incident.detection.ruleName}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Trigger Count:</span>
                  <span className="font-mono font-bold text-red-600">
                    {incident.detection.triggerCount} matching events
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Sliding Window Duration:</span>
                  <span className="font-mono text-slate-900">
                    {incident.detection.timeWindowSeconds} seconds
                  </span>
                </div>
              </div>

              {incident.detection.evidence?.triggerEventIds && (
                <div className="pt-2 border-t border-slate-100">
                  <span className="text-[11px] font-semibold text-slate-500 block mb-1">
                    Event Telemetry Trace IDs ({incident.detection.evidence.triggerEventIds.length}):
                  </span>
                  <div className="bg-slate-900 text-slate-200 p-2.5 rounded-lg font-mono text-[11px] overflow-x-auto space-y-0.5 max-h-28">
                    {incident.detection.evidence.triggerEventIds.map((evtId: string, idx: number) => (
                      <div key={evtId} className="flex space-x-2">
                        <span className="text-slate-500">[{idx + 1}]</span>
                        <span className="text-emerald-400">{evtId}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Triage Actions */}
          <div className="pt-2">
            <span className="text-xs font-semibold text-slate-700 block mb-2">
              Analyst Triage Action:
            </span>
            <div className="flex flex-wrap gap-2">
              {(['OPEN', 'INVESTIGATING', 'CONTAINED', 'RESOLVED'] as IncidentStatus[]).map(
                (statusOption) => (
                  <button
                    key={statusOption}
                    disabled={updating || incident.status === statusOption}
                    onClick={() => handleStatusChange(statusOption)}
                    className={`px-3 py-1.5 text-xs font-semibold rounded-lg transition-all ${
                      incident.status === statusOption
                        ? 'bg-slate-900 text-white shadow-xs'
                        : 'bg-slate-100 text-slate-700 hover:bg-slate-200'
                    }`}
                  >
                    Set {statusOption}
                  </button>
                ),
              )}
            </div>
          </div>
        </>
      )}
    </div>
  </div>
</div>
);
};
