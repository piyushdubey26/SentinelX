import React from 'react';
import { Incident, Severity } from '../../../types';
import { ChevronLeft, ChevronRight, Loader2, AlertCircle } from 'lucide-react';

interface IncidentQueueProps {
  incidents: Incident[];
  loading: boolean;
  error: string | null;
  total: number;
  page: number;
  pageSize: number;
  onPageChange: (newPage: number) => void;
  onSelectIncident: (incident: Incident) => void;
  onRefresh: () => void;
}

const getSeverityClass = (severity: Severity): string => {
  switch (severity) {
    case 'CRITICAL':
      return 'text-red-500 font-bold';
    case 'HIGH':
      return 'text-orange-600 font-bold';
    case 'MEDIUM':
      return 'text-amber-600 font-medium';
    case 'LOW':
      return 'text-blue-600 font-medium';
    default:
      return 'text-slate-500 font-medium';
  }
};

export const IncidentQueue: React.FC<IncidentQueueProps> = ({
  incidents,
  loading,
  error,
  total,
  page,
  pageSize,
  onPageChange,
  onSelectIncident,
  onRefresh,
}) => {
  const totalPages = Math.ceil(total / pageSize) || 1;

  return (
    <div className="border border-slate-200 rounded-xl bg-white shadow-xs overflow-hidden">
      {/* Queue Header */}
      <div className="px-5 py-4 border-b border-slate-100 flex items-center justify-between">
        <div className="flex items-center space-x-2">
          <h2 className="text-base font-semibold text-slate-900 tracking-tight">
            Incident queue
          </h2>
          <span className="text-xs bg-slate-100 text-slate-600 px-2 py-0.5 rounded-full font-mono font-medium">
            {total} incidents
          </span>
        </div>
        <div className="flex items-center space-x-2">
          {loading && <Loader2 className="w-3.5 h-3.5 animate-spin text-slate-400" />}
          <span className="text-xs text-slate-400 font-medium">Real-time Telemetry</span>
        </div>
      </div>

      {/* Error state */}
      {error && (
        <div className="p-6 text-center space-y-2">
          <AlertCircle className="w-6 h-6 text-red-500 mx-auto" />
          <p className="text-xs text-red-600 font-medium">{error}</p>
          <button
            onClick={onRefresh}
            className="text-xs text-slate-700 underline font-semibold"
          >
            Retry Connection
          </button>
        </div>
      )}

      {/* Loading Skeleton */}
      {loading && incidents.length === 0 && !error && (
        <div className="divide-y divide-slate-100 p-4 space-y-3">
          {[1, 2, 3].map((i) => (
            <div key={i} className="animate-pulse flex justify-between py-2">
              <div className="space-y-1">
                <div className="h-4 bg-slate-200 rounded w-24"></div>
                <div className="h-3 bg-slate-100 rounded w-48"></div>
              </div>
              <div className="h-4 bg-slate-200 rounded w-16"></div>
            </div>
          ))}
        </div>
      )}

      {/* Empty State */}
      {!loading && !error && incidents.length === 0 && (
        <div className="p-10 text-center text-xs text-slate-500">
          No incidents logged in PostgreSQL yet. Submit synthetic events to trigger detection.
        </div>
      )}

      {/* Incident Rows */}
      {!error && incidents.length > 0 && (
        <div className="divide-y divide-slate-100">
          {incidents.map((incident) => (
            <div
              key={incident.id}
              onClick={() => onSelectIncident(incident)}
              className="px-5 py-4 flex items-center justify-between hover:bg-slate-50/80 transition-colors cursor-pointer group"
            >
              <div className="space-y-0.5">
                <div className="text-sm font-bold text-slate-900 font-mono tracking-tight group-hover:text-slate-700">
                  {incident.code}
                </div>
                <div className="text-xs text-slate-500 font-normal">
                  {incident.title}
                </div>
              </div>

              <div className="flex items-center space-x-3">
                <span className="text-[11px] font-mono text-slate-400">
                  {incident.status}
                </span>
                <span className={`text-xs tracking-wider uppercase ${getSeverityClass(incident.severity)}`}>
                  {incident.severity}
                </span>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Pagination Bar */}
      {total > pageSize && (
        <div className="px-5 py-3 border-t border-slate-100 flex items-center justify-between text-xs text-slate-500 bg-slate-50/50">
          <span>
            Page {page} of {totalPages}
          </span>
          <div className="flex items-center space-x-1">
            <button
              disabled={page <= 1 || loading}
              onClick={() => onPageChange(page - 1)}
              className="p-1 rounded hover:bg-slate-200 disabled:opacity-40"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <button
              disabled={page >= totalPages || loading}
              onClick={() => onPageChange(page + 1)}
              className="p-1 rounded hover:bg-slate-200 disabled:opacity-40"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}
    </div>
  );
};
