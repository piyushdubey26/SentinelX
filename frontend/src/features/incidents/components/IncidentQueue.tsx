import React from 'react';
import { Incident, Severity } from '../../../types';

interface IncidentQueueProps {
  incidents: Incident[];
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

export const IncidentQueue: React.FC<IncidentQueueProps> = ({ incidents }) => {
  return (
    <div className="border border-slate-200 rounded-xl bg-white shadow-xs overflow-hidden">
      {/* Queue Header */}
      <div className="px-5 py-4 border-b border-slate-100 flex items-center justify-between">
        <h2 className="text-base font-semibold text-slate-900 tracking-tight">
          Incident queue
        </h2>
        <span className="text-xs text-slate-400 font-medium">Illustrative UI</span>
      </div>

      {/* Incident Rows */}
      <div className="divide-y divide-slate-100">
        {incidents.map((incident) => (
          <div
            key={incident.id}
            className="px-5 py-4 flex items-center justify-between hover:bg-slate-50/60 transition-colors"
          >
            <div className="space-y-0.5">
              <div className="text-sm font-bold text-slate-900 font-mono tracking-tight">
                {incident.code}
              </div>
              <div className="text-xs text-slate-500 font-normal">
                {incident.title}
              </div>
            </div>

            <div className={`text-xs tracking-wider uppercase ${getSeverityClass(incident.severity)}`}>
              {incident.severity}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
