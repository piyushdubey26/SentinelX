import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  Zap,
  Clock,
  RotateCw,
  Info,
  AlertTriangle,
} from 'lucide-react';
import {
  getIncidentRiskBreakdownApi,
  recalculateIncidentRiskApi,
} from '../../../services/api';
import { RiskScoreBreakdown, RiskTier } from '../../../types';

interface RiskBreakdownViewProps {
  incidentId: string;
  incidentCode: string;
  initialScore?: number;
  initialTier?: RiskTier;
  onScoreUpdated?: (newScore: number, newTier: RiskTier) => void;
}

const getTierColor = (tier: RiskTier) => {
  switch (tier) {
    case 'CRITICAL':
      return {
        bg: 'bg-red-50',
        text: 'text-red-700',
        border: 'border-red-200',
        badge: 'bg-red-600 text-white',
        bar: 'bg-red-500',
      };
    case 'HIGH':
      return {
        bg: 'bg-orange-50',
        text: 'text-orange-700',
        border: 'border-orange-200',
        badge: 'bg-orange-500 text-white',
        bar: 'bg-orange-500',
      };
    case 'MEDIUM':
      return {
        bg: 'bg-amber-50',
        text: 'text-amber-700',
        border: 'border-amber-200',
        badge: 'bg-amber-500 text-white',
        bar: 'bg-amber-500',
      };
    case 'LOW':
    default:
      return {
        bg: 'bg-blue-50',
        text: 'text-blue-700',
        border: 'border-blue-200',
        badge: 'bg-blue-500 text-white',
        bar: 'bg-blue-500',
      };
  }
};

export const RiskBreakdownView: React.FC<RiskBreakdownViewProps> = ({
  incidentId,
  incidentCode,
  initialScore,
  initialTier,
  onScoreUpdated,
}) => {
  const [breakdown, setBreakdown] = useState<RiskScoreBreakdown | null>(null);
  const [loading, setLoading] = useState(true);
  const [recalculating, setRecalculating] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchBreakdown = async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await getIncidentRiskBreakdownApi(incidentId);
      if (res && res.riskFactors) {
        setBreakdown(res.riskFactors);
      }
    } catch (err: any) {
      console.error('Failed to load risk breakdown:', err);
      setError(err?.response?.data?.message || 'Failed to evaluate incident risk factors.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchBreakdown();
  }, [incidentId]);

  const handleRecalculate = async () => {
    try {
      setRecalculating(true);
      const res = await recalculateIncidentRiskApi(incidentId);
      await fetchBreakdown();
      if (onScoreUpdated && res.riskScore !== undefined) {
        onScoreUpdated(Number(res.riskScore), res.riskTier);
      }
    } catch (err: any) {
      console.error('Failed to recalculate risk:', err);
      setError(err?.response?.data?.message || 'Failed to recalculate risk score.');
    } finally {
      setRecalculating(false);
    }
  };

  if (loading && !breakdown) {
    return (
      <div className="py-12 flex flex-col items-center justify-center space-y-3">
        <RotateCw className="w-6 h-6 animate-spin text-slate-400" />
        <span className="text-xs text-slate-500 font-medium">
          Evaluating mathematical risk factors and dampening curves...
        </span>
      </div>
    );
  }

  if (error && !breakdown) {
    return (
      <div className="p-6 bg-red-50 border border-red-200 rounded-xl text-center space-y-2">
        <AlertTriangle className="w-6 h-6 text-red-500 mx-auto" />
        <p className="text-xs text-red-700 font-medium">{error}</p>
        <button
          onClick={fetchBreakdown}
          className="text-xs text-red-800 underline font-semibold"
        >
          Retry Calculation
        </button>
      </div>
    );
  }

  const score = breakdown?.score ?? initialScore ?? 0;
  const tier = breakdown?.tier ?? initialTier ?? 'LOW';
  const tierStyle = getTierColor(tier);

  const impact = breakdown?.components.impact;
  const confidence = breakdown?.components.confidence;
  const recency = breakdown?.components.recency;

  return (
    <div className="space-y-6">
      {/* Top Risk Header Card */}
      <div className={`p-5 rounded-xl border ${tierStyle.border} ${tierStyle.bg} flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4`}>
        <div className="flex items-center space-x-4">
          <div className="w-16 h-16 rounded-xl bg-white shadow-xs border border-slate-200 flex flex-col items-center justify-center">
            <span className="text-2xl font-black font-mono tracking-tight text-slate-900">
              {score.toFixed(0)}
            </span>
            <span className="text-[10px] text-slate-400 font-bold uppercase tracking-wider">
              / 100
            </span>
          </div>

          <div>
            <div className="flex items-center space-x-2">
              <span className={`px-2.5 py-0.5 rounded-full text-xs font-bold uppercase tracking-wider ${tierStyle.badge}`}>
                {tier} Risk
              </span>
              <span className="text-xs text-slate-500 font-mono">
                v{breakdown?.version || '1.0.0'}
              </span>
            </div>
            <h3 className="text-sm font-semibold text-slate-900 mt-1">
              Incident {incidentCode} — Explainable Risk Breakdown
            </h3>
            <p className="text-xs text-slate-600">
              Deterministic multi-factor score separating impact severity, evidence confidence, and recency.
            </p>
          </div>
        </div>

        <button
          onClick={handleRecalculate}
          disabled={recalculating}
          className="inline-flex items-center space-x-1.5 px-3 py-1.5 bg-white border border-slate-300 rounded-lg text-xs font-semibold text-slate-700 hover:bg-slate-50 transition-colors shadow-xs disabled:opacity-50"
        >
          <RotateCw className={`w-3.5 h-3.5 ${recalculating ? 'animate-spin' : ''}`} />
          <span>{recalculating ? 'Recalculating...' : 'Recalculate'}</span>
        </button>
      </div>

      {/* 3 Core Components Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Component 1: Impact */}
        <div className="p-4 rounded-xl border border-slate-200 bg-white shadow-xs space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <ShieldAlert className="w-4 h-4 text-red-500" />
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-700">
                1. Impact Component
              </h4>
            </div>
            <span className="text-sm font-black font-mono text-slate-900">
              {impact?.score.toFixed(1) || '0.0'}/100
            </span>
          </div>

          <div className="w-full bg-slate-100 rounded-full h-1.5 overflow-hidden">
            <div
              className="bg-red-500 h-1.5 rounded-full"
              style={{ width: `${Math.min(100, impact?.score || 0)}%` }}
            />
          </div>

          <div className="text-[11px] text-slate-600 space-y-1.5 pt-1">
            <div className="flex justify-between">
              <span>Detection Severity:</span>
              <span className="font-mono font-medium text-slate-800">
                {((impact?.severityScore || 0) * 100).toFixed(0)}%
              </span>
            </div>
            <div className="flex justify-between">
              <span>Asset Criticality:</span>
              <span className="font-mono font-medium text-slate-800">
                {((impact?.assetCriticalityScore || 0) * 100).toFixed(0)}%
              </span>
            </div>
            <div className="flex justify-between">
              <span>Environment Modifier:</span>
              <span className="font-mono font-medium text-slate-800">
                {((impact?.environmentModifier || 1) * 100).toFixed(0)}%
              </span>
            </div>
            <div className="flex justify-between">
              <span>Blast Radius Exposure:</span>
              <span className="font-mono font-medium text-slate-800">
                {((impact?.blastRadiusScore || 0) * 100).toFixed(0)}%
              </span>
            </div>
          </div>
        </div>

        {/* Component 2: Confidence & Velocity */}
        <div className="p-4 rounded-xl border border-slate-200 bg-white shadow-xs space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <Zap className="w-4 h-4 text-amber-500" />
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-700">
                2. Evidence Confidence
              </h4>
            </div>
            <span className="text-sm font-black font-mono text-slate-900">
              {((confidence?.score || 0) * 100).toFixed(1)}%
            </span>
          </div>

          <div className="w-full bg-slate-100 rounded-full h-1.5 overflow-hidden">
            <div
              className="bg-amber-500 h-1.5 rounded-full"
              style={{ width: `${Math.min(100, (confidence?.score || 0) * 100)}%` }}
            />
          </div>

          <div className="text-[11px] text-slate-600 space-y-1.5 pt-1">
            <div className="flex justify-between">
              <span>Correlation Confidence:</span>
              <span className="font-mono font-medium text-slate-800">
                {((confidence?.correlationScore || 0) * 100).toFixed(0)}%
              </span>
            </div>
            <div className="flex justify-between">
              <span>Logarithmic Velocity:</span>
              <span className="font-mono font-medium text-slate-800">
                {((confidence?.velocityScore || 0) * 100).toFixed(0)}%
              </span>
            </div>
            <div className="flex justify-between">
              <span>Raw Events Sampled:</span>
              <span className="font-mono font-medium text-slate-800">
                {confidence?.rawEventCount || 1} events
              </span>
            </div>
            <div className="flex justify-between">
              <span>Rule Fidelity:</span>
              <span className="font-mono font-medium text-slate-800">
                {((confidence?.detectionFidelityScore || 0) * 100).toFixed(0)}%
              </span>
            </div>
          </div>
        </div>

        {/* Component 3: Recency Decay */}
        <div className="p-4 rounded-xl border border-slate-200 bg-white shadow-xs space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <Clock className="w-4 h-4 text-blue-500" />
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-700">
                3. Recency Decay
              </h4>
            </div>
            <span className="text-sm font-black font-mono text-slate-900">
              {((recency?.decayMultiplier || 1) * 100).toFixed(1)}%
            </span>
          </div>

          <div className="w-full bg-slate-100 rounded-full h-1.5 overflow-hidden">
            <div
              className="bg-blue-500 h-1.5 rounded-full"
              style={{ width: `${Math.min(100, (recency?.decayMultiplier || 1) * 100)}%` }}
            />
          </div>

          <div className="text-[11px] text-slate-600 space-y-1.5 pt-1">
            <div className="flex justify-between">
              <span>Elapsed Inactive Time:</span>
              <span className="font-mono font-medium text-slate-800">
                {recency?.elapsedHours?.toFixed(1) || '0.0'} hrs
              </span>
            </div>
            <div className="flex justify-between">
              <span>Decay Half-Life:</span>
              <span className="font-mono font-medium text-slate-800">
                24.0 hrs
              </span>
            </div>
            <div className="flex justify-between">
              <span>Decay Floor Limit:</span>
              <span className="font-mono font-medium text-slate-800">
                50.0%
              </span>
            </div>
            <div className="flex justify-between">
              <span>Status:</span>
              <span className="font-mono font-semibold text-emerald-600">
                {(recency?.elapsedHours || 0) < 1.0 ? 'Active / Emerging' : 'Decayed'}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Mathematical Audit Explanation Box */}
      <div className="p-4 rounded-xl border border-slate-200 bg-slate-50/50 space-y-3">
        <div className="flex items-center space-x-2">
          <Info className="w-4 h-4 text-slate-600" />
          <h4 className="text-xs font-bold uppercase tracking-wider text-slate-800">
            Explainable Factor Rationale
          </h4>
        </div>

        <ul className="space-y-1.5 text-xs text-slate-700">
          {breakdown?.explanation && breakdown.explanation.length > 0 ? (
            breakdown.explanation.map((item, idx) => (
              <li key={idx} className="flex items-start space-x-2">
                <span className="text-slate-400 mt-0.5">•</span>
                <span>{item}</span>
              </li>
            ))
          ) : (
            <li className="text-slate-400">No explanation available.</li>
          )}
        </ul>

        {impact?.assumedDefaults && impact.assumedDefaults.length > 0 && (
          <div className="mt-3 pt-3 border-t border-slate-200 text-xs text-amber-700 flex items-start space-x-2">
            <AlertTriangle className="w-3.5 h-3.5 text-amber-600 mt-0.5 shrink-0" />
            <span>
              <strong>Imputed Defaults:</strong> {impact.assumedDefaults.join('; ')}
            </span>
          </div>
        )}
      </div>
    </div>
  );
};
