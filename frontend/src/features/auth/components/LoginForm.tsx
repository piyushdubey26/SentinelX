import React, { useState } from 'react';
import { ShieldCheck, Lock, AlertCircle, Loader2 } from 'lucide-react';
import { loginApi } from '../../../services/api';
import { UserProfile } from '../../../types';

interface LoginFormProps {
  onSuccess: (user: UserProfile) => void;
}

export const LoginForm: React.FC<LoginFormProps> = ({ onSuccess }) => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      const res = await loginApi(email, password);
      onSuccess(res.user);
    } catch (err: any) {
      setError(err.response?.data?.message || 'Authentication failed. Please verify credentials.');
    } finally {
      setLoading(false);
    }
  };

  const handleQuickFill = (role: 'admin' | 'analyst') => {
    if (role === 'admin') {
      setEmail('admin@sentinelx.local');
      setPassword('AdminPassword123!');
    } else {
      setEmail('analyst@sentinelx.local');
      setPassword('AnalystPassword123!');
    }
  };

  return (
    <div className="w-full max-w-md mx-auto bg-white rounded-2xl border border-slate-200 shadow-sm p-8 space-y-6">
      <div className="text-center space-y-2">
        <div className="w-12 h-12 bg-slate-900 rounded-xl mx-auto flex items-center justify-center text-white shadow-xs">
          <ShieldCheck className="w-7 h-7 stroke-[2]" />
        </div>
        <h2 className="text-xl font-bold tracking-tight text-slate-900 font-sans">
          SentinelX SOC Access
        </h2>
        <p className="text-xs text-slate-500">
          Enter analyst credentials to access telemetry and incident queue
        </p>
      </div>

      {error && (
        <div className="p-3 bg-red-50 border border-red-200 rounded-lg flex items-center text-xs text-red-700 space-x-2">
          <AlertCircle className="w-4 h-4 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="block text-xs font-semibold text-slate-700 uppercase tracking-wider mb-1">
            Email Address
          </label>
          <input
            type="email"
            required
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="analyst@sentinelx.local"
            className="w-full px-3.5 py-2 text-sm border border-slate-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-slate-900/10 focus:border-slate-900 transition-all font-sans"
          />
        </div>

        <div>
          <label className="block text-xs font-semibold text-slate-700 uppercase tracking-wider mb-1">
            Password
          </label>
          <div className="relative">
            <input
              type="password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••••••"
              className="w-full px-3.5 py-2 text-sm border border-slate-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-slate-900/10 focus:border-slate-900 transition-all font-sans"
            />
            <Lock className="w-4 h-4 text-slate-400 absolute right-3 top-2.5" />
          </div>
        </div>

        <button
          type="submit"
          disabled={loading}
          className="w-full py-2.5 px-4 bg-slate-900 hover:bg-slate-800 text-white rounded-lg text-sm font-semibold tracking-tight transition-all flex items-center justify-center space-x-2 disabled:opacity-50"
        >
          {loading ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin" />
              <span>Authenticating...</span>
            </>
          ) : (
            <span>Authenticate Session</span>
          )}
        </button>
      </form>

      {/* Quick Access Dev Presets */}
      <div className="pt-2 border-t border-slate-100 space-y-2">
        <span className="text-[10px] uppercase font-bold text-slate-400 tracking-wider block text-center">
          Developer Test Presets
        </span>
        <div className="grid grid-cols-2 gap-2">
          <button
            type="button"
            onClick={() => handleQuickFill('admin')}
            className="px-2.5 py-1.5 text-xs font-medium border border-slate-200 rounded-md hover:bg-slate-50 text-slate-700 text-center transition-colors"
          >
            Fill Admin User
          </button>
          <button
            type="button"
            onClick={() => handleQuickFill('analyst')}
            className="px-2.5 py-1.5 text-xs font-medium border border-slate-200 rounded-md hover:bg-slate-50 text-slate-700 text-center transition-colors"
          >
            Fill SOC Analyst
          </button>
        </div>
      </div>
    </div>
  );
};
