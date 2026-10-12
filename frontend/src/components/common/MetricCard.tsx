import React from 'react';

interface MetricCardProps {
  label: string;
  value: string | number;
  subtext: string;
  colorVariant?: 'critical' | 'neutral' | 'high' | 'medium';
}

export const MetricCard: React.FC<MetricCardProps> = ({
  label,
  value,
  subtext,
  colorVariant = 'neutral',
}) => {
  const valueColor =
    colorVariant === 'critical'
      ? 'text-red-500'
      : colorVariant === 'high'
      ? 'text-orange-500'
      : colorVariant === 'medium'
      ? 'text-amber-500'
      : 'text-slate-900';

  return (
    <div className="flex flex-col py-2">
      <span className="text-sm font-medium text-slate-600 tracking-tight">{label}</span>
      <span className={`text-4xl font-bold tracking-tight my-1 ${valueColor}`}>
        {typeof value === 'number' && value < 10 ? `0${value}` : value}
      </span>
      <span className="text-xs text-slate-400 font-medium">{subtext}</span>
    </div>
  );
};
