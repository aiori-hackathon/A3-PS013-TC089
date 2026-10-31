import React from 'react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from 'recharts';

interface ComparisonMetric {
  metric: string;
  Manual: number;
  Vigilance: number;
}

interface TriageComparisonProps {
  data: ComparisonMetric[];
  height?: number;
}

export const TriageComparisonChart: React.FC<TriageComparisonProps> = ({
  data,
  height = 280,
}) => {
  return (
    <div className="w-full" style={{ height }}>
      <ResponsiveContainer width="100%" height="100%">
        <BarChart
          data={data}
          margin={{ top: 20, right: 30, left: 10, bottom: 5 }}
        >
          <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
          <XAxis
            dataKey="metric"
            stroke="#64748b"
            tick={{ fontSize: 12, fill: '#94a3b8' }}
          />
          <YAxis
            stroke="#64748b"
            tick={{ fontSize: 12, fill: '#94a3b8' }}
          />
          <Tooltip
            contentStyle={{
              backgroundColor: '#111827',
              borderColor: '#1e293b',
              borderRadius: '0.375rem',
              color: '#f8fafc',
              fontSize: '12px',
              fontFamily: 'monospace',
            }}
          />
          <Legend
            verticalAlign="top"
            height={36}
            formatter={(value: string) => (
              <span className="text-xs font-mono text-slate-300">{value}</span>
            )}
          />
          <Bar dataKey="Manual" fill="#64748b" radius={[4, 4, 0, 0]} />
          <Bar dataKey="Vigilance" fill="#0ea5e9" radius={[4, 4, 0, 0]} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
};
