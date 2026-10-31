import React from 'react';
import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from 'recharts';

interface SeverityData {
  severity: string;
  count: number;
}

interface SeverityChartProps {
  data: SeverityData[];
  height?: number;
}

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#ef4444',
  HIGH: '#f87171',
  MEDIUM: '#f59e0b',
  LOW: '#eab308',
  INFO: '#38bdf8',
  UNKNOWN: '#94a3b8',
};

export const SeverityChart: React.FC<SeverityChartProps> = ({
  data,
  height = 260,
}) => {
  const chartData = data && data.length > 0 ? data : [];

  if (chartData.length === 0 || chartData.every((d) => d.count === 0)) {
    return (
      <div className="flex h-56 items-center justify-center text-xs font-mono text-slate-500">
        NO SEVERITY TELEMETRY AVAILABLE
      </div>
    );
  }

  return (
    <div className="w-full" style={{ height }}>
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={chartData}
            dataKey="count"
            nameKey="severity"
            cx="50%"
            cy="50%"
            innerRadius={55}
            outerRadius={85}
            paddingAngle={3}
            stroke="#111827"
            strokeWidth={2}
          >
            {chartData.map((entry, index) => {
              const color =
                SEVERITY_COLORS[entry.severity.toUpperCase()] ||
                `hsl(${(index * 70) % 360}, 70%, 50%)`;
              return <Cell key={`cell-${index}`} fill={color} />;
            })}
          </Pie>
          <Tooltip
            contentStyle={{
              backgroundColor: '#111827',
              borderColor: '#1e293b',
              borderRadius: '0.375rem',
              color: '#f8fafc',
              fontSize: '12px',
              fontFamily: 'monospace',
            }}
            itemStyle={{ color: '#38bdf8' }}
          />
          <Legend
            verticalAlign="bottom"
            height={36}
            formatter={(value: string) => (
              <span className="text-xs font-mono text-slate-300">{value}</span>
            )}
          />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
};
