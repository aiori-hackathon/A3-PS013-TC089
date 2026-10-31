import React from 'react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts';

interface TimeData {
  date: string;
  count: number;
}

interface EventsOverTimeProps {
  data: TimeData[];
  height?: number;
}

export const EventsOverTime: React.FC<EventsOverTimeProps> = ({
  data,
  height = 260,
}) => {
  const chartData = data && data.length > 0 ? data : [];

  if (chartData.length === 0) {
    return (
      <div className="flex h-56 items-center justify-center text-xs font-mono text-slate-500">
        NO TEMPORAL EVENT TELEMETRY AVAILABLE
      </div>
    );
  }

  return (
    <div className="w-full" style={{ height }}>
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={chartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
          <defs>
            <linearGradient id="eventGradient" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#0ea5e9" stopOpacity={0.4} />
              <stop offset="95%" stopColor="#0ea5e9" stopOpacity={0.0} />
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
          <XAxis
            dataKey="date"
            stroke="#64748b"
            tick={{ fontSize: 11, fill: '#94a3b8' }}
            tickLine={{ stroke: '#1e293b' }}
          />
          <YAxis
            stroke="#64748b"
            tick={{ fontSize: 11, fill: '#94a3b8' }}
            tickLine={{ stroke: '#1e293b' }}
            allowDecimals={false}
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
            labelStyle={{ color: '#94a3b8', fontWeight: 600 }}
          />
          <Area
            type="monotone"
            dataKey="count"
            name="Events"
            stroke="#0ea5e9"
            strokeWidth={2}
            fillOpacity={1}
            fill="url(#eventGradient)"
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
};
