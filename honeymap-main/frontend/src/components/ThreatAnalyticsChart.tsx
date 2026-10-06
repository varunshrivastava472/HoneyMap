import React from 'react';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  Legend,
} from 'recharts';
import { Card, CardHeader, CardTitle, CardContent } from './ui/card';
import { AnalyticsPoint } from '../types';
import { Activity } from 'lucide-react';

interface ThreatAnalyticsChartProps {
  data: AnalyticsPoint[];
  range: 'day' | 'week' | 'month' | 'year';
  onRangeChange: (r: 'day' | 'week' | 'month' | 'year') => void;
  isLoading?: boolean;
}

export default function ThreatAnalyticsChart({
  data,
  range,
  onRangeChange,
  isLoading = false,
}: ThreatAnalyticsChartProps) {
  const formattedData = data.map((d) => {
    let label = d.bucket;
    if (range === 'day' && d.bucket.includes(' ')) {
      label = d.bucket.split(' ')[1] || d.bucket;
    } else if ((range === 'week' || range === 'month') && d.bucket.length >= 10) {
      label = d.bucket.slice(5);
    }
    return {
      ...d,
      displayLabel: label,
      malicious: (d.medium || 0) + (d.high || 0) + (d.critical || 0),
    };
  });

  return (
    <Card className="border-slate-200/80 bg-white rounded-2xl shadow-card">
      <CardHeader className="flex flex-row items-center justify-between pb-3">
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded-lg bg-brand-50 text-brand-600 border border-brand-200">
            <Activity className="w-4 h-4" />
          </div>
          <div>
            <CardTitle>Telemetry Volume & Threat Timeline</CardTitle>
            <p className="text-xs text-ink-muted">Normal vs malicious traffic distribution over time</p>
          </div>
        </div>
        <div className="flex items-center bg-slate-100/80 border border-slate-200/80 rounded-xl p-0.5 text-xs">
          {(['day', 'week', 'month', 'year'] as const).map((r) => (
            <button
              key={r}
              onClick={() => onRangeChange(r)}
              className={`px-2.5 py-1 rounded-lg text-xs font-medium uppercase transition-all cursor-pointer ${
                range === r
                  ? 'bg-white text-ink-primary font-semibold shadow-pill border border-slate-200/60'
                  : 'text-slate-500 hover:text-ink-primary'
              }`}
            >
              {r}
            </button>
          ))}
        </div>
      </CardHeader>
      <CardContent className="pt-2">
        {isLoading ? (
          <div className="h-64 flex items-center justify-center text-xs text-ink-muted">
            Aggregating real telemetry time buckets...
          </div>
        ) : formattedData.length === 0 ? (
          <div className="h-64 flex flex-col items-center justify-center text-xs text-ink-muted">
            <span>No telemetry recorded in selected window.</span>
            <span className="text-[11px] text-slate-400 mt-1">
              Events from live attackers will automatically populate this chart.
            </span>
          </div>
        ) : (
          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={formattedData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="colorNormalLight" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="var(--map-hub-pin)" stopOpacity={0.25} />
                    <stop offset="95%" stopColor="var(--map-hub-pin)" stopOpacity={0.0} />
                  </linearGradient>
                  <linearGradient id="colorMediumLight" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="var(--severity-medium)" stopOpacity={0.25} />
                    <stop offset="95%" stopColor="var(--severity-medium)" stopOpacity={0.0} />
                  </linearGradient>
                  <linearGradient id="colorHighLight" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="var(--severity-high)" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="var(--severity-high)" stopOpacity={0.0} />
                  </linearGradient>
                  <linearGradient id="colorCriticalLight" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="var(--severity-critical)" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="var(--severity-critical)" stopOpacity={0.0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--grid-surface)" vertical={false} />
                <XAxis
                  dataKey="displayLabel"
                  stroke="var(--text-muted)"
                  fontSize={11}
                  tickLine={false}
                  axisLine={{ stroke: 'var(--grid-line)' }}
                />
                <YAxis
                  stroke="var(--text-muted)"
                  fontSize={11}
                  tickLine={false}
                  axisLine={{ stroke: 'var(--grid-line)' }}
                  allowDecimals={false}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: 'var(--bg-panel-1)',
                    borderColor: 'var(--grid-line)',
                    borderRadius: '12px',
                    fontSize: '12px',
                    color: 'var(--text-ink)',
                    boxShadow: '0 10px 25px -5px var(--shadow-soft)',
                  }}
                  itemStyle={{ padding: '2px 0' }}
                />
                <Legend
                  wrapperStyle={{ fontSize: '11px', paddingTop: '10px' }}
                  iconSize={8}
                />
                <Area
                  type="monotone"
                  dataKey="low"
                  name="Normal / Low Probe"
                  stroke="var(--map-hub-pin)"
                  fillOpacity={1}
                  fill="url(#colorNormalLight)"
                  strokeWidth={2}
                />
                <Area
                  type="monotone"
                  dataKey="medium"
                  name="Suspicious (Medium)"
                  stroke="var(--severity-medium)"
                  fillOpacity={1}
                  fill="url(#colorMediumLight)"
                  strokeWidth={2}
                />
                <Area
                  type="monotone"
                  dataKey="high"
                  name="Exploit Attempt (High)"
                  stroke="var(--severity-high)"
                  fillOpacity={1}
                  fill="url(#colorHighLight)"
                  strokeWidth={2}
                />
                <Area
                  type="monotone"
                  dataKey="critical"
                  name="Honeytoken Breach (Critical)"
                  stroke="var(--severity-critical)"
                  fillOpacity={1}
                  fill="url(#colorCriticalLight)"
                  strokeWidth={2.5}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
