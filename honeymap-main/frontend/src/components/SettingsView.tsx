import React from 'react';
import { Card, CardHeader, CardTitle, CardContent } from './ui/card';
import { Badge } from './ui/badge';
import { Sliders, Shield, Lock, Database, Clock } from 'lucide-react';

export default function SettingsView() {
  const configs = [
    {
      group: 'Rate Limiting & DDoS Protection',
      icon: Shield,
      items: [
        { key: 'Per-IP Request Window', val: '60.0 seconds', note: 'Sliding-window memory deque' },
        { key: 'Max Requests per Window', val: '300 req / IP', note: 'Exceeding returns HTTP 429' },
        { key: 'Max Request Payload Size', val: '1.0 MB', note: 'Exceeding returns HTTP 413' },
      ],
    },
    {
      group: 'Async Attacker Tarpit Curves',
      icon: Clock,
      items: [
        { key: 'Progression Formula', val: 'min(0.2s × repeat_count, 3.0s)', note: 'Non-blocking asyncio.sleep' },
        { key: 'Maximum Tarpit Cap', val: '3.0 seconds', note: 'Prevents client connection timeouts' },
        { key: 'Concurrent Health Latency', val: '< 10 ms', note: 'Zero event loop blocking verified' },
      ],
    },
    {
      group: 'Database & Real-Time Engine',
      icon: Database,
      items: [
        { key: 'Async Driver', val: 'aiosqlite (Python 3.12)', note: 'Replaced legacy SQLite thread lock' },
        { key: 'SQLite Journal Mode', val: 'WAL (Write-Ahead Logging)', note: 'High concurrent write throughput' },
        { key: 'Busy Timeout', val: '30,000 ms (30 seconds)', note: 'Prevents database lock contention' },
        { key: 'Real-Time Transport', val: 'python-socketio ASGI Mount', note: 'WebSocket + 3s Polling Watchdog' },
      ],
    },
    {
      group: 'CORS & Hardening',
      icon: Lock,
      items: [
        { key: 'Allowed Origins', val: 'Configurable (Env Var)', note: 'Strictly scoped (no wildcard *)' },
        { key: 'Template Token Injection', val: 'FastAPI Lifespan Boot', note: 'Fresh bait credentials per startup' },
      ],
    },
  ];

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-bold tracking-tight text-ink-primary flex items-center gap-2">
          <Sliders className="w-5 h-5 text-brand-600" />
          SOC Hardening & Security Parameters
        </h2>
        <p className="text-xs text-ink-muted mt-1">
          Read-only view of active backend rate limits, non-blocking tarpit curves, and database WAL
          parameters.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
        {configs.map((grp, idx) => {
          const Icon = grp.icon;
          return (
            <Card key={idx} className="border-slate-200/80 bg-white rounded-2xl shadow-card">
              <CardHeader className="pb-3">
                <div className="flex items-center gap-2">
                  <div className="p-1.5 rounded-lg bg-emerald-50 text-brand-600 border border-brand-200">
                    <Icon className="w-4 h-4" />
                  </div>
                  <div>
                    <CardTitle>{grp.group}</CardTitle>
                    <p className="text-xs text-ink-muted">Active server runtime configuration</p>
                  </div>
                </div>
              </CardHeader>
              <CardContent className="space-y-3 pt-2">
                {grp.items.map((item, i) => (
                  <div
                    key={i}
                    className="p-3 rounded-xl bg-slate-50/80 border border-slate-200/60 flex items-center justify-between"
                  >
                    <div>
                      <div className="text-xs font-semibold text-ink-primary">{item.key}</div>
                      <div className="text-[11px] text-ink-muted">{item.note}</div>
                    </div>
                    <Badge variant="outline" className="font-mono text-xs text-brand-700 bg-white border-slate-200 shadow-sm">
                      {item.val}
                    </Badge>
                  </div>
                ))}
              </CardContent>
            </Card>
          );
        })}
      </div>
    </div>
  );
}
