import React from 'react';
import { Card, CardHeader, CardTitle, CardContent } from './ui/card';
import { Badge } from './ui/badge';
import { Cpu, CheckCircle2, ShieldCheck, Zap } from 'lucide-react';
import { Severity } from '../types';

export default function DetectionEngineView() {
  const rules = [
    {
      name: 'Exact Honeytoken String Reuse',
      severity: 'CRITICAL',
      certainty: '100% Deterministic',
      trigger: 'Payload contains exact active AWS Access Key ID, Secret, or DB Password',
      action: 'Immediate score surge to 100.0, maximum progressive tarpit delay (3.0s)',
    },
    {
      name: 'SQL Injection Signature Heuristic',
      severity: 'HIGH',
      certainty: '85% Pattern Match',
      trigger: "UNION SELECT, OR 1=1, SLEEP(), BENCHMARK(), INFORMATION_SCHEMA probes",
      action: '+25.0 Threat Score penalty, progressive tarpit delay',
    },
    {
      name: 'Cross-Site Scripting (XSS) Signature',
      severity: 'HIGH',
      certainty: '85% Pattern Match',
      trigger: "<script>, javascript:, onerror=, onload=, document.cookie injection",
      action: '+25.0 Threat Score penalty, progressive tarpit delay',
    },
    {
      name: 'Sensitive File Trapdoor Probe',
      severity: 'MEDIUM',
      certainty: '70% Trap Match',
      trigger: "Requests targeting /.env, /backup.sql, /config.php, /.git/config, etc.",
      action: '+10.0 Threat Score penalty, dynamic bait credential return',
    },
    {
      name: 'Generic Administrative Recon / Portal Scan',
      severity: 'LOW',
      certainty: '55% Behavioral Anomaly',
      trigger: "Requests targeting /admin, /wp-admin, /login, or unmapped catch-all routes",
      action: '+3.0 Threat Score penalty, baseline tarpit delay',
    },
  ];

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-bold tracking-tight text-ink-primary flex items-center gap-2">
          <Cpu className="w-5 h-5 text-brand-600" />
          Rule-Based Deterministic Detection Engine
        </h2>
        <p className="text-xs text-ink-muted mt-1">
          HoneyMap operates entirely on transparent, deterministic classification rules rather than
          opaque machine learning models. Confidence metrics reflect exact rule match guarantees.
        </p>
      </div>

      {/* Math & Formula Card */}
      <Card className="border-slate-200/80 bg-white rounded-2xl shadow-card">
        <CardHeader className="pb-3">
          <div className="flex items-center gap-2">
            <div className="p-1.5 rounded-lg bg-orange-50 text-warning-600 border border-orange-200">
              <Zap className="w-4 h-4" />
            </div>
            <div>
              <CardTitle>Score Decay & Velocity Formula</CardTitle>
              <p className="text-xs text-ink-muted">Continuous time-decay math balancing recent bursts vs idle attackers</p>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-3 text-xs">
          <p className="text-ink-secondary">
            Attacker threat scores decay exponentially over time to reflect active vs dormant threats:
          </p>
          <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 font-mono text-brand-700 font-bold text-xs">
            Score(t) = Score_raw × 0.5^( (t_now - t_last) / 300s )
          </div>
          <p className="text-xs text-ink-muted">
            With a half-life of 5 minutes (300s), an attacker idle for 10 minutes retains 25% of
            their peak threat score until re-engaging with honeypot trapdoors.
          </p>
        </CardContent>
      </Card>

      {/* Rules Matrix */}
      <Card className="border-slate-200/80 bg-white rounded-2xl shadow-card">
        <CardHeader className="pb-3">
          <CardTitle>Deterministic Classification Rules Matrix</CardTitle>
          <p className="text-xs text-ink-muted">Deterministic rule weights, heuristics, and engine response policies</p>
        </CardHeader>
        <CardContent className="p-5 space-y-3">
          {rules.map((r, idx) => (
            <div
              key={idx}
              className="p-4 rounded-xl bg-slate-50/70 border border-slate-200/70 space-y-1.5 hover:bg-white hover:border-slate-300 transition-colors"
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <ShieldCheck className="w-4 h-4 text-brand-600" />
                  <span className="font-semibold text-xs text-ink-primary">{r.name}</span>
                </div>
                <div className="flex items-center gap-2">
                  <Badge variant={r.severity.toLowerCase() as Severity} className="text-[10px]">
                    {r.severity}
                  </Badge>
                  <span className="text-[11px] font-mono font-bold text-brand-700">
                    {r.certainty}
                  </span>
                </div>
              </div>

              <div className="text-xs font-mono text-ink-secondary">
                <span className="text-ink-muted font-sans">Trigger Pattern: </span>
                {r.trigger}
              </div>

              <div className="text-xs text-ink-muted font-mono">
                <span className="text-ink-muted font-sans">Engine Action: </span>
                {r.action}
              </div>
            </div>
          ))}
        </CardContent>
      </Card>
    </div>
  );
}
