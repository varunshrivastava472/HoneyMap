import React from 'react';
import {
  ShieldAlert,
  ShieldBan,
  Activity,
  Zap,
  TrendingUp,
  TrendingDown,
} from 'lucide-react';
import { Card, CardContent } from './ui/card';
import { MetricsSummary } from '../types';

interface MetricsCardsProps {
  metrics: MetricsSummary | null;
  isLoading?: boolean;
}

export default function MetricsCards({ metrics, isLoading = false }: MetricsCardsProps) {
  const criticalThreats = metrics?.critical_threats ?? 0;
  const requestsBlocked = metrics?.requests_blocked ?? 0;
  const activeIncidents = metrics?.active_incidents ?? 0;
  const totalRequests = metrics?.total_requests ?? 0;

  const cards = [
    {
      title: 'Critical Threats',
      value: criticalThreats,
      icon: ShieldAlert,
      iconBg: 'bg-red-50 text-danger-600 border-red-200',
      badge: 'Breach Payoff',
      badgeClass: 'bg-red-50 text-red-700 border-red-200',
      statusText: criticalThreats > 0 ? 'Surge Active' : 'Nominal',
      statusAlert: criticalThreats > 0,
      subtext: `${metrics?.severity_breakdown?.critical ?? 0} Honeytoken Reuses`,
    },
    {
      title: 'Requests Intercepted / Blocked',
      value: requestsBlocked,
      icon: ShieldBan,
      iconBg: 'bg-orange-50 text-warning-600 border-orange-200',
      badge: 'Tarpit Active',
      badgeClass: 'bg-orange-50 text-orange-700 border-orange-200',
      statusText: requestsBlocked > 0 ? 'Intercepting' : 'Monitoring',
      statusAlert: requestsBlocked > 0,
      subtext: `${metrics?.severity_breakdown?.high ?? 0} High + ${criticalThreats} Critical`,
    },
    {
      title: 'Active High-Risk Incidents',
      value: activeIncidents,
      icon: Zap,
      iconBg: 'bg-amber-50 text-amber-600 border-amber-200',
      badge: 'Score ≥ 30.0',
      badgeClass: 'bg-amber-50 text-amber-800 border-amber-200',
      statusText: activeIncidents > 0 ? `${activeIncidents} Active` : 'Zero Threat',
      statusAlert: activeIncidents > 0,
      subtext: 'High-velocity threat sessions',
    },
    {
      title: 'Total Telemetry Logged',
      value: totalRequests,
      icon: Activity,
      iconBg: 'bg-emerald-50 text-brand-600 border-brand-200',
      badge: 'Live Events',
      badgeClass: 'bg-emerald-50 text-emerald-700 border-emerald-200',
      statusText: totalRequests > 0 ? 'Live Feed' : 'Awaiting',
      statusAlert: false,
      subtext: `${metrics?.severity_breakdown?.low ?? 0} Low · ${metrics?.severity_breakdown?.medium ?? 0} Med`,
    },
  ];

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
      {cards.map((card, idx) => {
        const Icon = card.icon;
        return (
          <Card
            key={idx}
            className="group border-slate-200/80 bg-white hover:border-slate-300/90 transition-all duration-200 shadow-card hover:shadow-xl hover:-translate-y-1.5 rounded-2xl cursor-default"
          >
            <CardContent className="p-5">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-ink-muted group-hover:text-slate-900 transition-colors">
                  {card.title}
                </span>
                <div className={`p-2 rounded-xl border transition-all duration-200 group-hover:scale-115 group-hover:rotate-6 ${card.iconBg}`}>
                  <Icon className="w-4 h-4" />
                </div>
              </div>

              <div className="mt-3 flex items-baseline gap-2">
                <span className="text-2xl font-bold font-mono text-ink-primary tracking-tight group-hover:scale-105 transition-transform origin-left">
                  {isLoading ? '...' : card.value.toLocaleString()}
                </span>
                <span
                  className={`text-[10px] px-1.5 py-0.5 rounded-md border font-medium transition-transform duration-150 group-hover:scale-105 ${card.badgeClass}`}
                >
                  {card.badge}
                </span>
              </div>

              <div className="mt-3 text-xs text-ink-muted flex items-center justify-between border-t border-slate-100 pt-2.5">
                <span className="truncate">{card.subtext}</span>
                <span
                  className={`flex items-center gap-1 font-mono text-[11px] font-semibold transition-transform duration-150 group-hover:translate-x-0.5 ${
                    card.statusAlert ? 'text-danger-600' : 'text-brand-600'
                  }`}
                >
                  <span className={`w-1.5 h-1.5 rounded-full ${card.statusAlert ? 'bg-danger-500 animate-pulse' : 'bg-brand-500'}`} />
                  {card.statusText}
                </span>
              </div>
            </CardContent>
          </Card>
        );
      })}
    </div>
  );
}
