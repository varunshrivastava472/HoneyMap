import React, { useEffect, useState } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from './ui/card';
import { Badge } from './ui/badge';
import { Clock, RefreshCw, AlertCircle, ShieldAlert, KeyRound } from 'lucide-react';
import { fetchLiveDecoys, fetchThreatIntel, fetchSessions } from '../api/client';

export default function SystemActionsMonitor() {
  const [secondsUntilRotation, setSecondsUntilRotation] = useState(90);
  const [compromisedCount, setCompromisedCount] = useState(0);
  const [sessionCapacityRatio, setSessionCapacityRatio] = useState(0);

  useEffect(() => {
    let isMounted = true;
    async function loadData() {
      try {
        const [intel, sess] = await Promise.all([
          fetchThreatIntel(),
          fetchSessions({ limit: 500 }),
        ]);

        if (isMounted) {
          if (intel) setCompromisedCount(intel.total_compromised_count || 0);
          if (sess) {
            const count = sess.count || (sess.sessions?.length || 0);
            setSessionCapacityRatio(Math.round((count / 500) * 100));
          }
        }
      } catch (err) {
        console.warn('[SystemActionsMonitor] Error loading action monitors:', err);
      }
    }

    loadData();
    const interval = setInterval(loadData, 15000);
    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, []);

  // Visual countdown timer for adaptive decoy rotation cycle (~90s)
  useEffect(() => {
    const timer = setInterval(() => {
      setSecondsUntilRotation((prev) => (prev <= 1 ? 90 : prev - 1));
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  const systemItems = [
    {
      title: 'Adaptive Decoy Pool Rotation',
      desc: 'Next automatic sensitive-file trap path shuffle from pool of 6',
      status: `In ~${secondsUntilRotation}s`,
      badge: 'Autonomous',
      badgeClass: 'bg-emerald-50 text-emerald-700 border-emerald-200',
      icon: RefreshCw,
      iconColor: 'text-brand-600',
    },
    {
      title: 'Active Session LRU Eviction Threshold',
      desc: `Session memory utilization currently at ${sessionCapacityRatio}% of 500 capacity`,
      status: sessionCapacityRatio > 80 ? 'Threshold Nearing' : 'Nominal',
      badge: 'Active Cap',
      badgeClass: sessionCapacityRatio > 80 ? 'bg-orange-50 text-orange-700 border-orange-200' : 'bg-slate-100 text-slate-700 border-slate-200',
      icon: AlertCircle,
      iconColor: sessionCapacityRatio > 80 ? 'text-warning-600' : 'text-slate-500',
    },
    {
      title: 'Dynamic Honeytoken Exfiltration Watch',
      desc: compromisedCount > 0 ? `${compromisedCount} token reuses intercepted by deterministic rules` : 'Zero exfiltrated bait tokens observed in traffic',
      status: compromisedCount > 0 ? 'Threat Detected' : 'Guarded',
      badge: 'Deterministic',
      badgeClass: compromisedCount > 0 ? 'bg-red-50 text-red-700 border-red-200' : 'bg-brand-50 text-brand-700 border-brand-200',
      icon: compromisedCount > 0 ? ShieldAlert : KeyRound,
      iconColor: compromisedCount > 0 ? 'text-danger-600' : 'text-brand-600',
    },
  ];

  return (
    <Card className="border-slate-200/80 bg-white rounded-2xl shadow-card">
      <CardHeader className="pb-3">
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded-lg bg-orange-50 text-warning-600 border border-orange-200">
            <Clock className="w-4 h-4" />
          </div>
          <div>
            <CardTitle>System Triggers & Automated Trap Controls</CardTitle>
            <p className="text-xs text-ink-muted">Active rotation schedules and backend safeguard monitors</p>
          </div>
        </div>
      </CardHeader>
      <CardContent className="space-y-3 pt-1">
        {systemItems.map((item, idx) => {
          const Icon = item.icon;
          return (
            <div
              key={idx}
              className="p-3.5 rounded-xl bg-slate-50/70 border border-slate-200/60 flex items-center justify-between gap-3 hover:border-slate-300 hover:bg-slate-50 hover:translate-x-1 hover:shadow-xs transition-all duration-150 group cursor-default"
            >
              <div className="flex items-start gap-3 min-w-0">
                <div className="p-2 rounded-lg bg-white border border-slate-200 mt-0.5 shadow-xs transition-transform duration-200 group-hover:scale-110 group-hover:rotate-6">
                  <Icon className={`w-4 h-4 ${item.iconColor}`} />
                </div>
                <div className="min-w-0">
                  <div className="text-xs font-semibold text-ink-primary group-hover:text-emerald-800 transition-colors">
                    {item.title}
                  </div>
                  <div className="text-xs text-ink-muted truncate mt-0.5">
                    {item.desc}
                  </div>
                </div>
              </div>

              <div className="flex flex-col items-end gap-1 flex-shrink-0">
                <Badge variant="outline" className={`text-[10px] font-medium transition-transform duration-150 group-hover:scale-105 ${item.badgeClass}`}>
                  {item.badge}
                </Badge>
                <span className="text-[11px] font-mono font-semibold text-ink-secondary">
                  {item.status}
                </span>
              </div>
            </div>
          );
        })}
      </CardContent>
    </Card>
  );
}
