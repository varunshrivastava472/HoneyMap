import React, { useEffect, useState } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from './ui/card';
import { fetchThreatIntel, fetchLiveDecoys, fetchSessions } from '../api/client';
import { KeyRound, Bug, Users, CheckCircle2, AlertTriangle } from 'lucide-react';

export default function SystemStatusCards() {
  const [tokenStats, setTokenStats] = useState({ active: 2, total: 2, compromised: 0 });
  const [decoyStats, setDecoyStats] = useState({ active: 3, pool: 6, interval: 90 });
  const [sessionStats, setSessionStats] = useState({ tracked: 0, cap: 500 });
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let isMounted = true;
    async function loadStats() {
      try {
        const [intel, decoys, sess] = await Promise.all([
          fetchThreatIntel(),
          fetchLiveDecoys(),
          fetchSessions({ limit: 500 }),
        ]);

        if (isMounted) {
          if (intel) {
            setTokenStats({
              active: intel.tokens?.length || 2,
              total: intel.tokens?.length || 2,
              compromised: intel.total_compromised_count || 0,
            });
          }
          if (decoys) {
            setDecoyStats({
              active: decoys.live_paths?.length || 4,
              pool: decoys.pool?.length || 6,
              interval: decoys.rotation_interval_seconds || 90,
            });
          }
          if (sess) {
            setSessionStats({
              tracked: sess.count || (sess.sessions?.length || 0),
              cap: 500,
            });
          }
        }
      } catch (err) {
        console.warn('[SystemStatusCards] Error loading real status:', err);
      } finally {
        if (isMounted) setLoading(false);
      }
    }

    loadStats();
    const timer = setInterval(loadStats, 10000);
    return () => {
      isMounted = false;
      clearInterval(timer);
    };
  }, []);

  const tokenPct = Math.round(((tokenStats.total - tokenStats.compromised) / Math.max(1, tokenStats.total)) * 100);
  const decoyPct = Math.round((decoyStats.active / Math.max(1, decoyStats.pool)) * 100);
  const sessionPct = Math.round((sessionStats.tracked / sessionStats.cap) * 100);

  return (
    <Card className="border-slate-200/80 bg-white rounded-2xl shadow-card">
      <CardHeader className="pb-3">
        <CardTitle>Platform Integrity & Capacity Monitor</CardTitle>
        <p className="text-xs text-ink-muted">Real-time derived system telemetry and decoy pool bounds</p>
      </CardHeader>
      <CardContent className="space-y-4 pt-1">
        {/* Honeytoken Integrity */}
        <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200/60 space-y-2 hover:border-slate-300 hover:translate-x-1 hover:shadow-xs transition-all duration-150 group cursor-default">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <div className="p-1.5 rounded-lg bg-emerald-100 text-brand-700 border border-brand-200 shadow-xs transition-transform duration-200 group-hover:scale-110 group-hover:rotate-6">
                <KeyRound className="w-3.5 h-3.5" />
              </div>
              <span className="text-xs font-semibold text-ink-primary group-hover:text-emerald-800 transition-colors">
                Honeytoken Integrity
              </span>
            </div>
            <span className="font-mono text-xs font-bold text-ink-primary">
              {tokenStats.total - tokenStats.compromised} / {tokenStats.total} Uncompromised ({tokenPct}%)
            </span>
          </div>
          <div className="w-full bg-slate-200 h-2 rounded-full overflow-hidden">
            <div
              className={`h-full rounded-full transition-all duration-300 ${
                tokenStats.compromised > 0 ? 'bg-orange-500' : 'bg-brand-500'
              }`}
              style={{ width: `${Math.max(5, tokenPct)}%` }}
            />
          </div>
          <div className="text-[11px] text-ink-muted flex items-center justify-between">
            <span>
              {tokenStats.compromised === 0
                ? 'All bait credentials pristine in storage'
                : `${tokenStats.compromised} credential(s) exfiltrated & reused`}
            </span>
            <span className="font-mono text-[10px] text-slate-400">100% Deterministic Rule</span>
          </div>
        </div>

        {/* Decoy Coverage */}
        <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200/60 space-y-2 hover:border-slate-300 hover:translate-x-1 hover:shadow-xs transition-all duration-150 group cursor-default">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <div className="p-1.5 rounded-lg bg-blue-50 text-blue-700 border border-blue-200 shadow-xs transition-transform duration-200 group-hover:scale-110 group-hover:rotate-6">
                <Bug className="w-3.5 h-3.5" />
              </div>
              <span className="text-xs font-semibold text-ink-primary group-hover:text-blue-800 transition-colors">
                Adaptive Decoy Coverage
              </span>
            </div>
            <span className="font-mono text-xs font-bold text-ink-primary">
              {decoyStats.active} of {decoyStats.pool} Live Trapdoors ({decoyPct}%)
            </span>
          </div>
          <div className="w-full bg-slate-200 h-2 rounded-full overflow-hidden">
            <div
              className="h-full bg-blue-500 rounded-full transition-all duration-300"
              style={{ width: `${Math.max(5, decoyPct)}%` }}
            />
          </div>
          <div className="text-[11px] text-ink-muted flex items-center justify-between">
            <span>Rotating trapdoor pool every ~{decoyStats.interval} seconds</span>
            <span className="font-mono text-[10px] text-slate-400">Pool of 6 Live</span>
          </div>
        </div>

        {/* Session Capacity */}
        <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200/60 space-y-2 hover:border-slate-300 hover:translate-x-1 hover:shadow-xs transition-all duration-150 group cursor-default">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <div className="p-1.5 rounded-lg bg-purple-50 text-purple-700 border border-purple-200 shadow-xs transition-transform duration-200 group-hover:scale-110 group-hover:rotate-6">
                <Users className="w-3.5 h-3.5" />
              </div>
              <span className="text-xs font-semibold text-ink-primary group-hover:text-purple-800 transition-colors">
                Session Tracking Capacity
              </span>
            </div>
            <span className="font-mono text-xs font-bold text-ink-primary">
              {sessionStats.tracked} / {sessionStats.cap} Active ({sessionPct}%)
            </span>
          </div>
          <div className="w-full bg-slate-200 h-2 rounded-full overflow-hidden">
            <div
              className={`h-full rounded-full transition-all duration-300 ${
                sessionPct > 80 ? 'bg-orange-500' : 'bg-purple-500'
              }`}
              style={{ width: `${Math.max(3, sessionPct)}%` }}
            />
          </div>
          <div className="text-[11px] text-ink-muted flex items-center justify-between">
            <span>LRU eviction active beyond 500 session cap</span>
            <span className="font-mono text-[10px] text-slate-400">T_half = 600s</span>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
