import React, { useEffect, useState, useMemo, useCallback } from 'react';
import { fetchSessions } from '../api/client';
import { AttackerSession, Severity } from '../types';
import { Card, CardHeader, CardTitle, CardContent } from './ui/card';
import {
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell,
} from './ui/table';
import { Badge } from './ui/badge';
import { Flame, Globe, ExternalLink } from 'lucide-react';
import { formatTimeAgo } from '@/lib/utils';

interface LeaderboardProps {
  onInvestigateSession: (sessionId: string) => void;
  selectedSessionId?: string | null;
  searchQuery?: string;
}

function isSessionInactive(lastSeen?: string): boolean {
  if (!lastSeen) return false;
  try {
    const isoStr = lastSeen.includes('T') ? lastSeen : lastSeen.replace(' ', 'T');
    const then = new Date(isoStr.endsWith('Z') ? isoStr : isoStr + 'Z').getTime();
    if (isNaN(then)) return false;
    return Date.now() - then > 120000; // > 2 minutes
  } catch {
    return false;
  }
}

export default function Leaderboard({
  onInvestigateSession,
  selectedSessionId,
  searchQuery = '',
}: LeaderboardProps) {
  const [sessions, setSessions] = useState<AttackerSession[]>([]);
  const [loading, setLoading] = useState(true);

  const loadSessions = useCallback(async () => {
    try {
      const data = await fetchSessions({ limit: 50 });
      if (data?.sessions) {
        setSessions(data.sessions);
      }
    } catch (err) {
      console.warn('[Leaderboard] 5s polling error:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadSessions();
    const interval = setInterval(loadSessions, 5000);
    return () => clearInterval(interval);
  }, [loadSessions]);

  const sortedSessions = useMemo(() => {
    return [...sessions].sort((a, b) => {
      const scoreA = Number(a.decayed_score ?? a.score ?? 0);
      const scoreB = Number(b.decayed_score ?? b.score ?? 0);
      return scoreB - scoreA;
    });
  }, [sessions]);

  const displaySessions = useMemo(() => {
    if (!searchQuery.trim()) return sortedSessions;
    const q = searchQuery.toLowerCase().trim();
    return sortedSessions.filter(
      (s) =>
        s.source_ip?.toLowerCase().includes(q) ||
        s.session_id?.toLowerCase().includes(q) ||
        s.geoip?.country?.toLowerCase().includes(q) ||
        s.geoip?.city?.toLowerCase().includes(q) ||
        s.max_severity?.toLowerCase().includes(q) ||
        s.user_agent?.toLowerCase().includes(q)
    );
  }, [sortedSessions, searchQuery]);

  const maxScore = useMemo(() => {
    if (displaySessions.length === 0) return 10;
    const highest = Math.max(
      ...displaySessions.map((s) => Number(s.decayed_score ?? s.score ?? 10))
    );
    return highest > 0 ? highest : 10;
  }, [displaySessions]);

  return (
    <Card className="border-slate-200/80 bg-white rounded-2xl shadow-card">
      <CardHeader className="flex flex-row items-center justify-between pb-3">
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded-lg bg-orange-50 text-warning-600 border border-orange-200">
            <Flame className="w-4 h-4" />
          </div>
          <div>
            <CardTitle>Attacker Threat Leaderboard & Velocity</CardTitle>
            <p className="text-xs text-ink-muted">Exponential score decay (T_half = 600s) with real-time ranking</p>
          </div>
        </div>
        <span className="text-xs text-ink-muted font-mono">
          Auto-refreshing 5s · {displaySessions.length} Ranked
        </span>
      </CardHeader>
      <CardContent className="p-0">
        <div className="max-h-[320px] overflow-y-auto">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-12 text-center">Rank</TableHead>
                <TableHead>Attacker IP / Session</TableHead>
                <TableHead>Location</TableHead>
                <TableHead className="text-center">Peak Severity</TableHead>
                <TableHead className="text-right">Hits</TableHead>
                <TableHead>Velocity Score</TableHead>
                <TableHead className="text-right">Last Active</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {loading && sessions.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} className="text-center py-8 text-ink-muted">
                    Computing attacker threat scores...
                  </TableCell>
                </TableRow>
              ) : displaySessions.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} className="text-center py-8 text-ink-muted">
                    {searchQuery ? `No active sessions match "${searchQuery}".` : 'No active threat sessions registered.'}
                  </TableCell>
                </TableRow>
              ) : (
                displaySessions.map((s, idx) => {
                  const rank = idx + 1;
                  const score = Number(s.decayed_score ?? s.score ?? 0);
                  const pct = Math.min(100, Math.max(8, (score / maxScore) * 100));
                  const isInactive = isSessionInactive(s.last_seen);
                  const isSelected = selectedSessionId === s.session_id;

                  return (
                    <TableRow
                      key={s.session_id}
                      onClick={() => onInvestigateSession(s.session_id)}
                      className={`cursor-pointer transition-all duration-150 active:scale-[0.995] group ${
                        isSelected
                          ? 'bg-emerald-50/80 border-l-4 border-l-emerald-600 translate-x-1'
                          : 'hover:bg-slate-50 hover:translate-x-1'
                      } ${isInactive ? 'opacity-40 hover:opacity-80' : ''}`}
                    >
                      <TableCell className="text-center font-mono font-bold text-xs text-slate-400 group-hover:scale-110 transition-transform">
                        {rank === 1 ? '🥇' : rank === 2 ? '🥈' : rank === 3 ? '🥉' : `#${rank}`}
                      </TableCell>

                      <TableCell>
                        <div className="font-mono text-xs font-semibold text-ink-primary group-hover:text-emerald-700 transition-colors">
                          {s.source_ip}
                        </div>
                        <div className="text-[10px] text-ink-muted font-mono">
                          ID: {s.session_id.slice(0, 10)}...
                        </div>
                      </TableCell>

                      <TableCell className="text-xs text-ink-secondary">
                        <div className="flex items-center gap-1 max-w-[130px] truncate" title={s.geoip?.country || 'Unknown'}>
                          <Globe className="w-3 h-3 text-slate-400 flex-shrink-0 group-hover:text-emerald-600 transition-colors" />
                          <span className="truncate">{s.geoip?.country || 'Unknown'}</span>
                        </div>
                      </TableCell>

                      <TableCell className="text-center">
                        <Badge
                          variant={(s.max_severity || 'low') as Severity}
                          className="text-[10px] uppercase transition-transform duration-150 group-hover:scale-105 font-bold"
                        >
                          {s.max_severity}
                        </Badge>
                      </TableCell>

                      <TableCell className="text-right font-mono text-ink-secondary text-xs font-semibold">
                        {s.request_count || s.event_count || 1}
                      </TableCell>

                      <TableCell className="min-w-[140px]">
                        <div className="flex items-center gap-2">
                          <div className="flex-1 bg-slate-100 rounded-full h-2 overflow-hidden border border-slate-200">
                            <div
                              className={`h-full rounded-full transition-all duration-300 ${
                                s.max_severity === 'critical'
                                  ? 'bg-danger-600'
                                  : s.max_severity === 'high'
                                  ? 'bg-warning-500'
                                  : s.max_severity === 'medium'
                                  ? 'bg-amber-500'
                                  : 'bg-brand-500'
                              }`}
                              style={{ width: `${pct}%` }}
                            />
                          </div>
                          <span className="font-mono text-xs font-bold text-ink-primary w-12 text-right">
                            {score.toFixed(1)}
                          </span>
                        </div>
                      </TableCell>

                      <TableCell className="text-right text-ink-muted font-mono text-[11px] whitespace-nowrap">
                        <div className="flex items-center justify-end gap-1.5">
                          <span>{formatTimeAgo(s.last_seen)}</span>
                          <ExternalLink className="w-3.5 h-3.5 text-slate-400 group-hover:text-emerald-600 group-hover:scale-115 transition-all duration-150" />
                        </div>
                      </TableCell>
                    </TableRow>
                  );
                })
              )}
            </TableBody>
          </Table>
        </div>
      </CardContent>
    </Card>
  );
}
