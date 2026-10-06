import React from 'react';
import { Card, CardHeader, CardTitle, CardContent } from './ui/card';
import { Badge } from './ui/badge';
import { Button } from './ui/button';
import { TelemetryEvent, Severity } from '../types';
import { Activity, ExternalLink, Globe, KeyRound } from 'lucide-react';
import { formatTimeAgo } from '@/lib/utils';

interface RecentActivityFeedProps {
  events: TelemetryEvent[];
  onInvestigateSession: (sessionId: string) => void;
  transport: string;
}

export default function RecentActivityFeed({
  events,
  onInvestigateSession,
  transport,
}: RecentActivityFeedProps) {
  return (
    <Card className="border-slate-200/80 bg-white rounded-2xl shadow-card">
      <CardHeader className="flex flex-row items-center justify-between pb-3">
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded-lg bg-brand-50 text-brand-600 border border-brand-200">
            <Activity className="w-4 h-4" />
          </div>
          <div>
            <CardTitle>Recent Intrusion Activity</CardTitle>
            <p className="text-xs text-ink-muted">Live classified telemetry stream ({transport.toUpperCase()})</p>
          </div>
        </div>
        <span className="text-xs font-mono text-ink-muted">
          {events.length} Intercepted
        </span>
      </CardHeader>
      <CardContent className="p-0">
        <div className="max-h-[380px] overflow-y-auto divide-y divide-slate-100 px-5">
          {events.length === 0 ? (
            <div className="py-12 text-center text-xs text-ink-muted">
              Awaiting live intrusion stream...
            </div>
          ) : (
            events.slice(0, 20).map((ev) => {
              const country = ev.geoip?.country || 'Unknown';
              const city = ev.geoip?.city || '';

              return (
                <div
                  key={ev.id}
                  onClick={() => ev.session_id && onInvestigateSession(ev.session_id)}
                  className="py-3 flex items-center justify-between gap-3 hover:bg-slate-50 hover:translate-x-1 active:scale-[0.99] -mx-5 px-5 transition-all duration-150 cursor-pointer group rounded-lg"
                >
                  <div className="flex items-start gap-3 min-w-0">
                    <Badge variant={(ev.severity || 'low') as Severity} className="mt-0.5 text-[10px] uppercase transition-transform duration-150 group-hover:scale-105 font-bold">
                      {ev.severity}
                    </Badge>

                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-xs font-semibold text-ink-primary group-hover:text-emerald-700 transition-colors">
                          {ev.source_ip || ev.ip}
                        </span>
                        <span className="text-[11px] text-slate-400 font-mono">
                          {ev.request_method || 'GET'} {ev.endpoint || ev.path}
                        </span>
                      </div>

                      <div className="text-xs text-ink-muted truncate mt-0.5 flex items-center gap-2">
                        {ev.flagged_token ? (
                          <span className="text-danger-600 font-bold flex items-center gap-1">
                            <KeyRound className="w-3 h-3 text-danger-600" />
                            Exfiltrated Token Reused: {ev.flagged_token}
                          </span>
                        ) : (
                          <span>{ev.reason || ev.attack_type || 'Decoy Scan'}</span>
                        )}
                        <span className="text-slate-300">·</span>
                        <span className="text-[11px] flex items-center gap-1 text-slate-500">
                          <Globe className="w-3 h-3 text-slate-400" />
                          {city ? `${city}, ${country}` : country}
                        </span>
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center gap-2 flex-shrink-0">
                    <span className="text-[11px] font-mono text-ink-muted">
                      {formatTimeAgo(ev.timestamp)}
                    </span>
                    {ev.session_id && (
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={(e) => {
                          e.stopPropagation();
                          onInvestigateSession(ev.session_id!);
                        }}
                        className="h-7 w-7 p-0 opacity-0 group-hover:opacity-100 transition-all duration-150 text-slate-400 hover:text-emerald-700 hover:bg-emerald-50 hover:scale-110 active:scale-90"
                      >
                        <ExternalLink className="w-3.5 h-3.5" />
                      </Button>
                    )}
                  </div>
                </div>
              );
            })
          )}
        </div>
      </CardContent>
    </Card>
  );
}
