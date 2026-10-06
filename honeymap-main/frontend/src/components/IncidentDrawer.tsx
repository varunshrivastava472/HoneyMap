import React, { useEffect, useState } from 'react';
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetDescription,
} from './ui/sheet';
import { Badge } from './ui/badge';
import { Button } from './ui/button';
import {
  fetchSessionTimeline,
  downloadReportJson,
  blockIpStub,
} from '../api/client';
import {
  SessionTimelineResponse,
  Severity,
} from '../types';
import {
  ShieldAlert,
  Globe,
  Download,
  ShieldBan,
  Clock,
  KeyRound,
  Check,
} from 'lucide-react';
import { formatTimeAgo } from '@/lib/utils';

interface IncidentDrawerProps {
  sessionId: string | null;
  isOpen: boolean;
  onClose: () => void;
}

export default function IncidentDrawer({
  sessionId,
  isOpen,
  onClose,
}: IncidentDrawerProps) {
  const [data, setData] = useState<SessionTimelineResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [downloading, setDownloading] = useState(false);
  const [blockStatus, setBlockStatus] = useState<string | null>(null);

  useEffect(() => {
    if (!sessionId || !isOpen) return;

    let isMounted = true;
    async function loadTimeline() {
      setLoading(true);
      try {
        const res = await fetchSessionTimeline(sessionId!);
        if (isMounted) {
          setData(res);
        }
      } catch (err) {
        console.error('[IncidentDrawer] Error loading timeline:', err);
      } finally {
        if (isMounted) setLoading(false);
      }
    }

    loadTimeline();
    return () => {
      isMounted = false;
    };
  }, [sessionId, isOpen]);

  const handleDownload = async () => {
    if (!sessionId) return;
    setDownloading(true);
    try {
      await downloadReportJson(sessionId);
    } catch (err) {
      console.error('[IncidentDrawer] Error downloading report:', err);
    } finally {
      setDownloading(false);
    }
  };

  const handleBlock = () => {
    const ip = data?.session?.source_ip;
    if (ip) {
      const res = blockIpStub(ip);
      setBlockStatus(res.message);
      setTimeout(() => setBlockStatus(null), 3500);
    }
  };

  const session = data?.session;
  const geoip = data?.geoip || session?.geoip;
  const events = data?.events || [];
  const maxSeverity = (session?.max_severity || 'low') as Severity;

  return (
    <Sheet open={isOpen} onOpenChange={(open) => !open && onClose()}>
      <SheetContent side="right" className="w-full sm:max-w-xl md:max-w-2xl bg-white border-slate-200">
        <SheetHeader className="border-b border-slate-100 pb-4">
          <div className="flex items-center justify-between pr-6">
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-5 h-5 text-danger-600" />
              <SheetTitle>Session Forensics & Incident Investigation</SheetTitle>
            </div>
            {session && (
              <Badge variant={maxSeverity} className="text-xs uppercase">
                {maxSeverity} Threat
              </Badge>
            )}
          </div>
          <SheetDescription className="font-mono text-xs text-ink-muted">
            Session ID: {sessionId}
          </SheetDescription>
        </SheetHeader>

        {loading ? (
          <div className="py-20 flex flex-col items-center justify-center text-xs text-ink-muted">
            <span>Retrieving chronological session telemetry...</span>
          </div>
        ) : !data ? (
          <div className="py-20 text-center text-xs text-ink-muted">
            No forensics data available for this session.
          </div>
        ) : (
          <div className="py-4 space-y-5">
            {/* Attacker Profile Header Card */}
            <div className="p-4 rounded-xl bg-slate-50 border border-slate-200/80 space-y-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div>
                  <div className="text-[10px] uppercase font-semibold text-ink-muted">
                    Source IP & Origin
                  </div>
                  <div className="text-base font-bold font-mono text-ink-primary flex items-center gap-2">
                    <span>{session?.source_ip}</span>
                    {geoip && (
                      <span className="text-xs font-normal text-ink-muted flex items-center gap-1">
                        <Globe className="w-3 h-3 text-slate-400" />
                        {geoip.city ? `${geoip.city}, ` : ''}{geoip.country} ({geoip.country_code})
                      </span>
                    )}
                  </div>
                </div>

                <div className="text-right">
                  <div className="text-[10px] uppercase font-semibold text-ink-muted">
                    Threat Velocity Score
                  </div>
                  <div className="text-lg font-bold font-mono text-orange-600">
                    {Number(session?.decayed_score ?? session?.score ?? 0).toFixed(1)}
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-3 gap-2 pt-2 border-t border-slate-200/60 text-xs">
                <div>
                  <span className="text-ink-muted text-[10px] block">Total Probes</span>
                  <span className="font-mono font-semibold text-ink-primary">
                    {events.length} Requests
                  </span>
                </div>
                <div>
                  <span className="text-ink-muted text-[10px] block">First Intercept</span>
                  <span className="font-mono text-ink-secondary text-[11px]">
                    {session?.first_seen ? formatTimeAgo(session.first_seen) : 'unknown'}
                  </span>
                </div>
                <div>
                  <span className="text-ink-muted text-[10px] block">Last Active</span>
                  <span className="font-mono text-ink-secondary text-[11px]">
                    {session?.last_seen ? formatTimeAgo(session.last_seen) : 'unknown'}
                  </span>
                </div>
              </div>

              {session?.user_agent && (
                <div className="text-[11px] font-mono text-ink-muted truncate bg-white p-2 rounded-lg border border-slate-200/60">
                  <span className="text-slate-500 font-sans">User-Agent: </span>
                  {session.user_agent}
                </div>
              )}
            </div>

            {/* Quick Action Buttons */}
            <div className="flex items-center gap-3">
              <Button
                variant="default"
                size="sm"
                onClick={handleDownload}
                disabled={downloading}
                className="flex-1 text-xs hover:scale-102 active:scale-96 transition-all duration-150 shadow-sm hover:shadow-md"
              >
                <Download className="w-3.5 h-3.5 mr-1.5" />
                {downloading ? 'Exporting...' : 'Download Forensics JSON'}
              </Button>

              <Button
                variant="outline"
                size="sm"
                onClick={handleBlock}
                className="flex-1 border-red-200 hover:bg-red-50 text-danger-600 text-xs hover:scale-102 active:scale-96 transition-all duration-150"
              >
                <ShieldBan className="w-3.5 h-3.5 mr-1.5 text-danger-600" />
                Block IP (Stub)
              </Button>
            </div>

            {blockStatus && (
              <div className="p-2.5 rounded-lg bg-emerald-50 border border-emerald-200 text-xs text-brand-700 flex items-center gap-1.5 animate-fade-in">
                <Check className="w-3.5 h-3.5 text-brand-600" />
                <span>{blockStatus}</span>
              </div>
            )}

            {/* Chronological Event Progression Timeline */}
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <div className="text-xs font-semibold uppercase tracking-wider text-ink-muted flex items-center gap-1.5">
                  <Clock className="w-3.5 h-3.5 text-brand-600" />
                  <span>Attack Execution Sequence ({events.length} Events)</span>
                </div>
              </div>

              <div className="space-y-2 max-h-96 overflow-y-auto pr-1">
                {events.map((ev, idx) => (
                  <div
                    key={ev.id || idx}
                    className="p-3.5 rounded-xl bg-slate-50/80 border border-slate-200/70 space-y-1.5 hover:bg-white hover:border-slate-300 hover:translate-x-1 hover:shadow-xs transition-all duration-150 group"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-[10px] text-slate-400">#{idx + 1}</span>
                        <Badge variant={(ev.severity || 'low') as Severity} className="text-[10px] uppercase transition-transform duration-150 group-hover:scale-105 font-bold">
                          {ev.severity}
                        </Badge>
                        <span className="font-mono text-xs font-bold text-ink-primary group-hover:text-emerald-700 transition-colors">
                          {ev.request_method || 'GET'} {ev.endpoint}
                        </span>
                      </div>
                      <span className="text-[10px] text-ink-muted font-mono">
                        {formatTimeAgo(ev.timestamp)}
                      </span>
                    </div>

                    <div className="text-xs text-ink-secondary font-mono">
                      <span className="text-ink-muted">Tactic: </span>
                      {ev.attack_type || ev.reason || 'Decoy Probe'}
                    </div>

                    {ev.flagged_token && (
                      <div className="p-2.5 rounded-lg bg-red-50 border border-red-200 text-xs text-red-800 font-mono flex items-center gap-2 animate-pulse-subtle">
                        <KeyRound className="w-4 h-4 text-danger-600 flex-shrink-0" />
                        <div>
                          <div className="font-bold uppercase text-[10px] text-danger-600">
                            CRITICAL PAYOFF TRIGGERED
                          </div>
                          <div>Exfiltrated Honeytoken Reused: {ev.flagged_token}</div>
                        </div>
                      </div>
                    )}

                    {ev.payload && (
                      <div className="p-2 rounded-lg bg-white text-[11px] font-mono text-ink-secondary break-all max-h-16 overflow-y-auto border border-slate-200/60">
                        <span className="text-ink-muted text-[10px] block">Payload:</span>
                        {ev.payload}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </SheetContent>
    </Sheet>
  );
}
