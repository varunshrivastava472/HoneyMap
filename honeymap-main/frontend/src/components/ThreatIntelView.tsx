import React, { useEffect, useState } from 'react';
import { fetchThreatIntel } from '../api/client';
import { ThreatIntelData } from '../types';
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
import { KeyRound, ShieldAlert, CheckCircle2, AlertOctagon } from 'lucide-react';
import { formatTimeAgo } from '@/lib/utils';

export default function ThreatIntelView() {
  const [intel, setIntel] = useState<ThreatIntelData | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let isMounted = true;
    async function load() {
      try {
        const data = await fetchThreatIntel();
        if (isMounted) setIntel(data);
      } catch (err) {
        console.error('[ThreatIntelView] Error:', err);
      } finally {
        if (isMounted) setLoading(false);
      }
    }
    load();
    const timer = setInterval(load, 10000);
    return () => {
      isMounted = false;
      clearInterval(timer);
    };
  }, []);

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-bold tracking-tight text-ink-primary flex items-center gap-2">
          <KeyRound className="w-5 h-5 text-brand-600" />
          Threat Intelligence: Honeytoken Trap Inventory
        </h2>
        <p className="text-xs text-ink-muted mt-1">
          Dynamic bait credentials injected into adaptive decoy files on server startup. Any exact
          reuse triggers an immediate deterministic CRITICAL alert.
        </p>
      </div>

      {/* Active Tokens Summary */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
        <Card className="border-slate-200/80 bg-white rounded-2xl shadow-card">
          <CardContent className="p-5 flex items-center justify-between">
            <div>
              <div className="text-xs text-ink-muted uppercase font-semibold">
                Active Bait Tokens
              </div>
              <div className="text-2xl font-bold font-mono text-brand-600 mt-1">
                {intel?.tokens?.length || 0}
              </div>
            </div>
            <div className="p-2.5 rounded-xl bg-brand-50 text-brand-600 border border-brand-200">
              <KeyRound className="w-5 h-5" />
            </div>
          </CardContent>
        </Card>

        <Card className="border-slate-200/80 bg-white rounded-2xl shadow-card">
          <CardContent className="p-5 flex items-center justify-between">
            <div>
              <div className="text-xs text-ink-muted uppercase font-semibold">
                Compromised Triggers
              </div>
              <div className="text-2xl font-bold font-mono text-danger-600 mt-1">
                {intel?.total_compromised_count || 0}
              </div>
            </div>
            <div className="p-2.5 rounded-xl bg-red-50 text-danger-600 border border-red-200">
              <ShieldAlert className="w-5 h-5" />
            </div>
          </CardContent>
        </Card>

        <Card className="border-slate-200/80 bg-white rounded-2xl shadow-card">
          <CardContent className="p-5 flex items-center justify-between">
            <div>
              <div className="text-xs text-ink-muted uppercase font-semibold">
                Match Strategy
              </div>
              <div className="text-xs font-bold font-mono text-emerald-700 mt-1">
                Exact Substring (100% Deterministic)
              </div>
            </div>
            <div className="p-2.5 rounded-xl bg-emerald-50 text-brand-600 border border-brand-200">
              <CheckCircle2 className="w-5 h-5" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Active Honeytokens Table */}
      <Card className="border-slate-200/80 bg-white rounded-2xl shadow-card">
        <CardHeader className="pb-3">
          <CardTitle>Active Honeytoken Credentials (Live In-Memory & SQLite)</CardTitle>
          <p className="text-xs text-ink-muted">Bait strings currently active in decoy payloads</p>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Type</TableHead>
                <TableHead>Bait Credential Value</TableHead>
                <TableHead>Description</TableHead>
                <TableHead className="text-center">Status</TableHead>
                <TableHead className="text-right">Trigger Count</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {loading && !intel ? (
                <TableRow>
                  <TableCell colSpan={5} className="text-center py-8 text-ink-muted">
                    Loading honeytoken inventory...
                  </TableCell>
                </TableRow>
              ) : intel?.tokens?.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={5} className="text-center py-8 text-ink-muted">
                    No honeytokens currently active.
                  </TableCell>
                </TableRow>
              ) : (
                intel?.tokens?.map((t) => (
                  <TableRow key={t.token_id}>
                    <TableCell className="font-mono text-xs text-brand-700 font-semibold uppercase">
                      {t.token_type}
                    </TableCell>
                    <TableCell className="font-mono text-xs text-ink-primary font-bold max-w-xs truncate">
                      {t.token_value}
                    </TableCell>
                    <TableCell className="text-xs text-ink-muted max-w-sm">
                      {t.description || 'Dynamic bait credential'}
                    </TableCell>
                    <TableCell className="text-center">
                      <Badge variant="live" className="text-[10px]">
                        ACTIVE
                      </Badge>
                    </TableCell>
                    <TableCell className="text-right font-mono text-xs font-bold text-ink-primary">
                      {t.trigger_count}
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {/* Compromised History Table */}
      <Card className="border-slate-200/80 bg-white rounded-2xl shadow-card">
        <CardHeader className="pb-3">
          <div className="flex items-center gap-2">
            <div className="p-1.5 rounded-lg bg-red-50 text-danger-600 border border-red-200">
              <AlertOctagon className="w-4 h-4" />
            </div>
            <div>
              <CardTitle>Honeytoken Compromise & Reuse History</CardTitle>
              <p className="text-xs text-ink-muted">Chronological audit of bait credentials reused by attackers</p>
            </div>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Time</TableHead>
                <TableHead>Attacker IP</TableHead>
                <TableHead>Target Endpoint</TableHead>
                <TableHead>Triggered Token</TableHead>
                <TableHead>Severity</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {intel?.compromised_events?.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={5} className="text-center py-8 text-ink-muted">
                    No honeytokens have been reused by attackers yet.
                  </TableCell>
                </TableRow>
              ) : (
                intel?.compromised_events?.map((e) => (
                  <TableRow key={e.id}>
                    <TableCell className="text-ink-muted font-mono text-[11px]">
                      {formatTimeAgo(e.timestamp)}
                    </TableCell>
                    <TableCell className="font-mono text-xs font-semibold text-ink-primary">
                      {e.source_ip || e.ip}
                    </TableCell>
                    <TableCell className="font-mono text-xs text-brand-700">
                      {e.endpoint || e.path}
                    </TableCell>
                    <TableCell className="font-mono text-xs text-danger-600 font-bold">
                      {e.flagged_token}
                    </TableCell>
                    <TableCell>
                      <Badge variant="critical" className="text-[10px] uppercase">
                        CRITICAL
                      </Badge>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}
