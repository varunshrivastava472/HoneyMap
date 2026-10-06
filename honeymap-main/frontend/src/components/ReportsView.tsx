import React, { useEffect, useState } from 'react';
import { fetchSessions, downloadReportJson } from '../api/client';
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
import { Button } from './ui/button';
import { FileText, Download, Globe, Check } from 'lucide-react';
import { formatTimeAgo } from '@/lib/utils';

export default function ReportsView({
  onInvestigateSession,
}: {
  onInvestigateSession: (sessionId: string) => void;
}) {
  const [sessions, setSessions] = useState<AttackerSession[]>([]);
  const [loading, setLoading] = useState(true);
  const [downloadingId, setDownloadingId] = useState<string | null>(null);

  useEffect(() => {
    let isMounted = true;
    async function load() {
      try {
        const res = await fetchSessions({ limit: 50 });
        if (isMounted && res?.sessions) {
          setSessions(res.sessions);
        }
      } catch (err) {
        console.error('[ReportsView] Error:', err);
      } finally {
        if (isMounted) setLoading(false);
      }
    }
    load();
    return () => {
      isMounted = false;
    };
  }, []);

  const handleDownload = async (sessionId: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setDownloadingId(sessionId);
    try {
      await downloadReportJson(sessionId);
    } catch (err) {
      console.error('[ReportsView] Download error:', err);
    } finally {
      setTimeout(() => setDownloadingId(null), 1000);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-bold tracking-tight text-ink-primary flex items-center gap-2">
          <FileText className="w-5 h-5 text-brand-600" />
          Incident Forensics Reports Archive
        </h2>
        <p className="text-xs text-ink-muted mt-1">
          Export structured JSON reports for any attacker session containing MITRE tactics, targeted
          endpoints, indicators of compromise, and chronological event timelines.
        </p>
      </div>

      <Card className="border-slate-200/80 bg-white rounded-2xl shadow-card">
        <CardHeader className="pb-3">
          <CardTitle>Session Forensics Export Archive</CardTitle>
          <p className="text-xs text-ink-muted">Historical session audit logs with one-click forensic JSON export</p>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Report ID / Session</TableHead>
                <TableHead>Attacker IP</TableHead>
                <TableHead>Location</TableHead>
                <TableHead className="text-center">Max Severity</TableHead>
                <TableHead className="text-right">Threat Score</TableHead>
                <TableHead className="text-right">Probes</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {loading ? (
                <TableRow>
                  <TableCell colSpan={7} className="text-center py-8 text-ink-muted">
                    Loading session archive...
                  </TableCell>
                </TableRow>
              ) : sessions.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} className="text-center py-8 text-ink-muted">
                    No incident sessions available for export.
                  </TableCell>
                </TableRow>
              ) : (
                sessions.map((s) => (
                  <TableRow
                    key={s.session_id}
                    onClick={() => onInvestigateSession(s.session_id)}
                    className="cursor-pointer hover:bg-slate-50/80 transition-colors"
                  >
                    <TableCell className="font-mono text-xs text-ink-primary font-semibold">
                      REP-{s.session_id.slice(0, 8).toUpperCase()}
                    </TableCell>
                    <TableCell className="font-mono text-xs text-ink-secondary">
                      {s.source_ip}
                    </TableCell>
                    <TableCell className="text-xs text-ink-muted">
                      <div className="flex items-center gap-1">
                        <Globe className="w-3 h-3 text-slate-400" />
                        <span>{s.geoip?.country || 'Unknown'}</span>
                      </div>
                    </TableCell>
                    <TableCell className="text-center">
                      <Badge variant={(s.max_severity || 'low') as Severity} className="text-[10px] uppercase">
                        {s.max_severity}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-right font-mono text-xs font-bold text-orange-600">
                      {Number(s.decayed_score ?? s.score ?? 0).toFixed(1)}
                    </TableCell>
                    <TableCell className="text-right font-mono text-xs text-ink-secondary">
                      {s.request_count || s.event_count || 1}
                    </TableCell>
                    <TableCell className="text-right">
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={(e) => handleDownload(s.session_id, e)}
                        disabled={downloadingId === s.session_id}
                        className="h-8 text-xs bg-white hover:bg-slate-50 border-slate-200 shadow-sm"
                      >
                        {downloadingId === s.session_id ? (
                          <Check className="w-3 h-3 mr-1 text-brand-600" />
                        ) : (
                          <Download className="w-3 h-3 mr-1 text-brand-600" />
                        )}
                        <span>{downloadingId === s.session_id ? 'Downloaded' : 'Export JSON'}</span>
                      </Button>
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
