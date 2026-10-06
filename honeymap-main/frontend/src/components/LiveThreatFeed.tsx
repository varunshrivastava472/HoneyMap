import React, { useState } from 'react';
import {
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell,
} from './ui/table';
import { Card, CardHeader, CardTitle, CardContent } from './ui/card';
import { Badge } from './ui/badge';
import { Button } from './ui/button';
import { TelemetryEvent } from '../types';
import { Activity, ExternalLink, ShieldBan, Globe, Check } from 'lucide-react';
import { formatTimeAgo } from '@/lib/utils';
import { blockIpStub } from '../api/client';

interface LiveThreatFeedProps {
  events: TelemetryEvent[];
  onInvestigateSession: (sessionId: string) => void;
  transport: string;
}

export default function LiveThreatFeed({
  events,
  onInvestigateSession,
  transport,
}: LiveThreatFeedProps) {
  const [blockedNotice, setBlockedNotice] = useState<string | null>(null);

  const handleBlock = (ip: string, e: React.MouseEvent) => {
    e.stopPropagation();
    const res = blockIpStub(ip);
    setBlockedNotice(res.message);
    setTimeout(() => setBlockedNotice(null), 3000);
  };

  return (
    <Card className="border-border bg-surface-200">
      <CardHeader className="flex flex-row items-center justify-between pb-2">
        <div className="flex items-center gap-2">
          <Activity className="w-4 h-4 text-emerald-400" />
          <CardTitle>Live Intrusion & Honeytoken Stream</CardTitle>
        </div>
        <div className="flex items-center gap-2">
          {blockedNotice && (
            <span className="text-[11px] text-emerald-400 flex items-center gap-1 font-mono animate-fade-in">
              <Check className="w-3 h-3" />
              {blockedNotice}
            </span>
          )}
          <span className="text-[11px] text-slate-400 font-mono">
            {events.length} Events In Memory ({transport.toUpperCase()})
          </span>
        </div>
      </CardHeader>
      <CardContent className="p-0">
        <div className="max-h-80 overflow-y-auto">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Time</TableHead>
                <TableHead>Severity</TableHead>
                <TableHead>Threat & Reason</TableHead>
                <TableHead>Attacker IP</TableHead>
                <TableHead>Location</TableHead>
                <TableHead>Targeted Decoy</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {events.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} className="text-center py-8 text-slate-400">
                    Awaiting live intrusions...
                  </TableCell>
                </TableRow>
              ) : (
                events.slice(0, 50).map((ev) => {
                  const country = ev.geoip?.country || 'Unknown';
                  const city = ev.geoip?.city || '';

                  return (
                    <TableRow
                      key={ev.id}
                      onClick={() => ev.session_id && onInvestigateSession(ev.session_id)}
                      className="cursor-pointer hover:bg-surface-100/70 transition-colors"
                    >
                      <TableCell className="text-slate-400 font-mono text-[11px] whitespace-nowrap">
                        {formatTimeAgo(ev.timestamp)}
                      </TableCell>
                      <TableCell>
                        <Badge variant={ev.severity || 'low'} className="text-[10px] uppercase">
                          {ev.severity}
                        </Badge>
                      </TableCell>
                      <TableCell className="font-mono text-xs text-slate-200 max-w-[200px] truncate" title={ev.reason || ev.attack_type}>
                        {ev.flagged_token ? (
                          <span className="text-red-400 font-bold flex items-center gap-1">
                            ⚠️ Honeytoken Reuse
                          </span>
                        ) : (
                          ev.reason || ev.attack_type || 'Decoy Scan'
                        )}
                      </TableCell>
                      <TableCell className="font-mono text-slate-300 font-medium">
                        {ev.source_ip || ev.ip}
                      </TableCell>
                      <TableCell className="text-slate-400 text-xs">
                        <div className="flex items-center gap-1 truncate max-w-[130px]" title={`${city}, ${country}`}>
                          <Globe className="w-3 h-3 text-slate-400 flex-shrink-0" />
                          <span className="truncate">{city ? `${city}, ${country}` : country}</span>
                        </div>
                      </TableCell>
                      <TableCell className="font-mono text-orange-300 text-xs truncate max-w-[150px]">
                        {ev.endpoint || ev.path}
                      </TableCell>
                      <TableCell className="text-right whitespace-nowrap">
                        <div className="flex items-center justify-end gap-1.5" onClick={(e) => e.stopPropagation()}>
                          {ev.session_id && (
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => onInvestigateSession(ev.session_id!)}
                              className="h-6 px-2 text-[10px] text-blue-400 hover:text-blue-300 hover:bg-surface-100"
                            >
                              <ExternalLink className="w-3 h-3 mr-1" />
                              Inspect
                            </Button>
                          )}
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={(e) => handleBlock(ev.source_ip || ev.ip || '', e)}
                            className="h-6 px-2 text-[10px] text-red-400 hover:text-red-300 hover:bg-surface-100"
                          >
                            <ShieldBan className="w-3 h-3 mr-1" />
                            Block
                          </Button>
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
