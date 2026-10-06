import React from 'react';
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
import { AttackTarget, Severity } from '../types';
import { Target, TrendingUp, TrendingDown, Minus } from 'lucide-react';
import { formatTimeAgo } from '@/lib/utils';

interface AttackTargetsTableProps {
  targets: AttackTarget[];
  isLoading?: boolean;
}

export default function AttackTargetsTable({
  targets,
  isLoading = false,
}: AttackTargetsTableProps) {
  return (
    <Card className="border-slate-200/80 bg-white rounded-2xl shadow-card">
      <CardHeader className="flex flex-row items-center justify-between pb-3">
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded-lg bg-orange-50 text-warning-600 border border-orange-200">
            <Target className="w-4 h-4" />
          </div>
          <div>
            <CardTitle>Decoy Target Frequency & Trap Hit Rates</CardTitle>
            <p className="text-xs text-ink-muted">Probe volume and period-over-period trend per decoy path</p>
          </div>
        </div>
        <span className="text-xs text-ink-muted font-mono">
          {targets.length} Active Targets
        </span>
      </CardHeader>
      <CardContent className="p-0">
        <div className="max-h-[320px] overflow-y-auto">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Target Decoy Path</TableHead>
                <TableHead className="text-center">Peak Severity</TableHead>
                <TableHead className="text-right">Total Hits</TableHead>
                <TableHead className="text-right">Incidents</TableHead>
                <TableHead className="text-right">1h Trend</TableHead>
                <TableHead className="text-right">Last Probe</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {isLoading ? (
                <TableRow>
                  <TableCell colSpan={6} className="text-center py-8 text-ink-muted">
                    Loading target frequencies...
                  </TableCell>
                </TableRow>
              ) : targets.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} className="text-center py-8 text-ink-muted">
                    No decoy probes logged yet.
                  </TableCell>
                </TableRow>
              ) : (
                targets.map((t, idx) => {
                  const trendPositive = t.trend > 0;
                  const trendNegative = t.trend < 0;

                  return (
                    <TableRow key={idx} className="hover:bg-slate-50 hover:translate-x-0.5 active:scale-[0.995] transition-all duration-150 cursor-pointer group">
                      <TableCell className="font-mono text-xs font-semibold text-ink-primary group-hover:text-emerald-700 transition-colors">
                        <span className="text-ink-primary group-hover:text-emerald-700">{t.target}</span>
                      </TableCell>
                      <TableCell className="text-center">
                        <Badge variant={(t.severity || 'low') as Severity} className="text-[10px] uppercase transition-transform duration-150 group-hover:scale-105 font-bold">
                          {t.severity}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-right font-mono text-xs text-ink-secondary font-medium">
                        {t.requests.toLocaleString()}
                      </TableCell>
                      <TableCell className="text-right font-mono text-xs font-semibold">
                        <span className={t.incidents > 0 ? 'text-danger-600' : 'text-slate-500'}>
                          {t.incidents}
                        </span>
                      </TableCell>
                      <TableCell className="text-right font-mono">
                        <div className="flex items-center justify-end gap-1 transition-transform duration-150 group-hover:scale-105">
                          {trendPositive ? (
                            <>
                              <TrendingUp className="w-3 h-3 text-danger-600" />
                              <span className="text-danger-600 text-[11px] font-semibold">+{t.trend}%</span>
                            </>
                          ) : trendNegative ? (
                            <>
                              <TrendingDown className="w-3 h-3 text-brand-600" />
                              <span className="text-brand-600 text-[11px] font-semibold">{t.trend}%</span>
                            </>
                          ) : (
                            <>
                              <Minus className="w-3 h-3 text-slate-400" />
                              <span className="text-slate-400 text-[11px]">0.0%</span>
                            </>
                          )}
                        </div>
                      </TableCell>
                      <TableCell className="text-right text-ink-muted font-mono text-[11px]">
                        {t.last_seen ? formatTimeAgo(t.last_seen) : 'never'}
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
