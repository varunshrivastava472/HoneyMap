/**
 * HoneyMap Rule-Based Detection Analysis Panel
 *
 * HONESTY REQUIREMENT & TRANSPARENCY NOTE:
 * HoneyMap utilizes deterministic rule-based signature and honeytoken matching rather than
 * opaque machine learning models. Therefore, the "Detection Confidence" metric is derived
 * directly from rule certainty:
 *
 * - Exact Honeytoken Match (flagged_token != null): 100% Deterministic (Exact Bait Credential Match)
 * - Known Exploit Signature (SQLi / XSS pattern):   85% High-Confidence Signature Rule
 * - Sensitive Trapdoor Path (.env, /backup.sql):     70% Static Trapdoor Match
 * - Generic Portal Probe / Recon (/admin, scan):     55% Behavioral Anomaly Rule
 */

import React, { useState } from 'react';
import {
  Cpu,
  ShieldAlert,
  AlertTriangle,
  Lock,
  ExternalLink,
  ShieldBan,
  Check,
} from 'lucide-react';
import { Card, CardHeader, CardTitle, CardContent } from './ui/card';
import { Badge } from './ui/badge';
import { Button } from './ui/button';
import { TelemetryEvent } from '../types';
import { blockIpStub } from '../api/client';

interface DetectionAnalysisPanelProps {
  latestEvent: TelemetryEvent | null;
  onInvestigateSession: (sessionId: string) => void;
}

export default function DetectionAnalysisPanel({
  latestEvent,
  onInvestigateSession,
}: DetectionAnalysisPanelProps) {
  const [blockedFeedback, setBlockedFeedback] = useState<string | null>(null);

  if (!latestEvent) {
    return (
      <Card className="border-border bg-surface-200">
        <CardHeader className="pb-2">
          <div className="flex items-center gap-2">
            <Cpu className="w-4 h-4 text-cyan-400" />
            <CardTitle>Deterministic Detection Analysis</CardTitle>
          </div>
        </CardHeader>
        <CardContent className="h-48 flex flex-col items-center justify-center text-xs text-slate-400">
          <span>Awaiting live telemetry to evaluate classification rules...</span>
          <span className="text-[10px] text-slate-400 mt-1 font-mono">
            Engine: Rule-Based Deterministic Matrix
          </span>
        </CardContent>
      </Card>
    );
  }

  // Calculate Deterministic Rule Confidence
  let matchType = 'Heuristic Path Match';
  let confidencePct = 55;
  let ruleCategory = 'Behavioral Anomaly';

  if (latestEvent.flagged_token) {
    matchType = 'Exact Honeytoken String Match';
    confidencePct = 100;
    ruleCategory = 'Deterministic Bait Credential Trigger';
  } else if (
    latestEvent.attack_type?.includes('sqli') ||
    latestEvent.attack_type?.includes('xss') ||
    latestEvent.reason?.includes('SQL') ||
    latestEvent.reason?.includes('XSS')
  ) {
    matchType = 'Signature Pattern Match (SQLi / XSS)';
    confidencePct = 85;
    ruleCategory = 'High-Confidence Exploit Heuristic';
  } else if (
    latestEvent.endpoint?.includes('.env') ||
    latestEvent.endpoint?.includes('backup') ||
    latestEvent.endpoint?.includes('credentials') ||
    latestEvent.endpoint?.includes('config')
  ) {
    matchType = 'Sensitive Trapdoor Match';
    confidencePct = 70;
    ruleCategory = 'Static Decoy Exfiltration Probe';
  } else {
    matchType = 'Portal Probe / Path Scan';
    confidencePct = 55;
    ruleCategory = 'Low-Interaction Honeytrap Rule';
  }

  const handleBlockIp = (ip: string) => {
    const res = blockIpStub(ip);
    setBlockedFeedback(res.message);
    setTimeout(() => setBlockedFeedback(null), 3500);
  };

  return (
    <Card className="border-border bg-surface-200">
      <CardHeader className="flex flex-row items-center justify-between pb-2">
        <div className="flex items-center gap-2">
          <Cpu className="w-4 h-4 text-cyan-400" />
          <CardTitle>Deterministic Detection Analysis</CardTitle>
        </div>
        <Badge variant={latestEvent.severity || 'low'} className="text-[11px] uppercase">
          {latestEvent.severity} Risk
        </Badge>
      </CardHeader>
      <CardContent className="space-y-3 pt-1">
        {/* Detection Basis / Reason */}
        <div className="p-3 rounded-lg bg-surface-300 border border-border/80">
          <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider mb-1 flex items-center gap-1.5">
            <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
            <span>Detection Basis (Real Classifier Output)</span>
          </div>
          <div className="text-xs font-mono text-slate-200 break-all">
            {latestEvent.reason || latestEvent.attack_type || 'Suspicious Decoy Interaction'}
          </div>
          {latestEvent.flagged_token && (
            <div className="mt-2 p-1.5 rounded bg-red-950/60 border border-red-800/60 text-[11px] text-red-300 font-mono flex items-center gap-1.5">
              <Lock className="w-3 h-3 text-red-400 flex-shrink-0" />
              <span>Flagged Token: {latestEvent.flagged_token}</span>
            </div>
          )}
        </div>

        {/* Rule Type & Deterministic Confidence */}
        <div className="grid grid-cols-2 gap-2">
          <div className="p-2.5 rounded-lg bg-surface-300/80 border border-border/60">
            <div className="text-[10px] uppercase font-semibold text-slate-400">Match Rule</div>
            <div className="text-xs font-medium text-slate-200 mt-0.5 truncate" title={matchType}>
              {matchType}
            </div>
            <div className="text-[10px] text-slate-400 mt-0.5">{ruleCategory}</div>
          </div>

          <div className="p-2.5 rounded-lg bg-surface-300/80 border border-border/60">
            <div className="text-[10px] uppercase font-semibold text-slate-400">Rule Certainty</div>
            <div className="text-xs font-bold font-mono text-cyan-400 mt-0.5">
              {confidencePct}% (Deterministic)
            </div>
            <div className="text-[10px] text-slate-400 mt-0.5">Rule-derived, non-ML</div>
          </div>
        </div>

        {/* Context metadata: Source IP and Target */}
        <div className="flex items-center justify-between text-xs px-1 text-slate-300">
          <div>
            <span className="text-slate-400">Source: </span>
            <span className="font-mono font-medium text-slate-200">{latestEvent.source_ip}</span>
          </div>
          <div>
            <span className="text-slate-400">Target: </span>
            <span className="font-mono font-medium text-orange-300">{latestEvent.endpoint}</span>
          </div>
        </div>

        {/* Action Buttons */}
        <div className="flex items-center gap-2 pt-1">
          {latestEvent.session_id && (
            <Button
              variant="secondary"
              size="sm"
              onClick={() => onInvestigateSession(latestEvent.session_id!)}
              className="flex-1 bg-surface-100 hover:bg-surface-50 border-border text-xs"
            >
              <ExternalLink className="w-3.5 h-3.5 mr-1 text-blue-400" />
              Investigate Session
            </Button>
          )}

          <Button
            variant="outline"
            size="sm"
            onClick={() => handleBlockIp(latestEvent.source_ip)}
            className="flex-1 border-red-900/50 hover:bg-red-950/50 text-red-300 text-xs"
          >
            <ShieldBan className="w-3.5 h-3.5 mr-1 text-red-400" />
            Block IP (Stub)
          </Button>
        </div>

        {blockedFeedback && (
          <div className="p-2 rounded bg-red-950/70 border border-red-800 text-[11px] text-red-300 flex items-center gap-1.5 animate-fade-in">
            <Check className="w-3 h-3 text-red-400" />
            <span>{blockedFeedback}</span>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
