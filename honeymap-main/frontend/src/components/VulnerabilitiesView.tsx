import React, { useEffect, useState } from 'react';
import { fetchLiveDecoys } from '../api/client';
import { Card, CardHeader, CardTitle, CardContent } from './ui/card';
import { Badge } from './ui/badge';
import { Bug, RefreshCw, ShieldCheck } from 'lucide-react';

export default function VulnerabilitiesView() {
  const [data, setData] = useState<{
    live_paths: string[];
    pool: string[];
    rotation_cycle: number;
    rotation_interval_seconds: number;
  } | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let isMounted = true;
    async function load() {
      try {
        const res = await fetchLiveDecoys();
        if (isMounted) setData(res);
      } catch (err) {
        console.error('[VulnerabilitiesView] Error:', err);
      } finally {
        if (isMounted) setLoading(false);
      }
    }
    load();
    const interval = setInterval(load, 15000);
    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, []);

  const totalPool = [
    { path: '/.env', desc: 'Environment variables containing dynamic AWS keys & DB secrets', risk: 'HIGH' },
    { path: '/backup.sql', desc: 'Database dump containing bait admin user bcrypt hashes', risk: 'HIGH' },
    { path: '/config.php', desc: 'Legacy PHP configuration file with database credentials', risk: 'MEDIUM' },
    { path: '/.git/config', desc: 'Exposed git repository remote containing bait auth tokens', risk: 'HIGH' },
    { path: '/.aws/credentials', desc: 'AWS CLI configuration file with dynamic access keys', risk: 'HIGH' },
    { path: '/wp-config.php', desc: 'WordPress master config with DB credentials & auth salts', risk: 'HIGH' },
  ];

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-bold tracking-tight text-ink-primary flex items-center gap-2">
          <Bug className="w-5 h-5 text-brand-600" />
          Adaptive Decoy Trapdoor Rotation
        </h2>
        <p className="text-xs text-ink-muted mt-1">
          HoneyMap rotates exposed sensitive file paths from a pool of 6 decoys every ~90 seconds to
          divert recon crawlers and dynamically harvest threat signatures.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
        <Card className="border-slate-200/80 bg-white rounded-2xl shadow-card">
          <CardContent className="p-5 flex items-center justify-between">
            <div>
              <div className="text-xs text-ink-muted uppercase font-semibold">
                Active Live Trapdoors
              </div>
              <div className="text-2xl font-bold font-mono text-brand-600 mt-1">
                {data?.live_paths?.length || 4}
              </div>
            </div>
            <div className="p-2.5 rounded-xl bg-brand-50 text-brand-600 border border-brand-200">
              <ShieldCheck className="w-5 h-5" />
            </div>
          </CardContent>
        </Card>

        <Card className="border-slate-200/80 bg-white rounded-2xl shadow-card">
          <CardContent className="p-5 flex items-center justify-between">
            <div>
              <div className="text-xs text-ink-muted uppercase font-semibold">
                Total Decoy Pool
              </div>
              <div className="text-2xl font-bold font-mono text-blue-600 mt-1">
                {data?.pool?.length || 6} Paths
              </div>
            </div>
            <div className="p-2.5 rounded-xl bg-blue-50 text-blue-600 border border-blue-200">
              <Bug className="w-5 h-5" />
            </div>
          </CardContent>
        </Card>

        <Card className="border-slate-200/80 bg-white rounded-2xl shadow-card">
          <CardContent className="p-5 flex items-center justify-between">
            <div>
              <div className="text-xs text-ink-muted uppercase font-semibold">
                Rotation Interval
              </div>
              <div className="text-2xl font-bold font-mono text-warning-600 mt-1">
                {data?.rotation_interval_seconds || 90}s
              </div>
            </div>
            <div className="p-2.5 rounded-xl bg-orange-50 text-warning-600 border border-orange-200">
              <RefreshCw className="w-5 h-5" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Trapdoor Matrix */}
      <Card className="border-slate-200/80 bg-white rounded-2xl shadow-card">
        <CardHeader className="pb-3">
          <CardTitle>Decoy Vulnerability Pool Status</CardTitle>
          <p className="text-xs text-ink-muted">Active rotation status across all simulated sensitive files</p>
        </CardHeader>
        <CardContent className="p-5 space-y-3">
          {totalPool.map((p, idx) => {
            const isActive = data?.live_paths?.includes(p.path);
            return (
              <div
                key={idx}
                className={`p-4 rounded-xl border transition-colors flex items-center justify-between gap-4 ${
                  isActive
                    ? 'bg-brand-50/50 border-brand-200 shadow-sm'
                    : 'bg-slate-50/50 border-slate-200/60 opacity-60'
                }`}
              >
                <div className="space-y-1">
                  <div className="flex items-center gap-2 font-mono text-xs font-bold">
                    <span className={isActive ? 'text-brand-900' : 'text-slate-600'}>{p.path}</span>
                    <Badge variant={p.risk === 'HIGH' ? 'high' : 'medium'} className="text-[9px]">
                      {p.risk} RISK
                    </Badge>
                  </div>
                  <div className="text-xs text-ink-muted">{p.desc}</div>
                </div>

                <div>
                  {isActive ? (
                    <Badge variant="live" className="text-[10px]">
                      LIVE ROTATING
                    </Badge>
                  ) : (
                    <Badge variant="secondary" className="text-[10px]">
                      STANDBY
                    </Badge>
                  )}
                </div>
              </div>
            );
          })}
        </CardContent>
      </Card>
    </div>
  );
}
