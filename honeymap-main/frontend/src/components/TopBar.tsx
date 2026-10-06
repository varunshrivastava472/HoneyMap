import React, { useState, useEffect } from 'react';
import {
  Search,
  Bell,
  CheckCircle2,
  AlertCircle,
  Calendar,
  X,
  User,
} from 'lucide-react';
import { Input } from './ui/input';
import { Button } from './ui/button';
import { fetchHealth } from '../api/client';

interface TopBarProps {
  searchQuery: string;
  onSearchChange: (q: string) => void;
  selectedRange: 'day' | 'week' | 'month' | 'year';
  onRangeChange: (r: 'day' | 'week' | 'month' | 'year') => void;
  criticalNotificationCount: number;
  onClearNotifications: () => void;
  transport: string;
}

export default function TopBar({
  searchQuery,
  onSearchChange,
  selectedRange,
  onRangeChange,
  criticalNotificationCount,
  onClearNotifications,
  transport,
}: TopBarProps) {
  const [healthStatus, setHealthStatus] = useState<'ok' | 'degraded' | 'checking'>('checking');

  useEffect(() => {
    let isMounted = true;
    async function checkSystemHealth() {
      try {
        const res = await fetchHealth();
        if (isMounted) {
          setHealthStatus(res.status === 'ok' ? 'ok' : 'degraded');
        }
      } catch {
        if (isMounted) {
          setHealthStatus('degraded');
        }
      }
    }

    checkSystemHealth();
    const timer = setInterval(checkSystemHealth, 15000);
    return () => {
      isMounted = false;
      clearInterval(timer);
    };
  }, []);

  return (
    <header className="h-16 px-8 border-b border-slate-200/80 bg-white flex items-center justify-between gap-6 sticky top-0 z-30">
      {/* Search Input (Real event/session filter with instant clear & Esc key) */}
      <div className="relative flex-1 max-w-md">
        <Search className="w-4 h-4 absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-400 pointer-events-none" />
        <Input
          type="text"
          placeholder="Search intrusions by IP, path, tactic, token, or session..."
          value={searchQuery}
          onChange={(e) => onSearchChange(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Escape') onSearchChange('');
          }}
          className="pl-9 pr-9 bg-slate-50/80 border-slate-200 text-xs h-9 rounded-xl focus-visible:ring-2 focus-visible:ring-emerald-500 focus-visible:border-emerald-500 placeholder:text-slate-400 transition-all shadow-2xs"
        />
        {searchQuery && (
          <button
            onClick={() => onSearchChange('')}
            title="Clear search (Esc)"
            className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-700 hover:scale-110 active:scale-90 p-1 rounded-md transition-all cursor-pointer"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        )}
      </div>

      {/* Right Controls */}
      <div className="flex items-center gap-3">
        {/* Date Filter */}
        <div className="flex items-center bg-slate-100/80 border border-slate-200/80 rounded-xl p-0.5 text-xs shadow-xs">
          <Calendar className="w-3.5 h-3.5 ml-2.5 mr-1.5 text-slate-500" />
          {(['day', 'week', 'month', 'year'] as const).map((r) => (
            <button
              key={r}
              onClick={() => onRangeChange(r)}
              className={`px-3 py-1 rounded-lg text-xs font-medium uppercase transition-all duration-150 cursor-pointer active:scale-95 ${
                selectedRange === r
                  ? 'bg-white text-ink-primary font-bold shadow-pill border border-slate-200/80 scale-100'
                  : 'text-slate-500 hover:text-ink-primary hover:scale-105'
              }`}
            >
              {r}
            </button>
          ))}
        </div>

        {/* System Health Status */}
        <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-emerald-50/90 border border-emerald-200 text-xs hover:scale-105 hover:bg-emerald-100/80 transition-all duration-150 cursor-default shadow-xs">
          {healthStatus === 'ok' ? (
            <>
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600 animate-pulse-subtle" />
              <span className="text-xs text-emerald-800 font-semibold tracking-wide">Protected</span>
            </>
          ) : (
            <>
              <AlertCircle className="w-3.5 h-3.5 text-warning-500 animate-pulse" />
              <span className="text-xs text-warning-700 font-medium">Degraded</span>
            </>
          )}
        </div>

        {/* Notification Bell with Wiggle */}
        <div className="relative">
          <Button
            variant="outline"
            size="icon"
            onClick={onClearNotifications}
            className="group relative h-9 w-9 rounded-xl bg-white border-slate-200 hover:bg-slate-50 hover:border-slate-300 hover:shadow-md active:scale-90 transition-all duration-150"
            title={
              criticalNotificationCount > 0
                ? `${criticalNotificationCount} unread CRITICAL events`
                : 'No unread alerts'
            }
          >
            <Bell className="w-4 h-4 text-slate-600 transition-transform duration-200 group-hover:rotate-12 group-hover:scale-110" />
            {criticalNotificationCount > 0 && (
              <span className="absolute -top-1 -right-1 flex h-4 min-w-4 px-1 items-center justify-center rounded-full bg-danger-600 text-[10px] font-bold text-white ring-2 ring-white animate-pulse">
                {criticalNotificationCount > 99 ? '99+' : criticalNotificationCount}
              </span>
            )}
          </Button>
        </div>

        {/* User Profile (Labeled as Demo Mode) */}
        <div className="flex items-center gap-2 pl-2 border-l border-slate-200 hover:scale-105 transition-transform duration-150 cursor-pointer">
          <div className="w-8 h-8 rounded-full bg-brand-100 border border-brand-200 flex items-center justify-center text-brand-700 shadow-xs">
            <User className="w-4 h-4" />
          </div>
          <div className="hidden lg:block text-left">
            <div className="text-xs font-semibold text-ink-primary">Security Lead</div>
            <div className="text-[10px] text-ink-muted">Demo Mode</div>
          </div>
        </div>
      </div>
    </header>
  );
}
