import React from 'react';
import {
  LayoutDashboard,
  Radio,
  Flame,
  AlertTriangle,
  Bug,
  Cpu,
  Globe2,
  KeyRound,
  FileText,
  Sliders,
  ShieldCheck,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { Badge } from './ui/badge';

export type ActiveTab =
  | 'command-center'
  | 'live-threats'
  | 'attacks'
  | 'incidents'
  | 'vulnerabilities'
  | 'detection-engine'
  | 'network-map'
  | 'threat-intel'
  | 'reports'
  | 'settings';

interface SidebarProps {
  activeTab: ActiveTab;
  onSelectTab: (tab: ActiveTab) => void;
  criticalCount?: number;
  liveTransport?: string;
}

interface NavItem {
  id: ActiveTab;
  label: string;
  icon: React.ElementType;
  badge?: string | number;
  badgeVariant?: 'default' | 'critical' | 'live' | 'secondary' | 'brand';
}

export default function Sidebar({
  activeTab,
  onSelectTab,
  criticalCount = 0,
  liveTransport = 'websocket',
}: SidebarProps) {
  const navItems: NavItem[] = [
    {
      id: 'command-center',
      label: 'Command Center',
      icon: LayoutDashboard,
    },
    {
      id: 'live-threats',
      label: 'Live Threats',
      icon: Radio,
      badge: liveTransport === 'websocket' ? 'LIVE' : 'POLL',
      badgeVariant: liveTransport === 'websocket' ? 'brand' : 'secondary',
    },
    {
      id: 'attacks',
      label: 'Attacks',
      icon: Flame,
    },
    {
      id: 'incidents',
      label: 'Incidents',
      icon: AlertTriangle,
      badge: criticalCount > 0 ? criticalCount : undefined,
      badgeVariant: 'critical',
    },
    {
      id: 'vulnerabilities',
      label: 'Vulnerabilities',
      icon: Bug,
    },
    {
      id: 'detection-engine',
      label: 'Detection Engine',
      icon: Cpu,
    },
    {
      id: 'network-map',
      label: 'Network Map',
      icon: Globe2,
    },
    {
      id: 'threat-intel',
      label: 'Threat Intelligence',
      icon: KeyRound,
    },
    {
      id: 'reports',
      label: 'Reports',
      icon: FileText,
    },
    {
      id: 'settings',
      label: 'Settings',
      icon: Sliders,
    },
  ];

  return (
    <aside className="w-64 flex-shrink-0 border-r flex flex-col justify-between h-screen select-none" style={{ backgroundColor: 'var(--map-hub-slight)', borderRightColor: 'var(--grid-line)' }}>
      {/* Brand Header */}
      <div>
        <div className="h-16 px-5 flex items-center gap-3 border-b border-emerald-200/60 bg-white/50 backdrop-blur-sm">
          <div className="w-9 h-9 rounded-xl bg-emerald-600 border border-emerald-700 flex items-center justify-center text-white shadow-sm hover:scale-110 hover:rotate-6 transition-all duration-300 cursor-pointer">
            <ShieldCheck className="w-5 h-5 transition-transform" />
          </div>
          <div>
            <div className="flex items-center gap-1.5">
              <span className="font-bold text-base tracking-tight text-slate-900">
                HoneyMap
              </span>
            </div>
            <p className="text-[11px] text-emerald-800/80 font-medium">Intrusion & Threat Grid</p>
          </div>
        </div>

        {/* Navigation List with Light Green Theme & Micro-Animations */}
        <nav className="p-3 space-y-1">
          <div className="px-3 py-2 text-[10px] font-bold uppercase tracking-wider text-emerald-900/70">
            Platform Views
          </div>
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => onSelectTab(item.id)}
                className={cn(
                  'w-full flex items-center justify-between px-3.5 py-2.5 rounded-xl text-xs font-medium transition-all duration-200 group cursor-pointer active:scale-[0.97]',
                  isActive
                    ? 'bg-white text-emerald-900 font-bold border border-emerald-300 shadow-sm translate-x-1'
                    : 'text-emerald-950/80 hover:text-emerald-950 hover:bg-emerald-100/80 hover:translate-x-1 hover:shadow-xs'
                )}
              >
                <div className="flex items-center gap-3">
                  <Icon
                    className={cn(
                      'w-4 h-4 transition-transform duration-200',
                      isActive
                        ? 'text-emerald-600 scale-110'
                        : 'text-emerald-700/70 group-hover:text-emerald-900 group-hover:scale-115'
                    )}
                  />
                  <span className="transition-colors">{item.label}</span>
                </div>
                {item.badge !== undefined && (
                  <Badge
                    variant={item.badgeVariant || 'default'}
                    className="text-[10px] px-1.5 py-0 h-4 transition-transform duration-150 group-hover:scale-105"
                  >
                    {item.badge}
                  </Badge>
                )}
              </button>
            );
          })}
        </nav>
      </div>

      {/* Footer System Status */}
      <div className="p-4 border-t border-emerald-200/60 bg-emerald-100/50 hover:bg-emerald-100/80 transition-colors duration-200">
        <div className="flex items-center justify-between text-xs">
          <span className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
            <span className="font-semibold text-emerald-900">System Active</span>
          </span>
          <span className="text-[11px] text-emerald-800/70 font-medium">Real-Time</span>
        </div>
      </div>
    </aside>
  );
}
