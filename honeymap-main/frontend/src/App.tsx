import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { subscribeToEvents, subscribeToTransportStatus, TransportType } from './api/socket';
import {
  fetchEvents,
  fetchSessions,
  fetchMetrics,
  fetchAnalytics,
  fetchTargets,
  searchTelemetry,
} from './api/client';
import {
  TelemetryEvent,
  AttackerSession,
  MetricsSummary,
  AnalyticsPoint,
  AttackTarget,
} from './types';

import Sidebar, { ActiveTab } from './components/Sidebar';
import TopBar from './components/TopBar';
import MetricsCards from './components/MetricsCards';
import ThreatAnalyticsChart from './components/ThreatAnalyticsChart';
import SystemStatusCards from './components/SystemStatusCards';
import RecentActivityFeed from './components/RecentActivityFeed';
import SystemActionsMonitor from './components/SystemActionsMonitor';
import AttackTargetsTable from './components/AttackTargetsTable';
import ThreatMap from './components/ThreatMap';
import Leaderboard from './components/Leaderboard';
import IncidentDrawer from './components/IncidentDrawer';
import ThreatIntelView from './components/ThreatIntelView';
import VulnerabilitiesView from './components/VulnerabilitiesView';
import DetectionEngineView from './components/DetectionEngineView';
import ReportsView from './components/ReportsView';
import SettingsView from './components/SettingsView';

export default function App() {
  const [activeTab, setActiveTab] = useState<ActiveTab>('command-center');
  const [transport, setTransport] = useState<TransportType>('connecting');
  const [events, setEvents] = useState<TelemetryEvent[]>([]);
  const [sessions, setSessions] = useState<AttackerSession[]>([]);
  const [metrics, setMetrics] = useState<MetricsSummary | null>(null);
  const [analytics, setAnalytics] = useState<AnalyticsPoint[]>([]);
  const [targets, setTargets] = useState<AttackTarget[]>([]);

  const [selectedRange, setSelectedRange] = useState<'day' | 'week' | 'month' | 'year'>('day');
  // Search query state & server-side lookup debouncer
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedSessionId, setSelectedSessionId] = useState<string | null>(null);
  const [isDrawerOpen, setIsDrawerOpen] = useState(false);
  const [criticalNotifications, setCriticalNotifications] = useState(0);

  // 1. Initial REST Hydration
  const loadDashboardData = useCallback(async () => {
    try {
      const [eventsRes, sessionsRes, metricsRes, analyticsRes, targetsRes] = await Promise.all([
        fetchEvents({ limit: 50 }),
        fetchSessions({ limit: 25 }),
        fetchMetrics(),
        fetchAnalytics(selectedRange),
        fetchTargets(),
      ]);

      if (eventsRes?.events) setEvents(eventsRes.events);
      if (sessionsRes?.sessions) setSessions(sessionsRes.sessions);
      if (metricsRes) setMetrics(metricsRes);
      if (analyticsRes?.points) setAnalytics(analyticsRes.points);
      if (targetsRes?.targets) setTargets(targetsRes.targets);
    } catch (err) {
      console.warn('[HoneyMap] Initial REST hydration error:', err);
    }
  }, [selectedRange]);

  useEffect(() => {
    loadDashboardData();
  }, [loadDashboardData]);

  // Server-side historical search integration
  useEffect(() => {
    if (!searchQuery.trim() || searchQuery.trim().length < 2) return;

    let isMounted = true;
    const timer = setTimeout(async () => {
      try {
        const res = await searchTelemetry(searchQuery.trim());
        if (isMounted && res?.events && res.events.length > 0) {
          setEvents((prev) => {
            const seen = new Set(prev.map((e: TelemetryEvent) => e.id));
            const newEvents = res.events.filter((e: TelemetryEvent) => !seen.has(e.id));
            return newEvents.length > 0 ? [...newEvents, ...prev] : prev;
          });
        }
      } catch (err) {
        console.warn('[HoneyMap Search] API search fallback notice:', err);
      }
    }, 300);

    return () => {
      isMounted = false;
      clearTimeout(timer);
    };
  }, [searchQuery]);

  // 2. Real-Time Stream Subscription & Deduplication
  useEffect(() => {
    const unsubStatus = subscribeToTransportStatus((t) => setTransport(t));

    const unsubEvents = subscribeToEvents((event, sourceTransport) => {
      console.log(
        `[HoneyMap Stream] [${sourceTransport.toUpperCase()}] #${event.id} | ${event.severity?.toUpperCase()} | ${event.source_ip} -> ${event.endpoint}`
      );

      setEvents((prev) => [event, ...prev.slice(0, 149)]);

      if (event.severity === 'critical') {
        setCriticalNotifications((cnt) => cnt + 1);
      }

      fetchMetrics()
        .then((m) => setMetrics(m))
        .catch(() => {});
      fetchTargets()
        .then((t) => t?.targets && setTargets(t.targets))
        .catch(() => {});
    });

    return () => {
      unsubStatus();
      unsubEvents();
    };
  }, []);

  // 3. Periodic Refresh for Analytics
  useEffect(() => {
    let isMounted = true;
    async function refreshAnalytics() {
      try {
        const res = await fetchAnalytics(selectedRange);
        if (isMounted && res?.points) {
          setAnalytics(res.points);
        }
      } catch {}
    }

    const timer = setInterval(refreshAnalytics, 15000);
    return () => {
      isMounted = false;
      clearInterval(timer);
    };
  }, [selectedRange]);

  // Open Incident Forensics Drawer
  const handleInvestigateSession = (sessionId: string) => {
    setSelectedSessionId(sessionId);
    setIsDrawerOpen(true);
  };

  // Filtered Events based on search query across all telemetry attributes
  const filteredEvents = useMemo(() => {
    if (!searchQuery.trim()) return events;
    const q = searchQuery.toLowerCase().trim();
    return events.filter(
      (e) =>
        e.source_ip?.toLowerCase().includes(q) ||
        e.ip?.toLowerCase().includes(q) ||
        e.endpoint?.toLowerCase().includes(q) ||
        e.path?.toLowerCase().includes(q) ||
        e.attack_type?.toLowerCase().includes(q) ||
        e.reason?.toLowerCase().includes(q) ||
        e.flagged_token?.toLowerCase().includes(q) ||
        e.session_id?.toLowerCase().includes(q) ||
        e.request_method?.toLowerCase().includes(q) ||
        e.payload?.toLowerCase().includes(q) ||
        e.severity?.toLowerCase().includes(q) ||
        e.geoip?.country?.toLowerCase().includes(q) ||
        e.geoip?.city?.toLowerCase().includes(q) ||
        e.geoip?.country_code?.toLowerCase().includes(q)
    );
  }, [events, searchQuery]);

  // Filtered Attack Targets
  const filteredTargets = useMemo(() => {
    if (!searchQuery.trim()) return targets;
    const q = searchQuery.toLowerCase().trim();
    return targets.filter(
      (t) =>
        t.target?.toLowerCase().includes(q) ||
        t.severity?.toLowerCase().includes(q)
    );
  }, [targets, searchQuery]);

  const incidentsOnly = useMemo(() => {
    return filteredEvents.filter((e) => e.severity === 'high' || e.severity === 'critical');
  }, [filteredEvents]);

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-canvas text-ink-primary font-sans">
      {/* 1. Sidebar Navigation */}
      <Sidebar
        activeTab={activeTab}
        onSelectTab={setActiveTab}
        criticalCount={criticalNotifications}
        liveTransport={transport}
      />

      {/* 2. Main Work Area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Top Header */}
        <TopBar
          searchQuery={searchQuery}
          onSearchChange={setSearchQuery}
          selectedRange={selectedRange}
          onRangeChange={setSelectedRange}
          criticalNotificationCount={criticalNotifications}
          onClearNotifications={() => setCriticalNotifications(0)}
          transport={transport}
        />

        {/* Dynamic Viewport with Generous Padding & Whitespace */}
        <main className="flex-1 overflow-y-auto p-8 space-y-8 bg-canvas">
          {/* Active Search Filter Banner */}
          {searchQuery.trim() && (
            <div className="max-w-7xl mx-auto p-3 bg-emerald-50/90 border border-emerald-200/90 rounded-xl flex items-center justify-between shadow-xs animate-fade-in">
              <div className="flex items-center gap-2 text-xs">
                <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
                <span className="text-emerald-950 font-semibold">Active Search:</span>
                <span className="font-mono bg-white px-2 py-0.5 rounded-md border border-emerald-200 text-emerald-900 font-bold shadow-2xs">
                  "{searchQuery}"
                </span>
                <span className="text-emerald-800/80 text-[11px] font-medium">
                  ({filteredEvents.length} events, {filteredTargets.length} decoy targets matched)
                </span>
              </div>
              <button
                onClick={() => setSearchQuery('')}
                className="text-xs font-semibold text-emerald-800 hover:text-emerald-950 bg-white hover:bg-emerald-100/80 px-2.5 py-1 rounded-lg border border-emerald-200 flex items-center gap-1.5 cursor-pointer transition-all duration-150 active:scale-95 shadow-2xs"
              >
                Clear Search
              </button>
            </div>
          )}

          {activeTab === 'command-center' && (
            <div className="space-y-8 max-w-7xl mx-auto">
              {/* Row 1: KPI Stat Cards */}
              <MetricsCards metrics={metrics} />

              {/* Row 2: Threat Analytics Recharts + Real System Status Cards */}
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                <div className="lg:col-span-2">
                  <ThreatAnalyticsChart
                    data={analytics}
                    range={selectedRange}
                    onRangeChange={setSelectedRange}
                  />
                </div>
                <div className="lg:col-span-1">
                  <SystemStatusCards />
                </div>
              </div>

              {/* Row 3: Attack Targets Table + Recent Activity Feed */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <AttackTargetsTable targets={filteredTargets} />
                <RecentActivityFeed
                  events={filteredEvents}
                  onInvestigateSession={handleInvestigateSession}
                  transport={transport}
                />
              </div>

              {/* Row 4: System Triggers & Automated Trap Controls + Leaderboard */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <SystemActionsMonitor />
                <Leaderboard
                  onInvestigateSession={handleInvestigateSession}
                  selectedSessionId={selectedSessionId}
                  searchQuery={searchQuery}
                />
              </div>

              {/* Row 5: Global Threat Map with CartoDB Positron Basemap */}
              <div>
                <ThreatMap
                  events={filteredEvents}
                  onInvestigateSession={handleInvestigateSession}
                />
              </div>
            </div>
          )}

          {activeTab === 'live-threats' && (
            <div className="max-w-7xl mx-auto">
              <RecentActivityFeed
                events={filteredEvents}
                onInvestigateSession={handleInvestigateSession}
                transport={transport}
              />
            </div>
          )}

          {activeTab === 'attacks' && (
            <div className="space-y-6 max-w-7xl mx-auto">
              <Leaderboard
                onInvestigateSession={handleInvestigateSession}
                selectedSessionId={selectedSessionId}
                searchQuery={searchQuery}
              />
              <RecentActivityFeed
                events={filteredEvents}
                onInvestigateSession={handleInvestigateSession}
                transport={transport}
              />
            </div>
          )}

          {activeTab === 'incidents' && (
            <div className="space-y-6 max-w-7xl mx-auto">
              <div>
                <h2 className="text-xl font-bold tracking-tight text-ink-primary flex items-center gap-2">
                  <span className="w-2.5 h-2.5 rounded-full bg-danger-600 animate-pulse-subtle" />
                  High & Critical Security Incidents
                </h2>
                <p className="text-xs text-ink-muted mt-1">
                  Filtered intrusion stream displaying high-confidence exploit attempts and honeytoken
                  reuse triggers.
                </p>
              </div>
              <RecentActivityFeed
                events={incidentsOnly}
                onInvestigateSession={handleInvestigateSession}
                transport={transport}
              />
            </div>
          )}

          {activeTab === 'vulnerabilities' && (
            <div className="max-w-7xl mx-auto">
              <VulnerabilitiesView />
            </div>
          )}

          {activeTab === 'detection-engine' && (
            <div className="max-w-7xl mx-auto">
              <DetectionEngineView />
            </div>
          )}

          {activeTab === 'network-map' && (
            <div className="space-y-4 max-w-7xl mx-auto">
              <div>
                <h2 className="text-xl font-bold tracking-tight text-ink-primary">
                  Global Attack Vector & Telemetry Grid
                </h2>
                <p className="text-xs text-ink-muted mt-1">
                  Real-time geolocation telemetry showing attack origins routing to the SOC hub.
                </p>
              </div>
              <ThreatMap
                events={filteredEvents}
                onInvestigateSession={handleInvestigateSession}
              />
            </div>
          )}

          {activeTab === 'threat-intel' && (
            <div className="max-w-7xl mx-auto">
              <ThreatIntelView />
            </div>
          )}

          {activeTab === 'reports' && (
            <div className="max-w-7xl mx-auto">
              <ReportsView onInvestigateSession={handleInvestigateSession} />
            </div>
          )}

          {activeTab === 'settings' && (
            <div className="max-w-7xl mx-auto">
              <SettingsView />
            </div>
          )}
        </main>
      </div>

      {/* 3. Slide-over Incident Forensics Drawer */}
      <IncidentDrawer
        sessionId={selectedSessionId}
        isOpen={isDrawerOpen}
        onClose={() => setIsDrawerOpen(false)}
      />
    </div>
  );
}
