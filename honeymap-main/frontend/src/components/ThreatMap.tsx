import React, { useState, useMemo } from 'react';
import { MapContainer, TileLayer, Marker, Popup, Polyline } from 'react-leaflet';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';
import { TelemetryEvent, Severity } from '../types';
import { Shield, ExternalLink, Globe, Layers, MapPin } from 'lucide-react';
import { Button } from './ui/button';
import { Badge } from './ui/badge';
import { Card, CardHeader, CardTitle, CardContent } from './ui/card';
import { formatTimeAgo } from '@/lib/utils';

interface ThreatMapProps {
  events: TelemetryEvent[];
  onInvestigateSession: (sessionId: string) => void;
}

// Center SOC Node ("YOUR NETWORK") Coordinates - Washington D.C.
const SOC_HUB: [number, number] = [38.9072, -77.0369];

// Hub Icon for "YOUR NETWORK" with multi-ring radar pulse
const hubIcon = L.divIcon({
  className: 'soc-hub-marker-vibrant',
  html: `
    <div style="position: relative; width: 34px; height: 34px; display: flex; align-items: center; justify-content: center;">
      <div style="position: absolute; width: 34px; height: 34px; border-radius: 50%; background: var(--map-hub-glow); border: 2px solid var(--map-hub-pin); animation: ringPulseHub 2.5s infinite;"></div>
      <div style="position: absolute; width: 22px; height: 22px; border-radius: 50%; background: rgba(5, 150, 105, 0.35); animation: ringPulseHub 2.5s 0.8s infinite;"></div>
      <div style="width: 16px; height: 16px; border-radius: 50%; background: var(--map-hub-core); border: 2.5px solid var(--bg-panel-1); box-shadow: 0 0 10px var(--map-hub-shadow); z-index: 5; display: flex; align-items: center; justify-content: center;">
        <div style="width: 4px; height: 4px; border-radius: 50%; background: var(--accent-interactive);"></div>
      </div>
    </div>
  `,
  iconSize: [34, 34],
  iconAnchor: [17, 17],
  popupAnchor: [0, -17],
});

// Marker icon generator for threat origins with vivid colors & distinct pulse styles
function createVibrantThreatIcon(severity: Severity) {
  const configs: Record<
    Severity,
    { pin: string; border: string; glow: string; anim: string; size: number }
  > = {
    low: {
      pin: 'var(--map-low-pin)',
      border: 'var(--bg-panel-1)',
      glow: 'var(--map-low-glow)',
      anim: 'ringPulseLow',
      size: 18,
    },
    medium: {
      pin: 'var(--map-medium-pin)',
      border: 'var(--bg-panel-1)',
      glow: 'var(--map-medium-glow)',
      anim: 'ringPulseMedium',
      size: 20,
    },
    high: {
      pin: 'var(--map-high-pin)',
      border: 'var(--bg-panel-1)',
      glow: 'var(--map-high-glow)',
      anim: 'ringPulseHigh',
      size: 22,
    },
    critical: {
      pin: 'var(--map-critical-pin)',
      border: 'var(--bg-panel-1)',
      glow: 'var(--map-critical-glow)',
      anim: 'ringPulseCritical',
      size: 24,
    },
  };

  const c = configs[severity] || configs.low;
  const innerSize = severity === 'critical' ? 12 : severity === 'high' ? 10 : 9;

  return L.divIcon({
    className: `threat-marker-vibrant-${severity}`,
    html: `
      <div style="position: relative; width: ${c.size}px; height: ${c.size}px; display: flex; align-items: center; justify-content: center;">
        <div style="position: absolute; width: ${c.size}px; height: ${c.size}px; border-radius: 50%; background: ${c.glow}; animation: ${c.anim} 2s infinite;"></div>
        <div style="width: ${innerSize}px; height: ${innerSize}px; border-radius: 50%; background: ${c.pin}; border: 2px solid ${c.border}; box-shadow: 0 0 8px ${c.pin}; z-index: 3;"></div>
      </div>
    `,
    iconSize: [c.size, c.size],
    iconAnchor: [c.size / 2, c.size / 2],
    popupAnchor: [0, -c.size / 2],
  });
}

const vibrantIcons: Record<Severity, L.DivIcon> = {
  low: createVibrantThreatIcon('low'),
  medium: createVibrantThreatIcon('medium'),
  high: createVibrantThreatIcon('high'),
  critical: createVibrantThreatIcon('critical'),
};

type BasemapStyle = 'osm' | 'esri-topo' | 'esri-street';

export default function ThreatMap({ events = [], onInvestigateSession }: ThreatMapProps) {
  const [basemap, setBasemap] = useState<BasemapStyle>('osm');

  const markers = useMemo(() => {
    const list: Array<{
      id: number;
      ip: string;
      lat: number;
      lon: number;
      severity: Severity;
      reason: string;
      path: string;
      timestamp: string;
      sessionId?: string | null;
      country: string;
      city: string;
    }> = [];
    const seenEvents = new Set<number>();

    for (const ev of events) {
      if (!ev || ev.id === undefined || seenEvents.has(ev.id)) continue;
      seenEvents.add(ev.id);

      const lat =
        ev.lat !== undefined && ev.lat !== null
          ? Number(ev.lat)
          : ev.geoip?.latitude !== undefined
          ? Number(ev.geoip.latitude)
          : null;
      const lon =
        ev.lon !== undefined && ev.lon !== null
          ? Number(ev.lon)
          : ev.geoip?.longitude !== undefined
          ? Number(ev.geoip.longitude)
          : null;

      if (lat !== null && lon !== null && !isNaN(lat) && !isNaN(lon) && (lat !== 0 || lon !== 0)) {
        list.push({
          id: ev.id,
          ip: ev.ip || ev.source_ip || 'Unknown IP',
          lat: Math.max(-85, Math.min(85, lat)),
          lon: Math.max(-180, Math.min(180, lon)),
          severity: (ev.severity || 'low') as Severity,
          reason: ev.reason || ev.attack_type || 'Suspicious probe',
          path: ev.path || ev.endpoint || '/',
          timestamp: ev.timestamp,
          sessionId: ev.session_id,
          country: ev.geoip?.country || 'Unknown Country',
          city: ev.geoip?.city || 'Unknown City',
        });
      }
    }
    return list;
  }, [events]);

  const counts = useMemo(() => {
    let crit = 0;
    let high = 0;
    let med = 0;
    let low = 0;
    for (const m of markers) {
      if (m.severity === 'critical') crit++;
      else if (m.severity === 'high') high++;
      else if (m.severity === 'medium') med++;
      else low++;
    }
    return { crit, high, med, low };
  }, [markers]);

  const vectorColors: Record<Severity, string> = {
    low: 'var(--map-low-pin)',
    medium: 'var(--map-medium-pin)',
    high: 'var(--map-high-pin)',
    critical: 'var(--map-critical-pin)',
  };

  const basemapUrls: Record<BasemapStyle, { url: string; attribution: string }> = {
    osm: {
      url: 'https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png',
      attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors',
    },
    'esri-topo': {
      url: 'https://server.arcgisonline.com/ArcGIS/rest/services/World_Topo_Map/MapServer/tile/{z}/{y}/{x}',
      attribution: 'Tiles &copy; Esri &mdash; Esri, DeLorme, NAVTEQ, TomTom, Intermap, iPC, USGS, FAO, NPS, NRCAN, GeoBase, Kadaster NL, Ordnance Survey, Esri Japan, METI, Esri China (Hong Kong), and the GIS User Community',
    },
    'esri-street': {
      url: 'https://server.arcgisonline.com/ArcGIS/rest/services/World_Street_Map/MapServer/tile/{z}/{y}/{x}',
      attribution: 'Tiles &copy; Esri &mdash; Source: Esri, DeLorme, NAVTEQ, USGS, Intermap, iPC, NRCAN, Esri Japan, METI, Esri China (Hong Kong), Esri (Thailand), TomTom, 2012',
    },
  };

  return (
    <Card className="border-slate-200/80 bg-white rounded-2xl shadow-card overflow-hidden">
      <CardHeader className="flex flex-col sm:flex-row sm:items-center justify-between pb-3 gap-3">
        <div className="flex items-center gap-2.5">
          <div className="p-2 rounded-xl bg-emerald-50 text-emerald-600 border border-emerald-200 shadow-sm">
            <Globe className="w-5 h-5" />
          </div>
          <div>
            <CardTitle className="text-base font-bold text-slate-900">
              Global Attack Geolocation & Telemetry Grid
            </CardTitle>
            <p className="text-xs text-slate-500">Live vector origins converging on protected network hub</p>
          </div>
        </div>

        {/* Live Threat Breakdown & Basemap Switcher */}
        <div className="flex items-center flex-wrap gap-2">
          {/* Severity Counters with Hover Lift */}
          <div className="flex items-center gap-1.5 text-xs bg-slate-50 border border-slate-200/90 rounded-xl px-2.5 py-1 hover:scale-105 transition-transform duration-150 shadow-xs cursor-default">
            <span className="flex items-center gap-1 font-semibold text-red-600">
              <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />
              {counts.crit}
            </span>
            <span className="text-slate-300">|</span>
            <span className="flex items-center gap-1 font-semibold text-orange-600">
              <span className="w-2 h-2 rounded-full bg-orange-500" />
              {counts.high}
            </span>
            <span className="text-slate-300">|</span>
            <span className="flex items-center gap-1 font-semibold text-purple-600">
              <span className="w-2 h-2 rounded-full bg-purple-500" />
              {counts.med}
            </span>
            <span className="text-slate-300">|</span>
            <span className="flex items-center gap-1 font-semibold text-cyan-600">
              <span className="w-2 h-2 rounded-full bg-cyan-500" />
              {counts.low}
            </span>
          </div>

          {/* Basemap Switcher with Tactile Buttons */}
          <div className="flex items-center bg-slate-100 rounded-lg p-0.5 text-[11px] font-medium border border-slate-200 shadow-xs">
            <button
              onClick={() => setBasemap('osm')}
              className={`px-2.5 py-1 rounded-md transition-all duration-150 active:scale-95 cursor-pointer ${
                basemap === 'osm'
                  ? 'bg-white text-slate-900 font-bold shadow-sm scale-100'
                  : 'text-slate-500 hover:text-slate-900 hover:scale-105'
              }`}
            >
              Vibrant OSM
            </button>
            <button
              onClick={() => setBasemap('esri-topo')}
              className={`px-2.5 py-1 rounded-md transition-all duration-150 active:scale-95 cursor-pointer ${
                basemap === 'esri-topo'
                  ? 'bg-white text-slate-900 font-bold shadow-sm scale-100'
                  : 'text-slate-500 hover:text-slate-900 hover:scale-105'
              }`}
            >
              Topographic
            </button>
            <button
              onClick={() => setBasemap('esri-street')}
              className={`px-2.5 py-1 rounded-md transition-all duration-150 active:scale-95 cursor-pointer ${
                basemap === 'esri-street'
                  ? 'bg-white text-slate-900 font-bold shadow-sm scale-100'
                  : 'text-slate-500 hover:text-slate-900 hover:scale-105'
              }`}
            >
              Street
            </button>
          </div>
        </div>
      </CardHeader>

      <CardContent className="p-0 relative h-[440px]">
        <MapContainer
          center={[25, 0]}
          zoom={2}
          minZoom={2}
          maxZoom={9}
          scrollWheelZoom={true}
          className="w-full h-full"
          attributionControl={false}
        >
          {/* Colorful Basemap Tile Layer */}
          <TileLayer
            key={basemap}
            url={basemapUrls[basemap].url}
            attribution={basemapUrls[basemap].attribution}
            maxZoom={19}
          />

          {/* Center Protected SOC Hub Node */}
          <Marker position={SOC_HUB} icon={hubIcon}>
            <Popup className="threat-map-popup-light">
              <div className="p-2 space-y-1">
                <div className="flex items-center gap-1.5 text-xs font-bold text-emerald-700">
                  <Shield className="w-4 h-4 text-emerald-600" />
                  <span>PROTECTED NETWORK (SOC HUB)</span>
                </div>
                <div className="text-[11px] text-slate-600">
                  HoneyMap Central Interceptor & Decoy Mesh
                </div>
                <div className="text-[10px] text-slate-400 font-mono">
                  Coordinates: 38.9072° N, 77.0369° W
                </div>
              </div>
            </Popup>
          </Marker>

          {/* Attack Vector Trajectory Lines */}
          {markers.slice(0, 30).map((m) => (
            <Polyline
              key={`vector-${m.id}`}
              positions={[
                [m.lat, m.lon],
                SOC_HUB,
              ]}
              pathOptions={{
                color: vectorColors[m.severity] || 'var(--map-low-pin)',
                weight: m.severity === 'critical' ? 2.5 : m.severity === 'high' ? 2 : 1.5,
                opacity: m.severity === 'critical' ? 0.85 : 0.65,
                dashArray: m.severity === 'critical' ? '6, 6' : '4, 8',
              }}
            />
          ))}

          {/* Threat Origin Markers */}
          {markers.map((m) => {
            const icon = vibrantIcons[m.severity] || vibrantIcons.low;
            return (
              <Marker key={`marker-${m.id}`} position={[m.lat, m.lon]} icon={icon}>
                <Popup className="threat-map-popup-light">
                  <div className="p-2.5 space-y-2 min-w-[230px]">
                    <div className="flex items-center justify-between border-b border-slate-100 pb-1.5">
                      <Badge variant={m.severity} className="text-[10px] uppercase font-bold">
                        {m.severity} Threat
                      </Badge>
                      <span className="text-[10px] text-slate-500 font-mono">
                        {formatTimeAgo(m.timestamp)}
                      </span>
                    </div>

                    <div className="space-y-0.5 text-xs">
                      <div className="flex items-center gap-1 text-slate-900 font-mono font-bold">
                        <MapPin className="w-3.5 h-3.5 text-slate-400" />
                        <span>{m.ip}</span>
                      </div>
                      <div className="text-[11px] text-slate-500 font-medium">
                        {m.city ? `${m.city}, ` : ''}{m.country}
                      </div>
                    </div>

                    <div className="p-2 rounded-lg bg-slate-50 border border-slate-200 text-[11px] space-y-0.5 font-mono">
                      <div className="text-slate-500 text-[10px] uppercase font-semibold">Target & Tactic:</div>
                      <div className="text-slate-900 font-semibold truncate">{m.path}</div>
                      <div className="text-slate-600 text-[10px]">{m.reason}</div>
                    </div>

                    {m.sessionId && (
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => onInvestigateSession(m.sessionId!)}
                        className="w-full text-xs h-7 mt-1 bg-white hover:bg-slate-50 border-slate-200 shadow-sm font-medium"
                      >
                        <ExternalLink className="w-3.5 h-3.5 mr-1 text-emerald-600" />
                        Investigate Session
                      </Button>
                    )}
                  </div>
                </Popup>
              </Marker>
            );
          })}
        </MapContainer>

        {/* Floating Colorful Map Legend */}
        <div className="absolute bottom-3 left-3 z-[1000] bg-white/95 backdrop-blur border border-slate-200/90 rounded-xl px-3.5 py-2 text-[11px] text-slate-600 shadow-card flex items-center gap-3">
          <span className="font-bold text-slate-400 uppercase text-[10px]">Vectors:</span>
          <span className="flex items-center gap-1.5 font-semibold text-emerald-700">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-600 shadow-sm" /> SOC Hub
          </span>
          <span className="flex items-center gap-1.5 font-medium text-slate-700">
            <span className="w-2 h-2 rounded-full bg-cyan-500" /> Low
          </span>
          <span className="flex items-center gap-1.5 font-medium text-slate-700">
            <span className="w-2 h-2 rounded-full bg-purple-500" /> Med
          </span>
          <span className="flex items-center gap-1.5 font-medium text-slate-700">
            <span className="w-2 h-2 rounded-full bg-orange-500" /> High
          </span>
          <span className="flex items-center gap-1.5 font-semibold text-red-600">
            <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse" /> Critical
          </span>
        </div>
      </CardContent>
    </Card>
  );
}
