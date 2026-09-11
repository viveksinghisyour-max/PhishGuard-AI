import React, { useEffect, useRef, useState } from 'react';
import L from 'leaflet';
import { Globe, Navigation, Shield, Flame, Radio, Maximize2, AlertCircle } from 'lucide-react';
import { RelayHop, GeoLocationInfo, RelayTrajectory } from '../../types';
import { api } from '../../services/api';

interface RelayMapProps {
  hops?: RelayHop[];
  singleGeo?: GeoLocationInfo;
  height?: string;
  className?: string;
  onSelectHop?: (hop: RelayHop) => void;
}

export const RelayMap: React.FC<RelayMapProps> = ({
  hops = [],
  singleGeo,
  height = '440px',
  className = '',
  onSelectHop,
}) => {
  const mapContainerRef = useRef<HTMLDivElement>(null);
  const mapInstanceRef = useRef<L.Map | null>(null);
  const layerGroupRef = useRef<L.LayerGroup | null>(null);

  const [trajectoryData, setTrajectoryData] = useState<RelayTrajectory | null>(null);
  const [selectedPoint, setSelectedPoint] = useState<any | null>(null);
  const [isLoadingTrajectory, setIsLoadingTrajectory] = useState(false);

  // Fetch or calculate trajectory data when hops change
  useEffect(() => {
    if (hops && hops.length > 0) {
      setIsLoadingTrajectory(true);
      api.getRelayTrajectory(hops)
        .then((traj) => {
          setTrajectoryData(traj);
          setIsLoadingTrajectory(false);
        })
        .catch((err) => {
          console.warn('Could not fetch server trajectory, falling back to local points', err);
          // Local fallback trajectory
          const valid = hops.filter(h => !h.is_private && (h.latitude !== 0 || h.longitude !== 0));
          const originHop = hops.find(h => h.is_origin) || valid[0];
          setTrajectoryData({
            trajectory: valid.map((h, i) => ({
              hop_number: h.hop_number,
              ip: h.ip,
              latitude: h.latitude,
              longitude: h.longitude,
              city: h.city,
              country: h.country,
              country_code: h.country_code,
              isp: h.isp,
              asn: h.asn,
              delay_seconds: h.delay_seconds,
              is_origin: h.is_origin,
              is_destination: i === valid.length - 1,
              is_tor: h.is_tor,
              is_hosting: h.is_hosting,
              is_vpn: h.is_vpn,
            })),
            total_points: valid.length,
            origin_ip: originHop ? originHop.ip : (valid[0]?.ip || 'Unknown'),
            origin_location: originHop ? `${originHop.city}, ${originHop.country}` : 'Unknown',
            total_distance_km: 0,
            total_delay_seconds: hops.reduce((acc, h) => acc + (h.delay_seconds || 0), 0),
            has_tor: valid.some(h => h.is_tor),
            has_anomalous_distance: false,
          });
          setIsLoadingTrajectory(false);
        });
    } else if (singleGeo) {
      setTrajectoryData({
        trajectory: [{
          hop_number: 1,
          ip: singleGeo.ip,
          latitude: singleGeo.latitude,
          longitude: singleGeo.longitude,
          city: singleGeo.city,
          country: singleGeo.country,
          country_code: singleGeo.country_code,
          isp: singleGeo.isp,
          asn: singleGeo.asn,
          delay_seconds: 0,
          is_origin: true,
          is_destination: true,
          is_tor: singleGeo.is_tor,
          is_hosting: singleGeo.is_hosting,
          is_vpn: singleGeo.is_vpn,
        }],
        total_points: 1,
        origin_ip: singleGeo.ip,
        origin_location: `${singleGeo.city}, ${singleGeo.country}`,
        total_distance_km: 0,
        total_delay_seconds: 0,
        has_tor: singleGeo.is_tor,
        has_anomalous_distance: false,
      });
    } else {
      setTrajectoryData(null);
    }
  }, [hops, singleGeo]);

  // Initialize and update Leaflet Map
  useEffect(() => {
    if (!mapContainerRef.current) return;

    // Initialize Map if not already initialized
    if (!mapInstanceRef.current) {
      const map = L.map(mapContainerRef.current, {
        zoomControl: false,
        attributionControl: false,
        minZoom: 2,
        maxZoom: 18,
        worldCopyJump: true,
      }).setView([25, 10], 2);

      // Esri World Dark Gray Base & Reference (Pristine zero-watermark dark SOC tiles, 100% open & free)
      L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Base/MapServer/tile/{z}/{y}/{x}', {
        maxZoom: 16,
      }).addTo(map);

      L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Reference/MapServer/tile/{z}/{y}/{x}', {
        maxZoom: 16,
      }).addTo(map);

      // Add Zoom control in top right
      L.control.zoom({ position: 'topright' }).addTo(map);

      const layerGroup = L.layerGroup().addTo(map);
      layerGroupRef.current = layerGroup;
      mapInstanceRef.current = map;
    }

    const map = mapInstanceRef.current;
    const layerGroup = layerGroupRef.current;
    if (!map || !layerGroup) return;

    layerGroup.clearLayers();

    const points = trajectoryData?.trajectory || [];
    if (points.length === 0) {
      // Default world view
      map.setView([20, 0], 2);
      return;
    }

    const latLngs: L.LatLngTuple[] = [];

    // 1. Draw connecting geodesic Polyline if multi-point
    if (points.length > 1) {
      points.forEach(p => {
        if (p.latitude !== 0 || p.longitude !== 0) {
          latLngs.push([p.latitude, p.longitude]);
        }
      });

      if (latLngs.length > 1) {
        // Outer glow polyline
        L.polyline(latLngs, {
          color: '#06b6d4',
          weight: 4,
          opacity: 0.4,
          lineCap: 'round',
          lineJoin: 'round',
        }).addTo(layerGroup);

        // Inner dashed polyline representing active transmission path
        L.polyline(latLngs, {
          color: '#38bdf8',
          weight: 2,
          opacity: 0.9,
          dashArray: '7, 9',
          lineCap: 'round',
        }).addTo(layerGroup);
      }
    }

    // 2. Add custom styled radar markers for each hop
    points.forEach((pt) => {
      if (pt.latitude === 0 && pt.longitude === 0) return;

      const isOrigin = pt.is_origin;
      const isDest = pt.is_destination && !isOrigin;
      const isTor = pt.is_tor;

      // Color scheme based on role
      let ringColor = 'rgba(6, 182, 212, 0.8)';
      let coreColor = '#06b6d4';
      let beaconClass = 'marker-beacon-relay';
      let label = `#${pt.hop_number}`;

      if (isOrigin) {
        ringColor = 'rgba(244, 63, 94, 0.8)';
        coreColor = '#f43f5e';
        beaconClass = 'marker-beacon-origin';
        label = 'ORIGIN';
      } else if (isDest) {
        ringColor = 'rgba(16, 185, 129, 0.8)';
        coreColor = '#10b981';
        label = 'GATEWAY';
      } else if (isTor) {
        ringColor = 'rgba(234, 88, 12, 0.8)';
        coreColor = '#ea580c';
        label = 'TOR';
      }

      // Custom SVG DivIcon avoiding bundler asset URL issues
      const iconHtml = `
        <div class="relative flex items-center justify-center cursor-pointer group" style="width: 36px; height: 36px;">
          <div class="${beaconClass} absolute w-7 h-7 rounded-full" style="background: ${ringColor};"></div>
          <div class="relative w-5 h-5 rounded-full flex items-center justify-center shadow-lg border border-white/40" style="background: ${coreColor};">
            <span style="font-size: 8px; font-weight: 900; color: #ffffff; font-family: monospace;">${pt.hop_number}</span>
          </div>
          <div class="absolute -bottom-4 bg-slate-950/90 text-white border border-slate-700/80 px-1 py-0.2 rounded text-[8px] font-mono whitespace-nowrap shadow-md pointer-events-none">
            ${label}
          </div>
        </div>
      `;

      const customIcon = L.divIcon({
        html: iconHtml,
        className: 'custom-leaflet-beacon',
        iconSize: [36, 36],
        iconAnchor: [18, 18],
        popupAnchor: [0, -18],
      });

      const marker = L.marker([pt.latitude, pt.longitude], { icon: customIcon }).addTo(layerGroup);

      // Cyber tactical popup
      const popupHtml = `
        <div style="min-width: 220px; font-family: ui-monospace, SFMono-Regular, monospace;" class="p-2 space-y-2">
          <div class="flex items-center justify-between border-b border-cyan-500/30 pb-1.5">
            <span class="text-[10px] font-bold uppercase tracking-wider ${isOrigin ? 'text-rose-400' : isDest ? 'text-emerald-400' : 'text-cyan-400'}">
              ${isOrigin ? '✦ EARLIEST SENDER ORIGIN' : isDest ? '✓ RECIPIENT GATEWAY' : `HOP #${pt.hop_number} SMTP RELAY`}
            </span>
            ${isTor ? '<span class="text-[9px] bg-rose-500/20 text-rose-300 px-1 rounded border border-rose-500/40">TOR EXIT</span>' : ''}
          </div>

          <div class="space-y-1 text-xs">
            <div class="flex justify-between">
              <span class="text-slate-400 text-[10px]">IPv4 Address:</span>
              <span class="text-white font-bold tracking-wider">${pt.ip}</span>
            </div>
            <div class="flex justify-between">
              <span class="text-slate-400 text-[10px]">Geographic:</span>
              <span class="text-slate-200 font-medium">${pt.city || 'Unknown'}, ${pt.country}</span>
            </div>
            <div class="flex justify-between">
              <span class="text-slate-400 text-[10px]">Network ASN:</span>
              <span class="text-cyan-300 font-medium">${pt.asn || 'AS0'}</span>
            </div>
            <div class="flex justify-between">
              <span class="text-slate-400 text-[10px]">ISP / Provider:</span>
              <span class="text-slate-300 font-medium truncate max-w-[130px]">${pt.isp || 'Commercial Carrier'}</span>
            </div>
            ${pt.delay_seconds > 0 ? `
              <div class="flex justify-between text-amber-300 pt-0.5 border-t border-slate-800">
                <span class="text-[10px]">Transit Delay:</span>
                <span class="font-bold">+${pt.delay_seconds}s</span>
              </div>
            ` : ''}
          </div>

          <div class="pt-1 flex gap-1">
            ${pt.is_hosting ? '<span class="text-[9px] px-1 py-0.5 rounded bg-purple-500/20 text-purple-300 border border-purple-500/30">DATACENTER</span>' : ''}
            ${pt.is_vpn ? '<span class="text-[9px] px-1 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30">VPN</span>' : ''}
          </div>
        </div>
      `;

      marker.bindPopup(popupHtml, {
        closeButton: false,
        className: 'cyber-dark-popup',
      });

      marker.on('click', () => {
        setSelectedPoint(pt);
        if (onSelectHop) {
          const matchedHop = hops.find(h => h.hop_number === pt.hop_number);
          if (matchedHop) onSelectHop(matchedHop);
        }
      });

      latLngs.push([pt.latitude, pt.longitude]);
    });

    // Auto fit bounds
    if (latLngs.length > 1) {
      const bounds = L.latLngBounds(latLngs);
      map.fitBounds(bounds, { padding: [50, 50], maxZoom: 10 });
    } else if (latLngs.length === 1) {
      map.setView(latLngs[0], 6);
    }
  }, [trajectoryData, hops]);

  // Clean teardown on unmount
  useEffect(() => {
    return () => {
      if (mapInstanceRef.current) {
        mapInstanceRef.current.remove();
        mapInstanceRef.current = null;
      }
    };
  }, []);

  const handleFitBounds = () => {
    if (!mapInstanceRef.current || !trajectoryData) return;
    const pts = trajectoryData.trajectory.filter(p => p.latitude !== 0 || p.longitude !== 0);
    if (pts.length > 1) {
      const bounds = L.latLngBounds(pts.map(p => [p.latitude, p.longitude]));
      mapInstanceRef.current.fitBounds(bounds, { padding: [50, 50], maxZoom: 10 });
    } else if (pts.length === 1) {
      mapInstanceRef.current.setView([pts[0].latitude, pts[0].longitude], 6);
    }
  };

  const handleFocusOrigin = () => {
    if (!mapInstanceRef.current || !trajectoryData) return;
    const origin = trajectoryData.trajectory.find(p => p.is_origin) || trajectoryData.trajectory[0];
    if (origin && (origin.latitude !== 0 || origin.longitude !== 0)) {
      mapInstanceRef.current.flyTo([origin.latitude, origin.longitude], 7, { duration: 1.2 });
    }
  };

  return (
    <div className={`relative rounded-2xl overflow-hidden border border-cyber-border/80 shadow-2xl glass-panel ${className}`}>
      {/* Tactical HUD Header */}
      <div className="absolute top-3 left-3 z-[400] flex flex-wrap items-center gap-2 pointer-events-auto">
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-xl bg-slate-950/85 backdrop-blur-md border border-cyber-border text-xs font-mono shadow-xl">
          <Globe className="w-4 h-4 text-cyan-400 animate-spin-slow" />
          <span className="text-white font-bold">GLOBAL RELAY TRAJECTORY</span>
          {isLoadingTrajectory && (
            <span className="text-[10px] text-cyan-400 animate-pulse">CALCULATING...</span>
          )}
        </div>

        {trajectoryData && (
          <div className="hidden sm:flex items-center gap-2 px-2.5 py-1.5 rounded-xl bg-slate-950/85 backdrop-blur-md border border-cyber-border text-[11px] font-mono text-slate-300 shadow-xl">
            <span className="text-slate-400">Flight:</span>
            <span className="text-cyan-300 font-bold">{trajectoryData.total_distance_km.toLocaleString()} km</span>
            <span className="text-slate-600">|</span>
            <span className="text-slate-400">Delay:</span>
            <span className="text-amber-400 font-bold">{trajectoryData.total_delay_seconds}s</span>
          </div>
        )}

        {trajectoryData?.has_tor && (
          <div className="flex items-center gap-1 px-2.5 py-1.5 rounded-xl bg-rose-950/80 backdrop-blur-md border border-rose-500/50 text-[10px] font-mono text-rose-300 font-bold shadow-xl animate-pulse">
            <Flame className="w-3.5 h-3.5 text-rose-400" />
            <span>TOR NODE IN PATH</span>
          </div>
        )}
      </div>

      {/* Map Control Buttons */}
      <div className="absolute top-3 right-12 z-[400] flex items-center gap-1.5 pointer-events-auto">
        <button
          type="button"
          onClick={handleFocusOrigin}
          title="Focus Origin IP"
          className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-slate-900/90 hover:bg-slate-800 border border-cyber-border text-xs font-mono text-slate-300 hover:text-white transition-all shadow-lg"
        >
          <Radio className="w-3.5 h-3.5 text-rose-400" />
          <span className="hidden md:inline text-[11px]">Focus Origin</span>
        </button>
        <button
          type="button"
          onClick={handleFitBounds}
          title="Fit Route Bounds"
          className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-slate-900/90 hover:bg-slate-800 border border-cyber-border text-xs font-mono text-slate-300 hover:text-white transition-all shadow-lg"
        >
          <Maximize2 className="w-3.5 h-3.5 text-cyan-400" />
          <span className="hidden md:inline text-[11px]">Fit View</span>
        </button>
      </div>

      {/* Leaflet Map Canvas Container */}
      <div
        ref={mapContainerRef}
        style={{ height, width: '100%' }}
        className="w-full bg-[#040711]"
      />

      {/* Bottom HUD Telemetry Strip */}
      {trajectoryData && trajectoryData.trajectory.length > 0 && (
        <div className="absolute bottom-2 left-3 right-3 z-[400] pointer-events-none">
          <div className="flex flex-wrap items-center justify-between gap-2 p-2 px-3 rounded-xl bg-slate-950/90 backdrop-blur-md border border-cyber-border text-xs font-mono shadow-2xl pointer-events-auto">
            <div className="flex items-center gap-3">
              <div className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-rose-500 animate-ping" />
                <span className="text-[11px] text-slate-400">Origin IP:</span>
                <span className="text-[11px] font-bold text-white">{trajectoryData.origin_ip}</span>
                <span className="text-[10px] text-slate-500">({trajectoryData.origin_location})</span>
              </div>
            </div>

            <div className="flex items-center gap-3 text-[11px]">
              <div className="flex items-center gap-1">
                <Navigation className="w-3 h-3 text-cyan-400" />
                <span className="text-slate-400">Hops:</span>
                <span className="text-white font-bold">{trajectoryData.total_points}</span>
              </div>
              <div className="flex items-center gap-1">
                <Shield className="w-3 h-3 text-emerald-400" />
                <span className="text-slate-400">Dark Canvas Tiles:</span>
                <span className="text-emerald-400 font-bold">Active</span>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
