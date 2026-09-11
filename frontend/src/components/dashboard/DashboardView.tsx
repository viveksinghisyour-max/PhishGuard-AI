import React, { useState } from 'react';
import { MetricsGrid } from './MetricsGrid';
import { SuspiciousEmailCards } from './SuspiciousEmailCards';
import { ThreatSeverityChart } from './ThreatSeverityChart';
import { RecentThreatsTable } from './RecentThreatsTable';
import { LiveIocTicker } from './LiveIocTicker';
import { DashboardStats, InvestigationCase, ActiveTab } from '../../types';

interface DashboardViewProps {
  stats: DashboardStats;
  setActiveTab: (tab: ActiveTab) => void;
  onSelectCase?: (caseItem: InvestigationCase) => void;
}

export const DashboardView: React.FC<DashboardViewProps> = ({ stats, setActiveTab, onSelectCase }) => {
  const [metricFilter, setMetricFilter] = useState<string>('all');

  const handleMetricFilter = (filterType: string) => {
    setMetricFilter(filterType);
  };

  return (
    <div className="space-y-5 pb-12">
      {/* Live Running Threat IOC Marquee Ticker */}
      <LiveIocTicker />

      {/* 4 Primary 3D KPI Cards with Sparklines & Filter Actions */}
      <MetricsGrid stats={stats} onFilterClick={handleMetricFilter} />

      {/* Hero Incident Spotlight & Urgent Triage Queue */}
      <SuspiciousEmailCards 
        cases={stats.recent_activity} 
        setActiveTab={setActiveTab} 
        onSelectCase={onSelectCase} 
      />

      {/* Recharts Severity Breakdown & Attack Velocity Area Chart */}
      <ThreatSeverityChart stats={stats} />

      {/* Recent Threat Activity Table with Expandable Forensics & Quick Actions */}
      <RecentThreatsTable 
        cases={stats.recent_activity} 
        setActiveTab={setActiveTab} 
        onSelectCase={onSelectCase} 
      />
    </div>
  );
};
