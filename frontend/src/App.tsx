import React, { useState, useEffect } from 'react';
import { Sidebar } from './components/layout/Sidebar';
import { Header } from './components/layout/Header';
import { DashboardView } from './components/dashboard/DashboardView';
import { AnalyzeView } from './components/analyze/AnalyzeView';
import { InvestigationsView } from './components/investigations/InvestigationsView';
import { IntelView } from './components/intel/IntelView';
import { ReportsView } from './components/reports/ReportsView';
import { SettingsView } from './components/settings/SettingsView';
import { ModelManagementView } from './components/ml/ModelManagementView';
import { ActiveTab, DashboardStats, InvestigationCase } from './types';
import { api } from './services/api';

export function App() {
  const [activeTab, setActiveTab] = useState<ActiveTab>('dashboard');
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [selectedCase, setSelectedCase] = useState<InvestigationCase | null>(null);
  const [isRefreshing, setIsRefreshing] = useState(false);

  const loadStats = async () => {
    setIsRefreshing(true);
    try {
      const data = await api.getDashboardStats();
      setStats(data);
    } catch (err) {
      console.error("Failed to load dashboard stats", err);
    } finally {
      setIsRefreshing(false);
    }
  };

  useEffect(() => {
    loadStats();
  }, []);

  const handleSelectCase = (caseItem: InvestigationCase) => {
    setSelectedCase(caseItem);
    setActiveTab('investigations');
  };

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-cyber-bg text-cyber-text font-sans">
      {/* Left Fixed SOC Sidebar */}
      <Sidebar activeTab={activeTab} setActiveTab={setActiveTab} />

      {/* Main Content Area */}
      <div className="flex flex-col flex-1 h-full min-w-0 overflow-hidden">
        {/* Top Header Bar */}
        <Header 
          setActiveTab={setActiveTab} 
          onRefresh={loadStats} 
          isRefreshing={isRefreshing} 
        />

        {/* Dynamic Tab Body with Cyber Grid and Glow */}
        <main className="flex-1 overflow-y-auto p-6 cyber-grid relative">
          {/* Ambient Lighting Overlay */}
          <div className="absolute top-0 left-1/4 w-96 h-96 bg-cyber-cyan/5 rounded-full blur-3xl pointer-events-none" />
          <div className="absolute bottom-10 right-1/4 w-96 h-96 bg-cyber-purple/5 rounded-full blur-3xl pointer-events-none" />

          <div className="relative z-10 max-w-7xl mx-auto">
            {activeTab === 'dashboard' && stats && (
              <DashboardView 
                stats={stats} 
                setActiveTab={setActiveTab} 
                onSelectCase={handleSelectCase} 
              />
            )}

            {activeTab === 'analyze' && (
              <AnalyzeView setActiveTab={setActiveTab} />
            )}

            {activeTab === 'investigations' && (
              <InvestigationsView 
                initialCase={selectedCase} 
                setActiveTab={setActiveTab} 
                onSelectCase={handleSelectCase}
              />
            )}

            {activeTab === 'intel' && (
              <IntelView 
                setActiveTab={setActiveTab}
                onSelectCase={handleSelectCase}
              />
            )}

            {activeTab === 'reports' && (
              <ReportsView 
                initialCaseId={selectedCase?.case_id}
                onSelectCase={handleSelectCase}
              />
            )}


            {activeTab === 'models' && (
              <ModelManagementView />
            )}

            {activeTab === 'settings' && (
              <SettingsView />
            )}
          </div>
        </main>
      </div>
    </div>
  );
}

export default App;
