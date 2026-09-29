'use client';

import React, { useState } from 'react';
import { TargetSpec, VulnerabilityFinding, OrchestrationStep, OOBToken } from '@/types';
import { TARGET_PRESETS } from '@/lib/data/presets';
import { Header } from '@/components/Header';
import { TargetSelector } from '@/components/TargetSelector';
import { ToolCatalog } from '@/components/ToolCatalog';
import { OrchestrationCanvas } from '@/components/OrchestrationCanvas';
import { OracleTelemetry } from '@/components/OracleTelemetry';
import { VulnerabilityDossier } from '@/components/VulnerabilityDossier';
import { PatchStudio } from '@/components/PatchStudio';

export default function Home() {
  const [selectedTarget, setSelectedTarget] = useState<TargetSpec>(TARGET_PRESETS[0]);
  const [selectedVectors, setSelectedVectors] = useState<string[]>([
    'ssrf_canary',
    'mcp_privilege_escalation',
    'excessive_agency',
  ]);
  const [isRunning, setIsRunning] = useState<boolean>(false);
  const [steps, setSteps] = useState<OrchestrationStep[]>([]);
  const [canaryTokens, setCanaryTokens] = useState<OOBToken[]>([]);
  const [findings, setFindings] = useState<VulnerabilityFinding[]>([]);
  const [selectedFinding, setSelectedFinding] = useState<VulnerabilityFinding | null>(null);

  const handleToggleVector = (vectorId: string) => {
    setSelectedVectors((prev) =>
      prev.includes(vectorId) ? prev.filter((v) => v !== vectorId) : [...prev, vectorId]
    );
  };

  const handleLaunchCampaign = async () => {
    setIsRunning(true);
    setSteps([]);
    setCanaryTokens([]);
    setFindings([]);
    setSelectedFinding(null);

    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target: selectedTarget,
          selectedVectors,
        }),
      });

      const data = await res.json();
      if (data.success) {
        setSteps(data.steps || []);
        setCanaryTokens(data.canaryTokens || []);
        setFindings(data.findings || []);
        if (data.findings && data.findings.length > 0) {
          setSelectedFinding(data.findings[0]);
        }
      }
    } catch (err) {
      console.error('Scan error:', err);
    } finally {
      setIsRunning(false);
    }
  };

  const handleExportSarif = async () => {
    if (findings.length === 0) return;

    try {
      const res = await fetch('/api/export-sarif', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          findings,
          targetName: selectedTarget.name,
        }),
      });

      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `isihlangu_${selectedTarget.name.toLowerCase().replace(/\s+/g, '_')}.sarif`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      a.remove();
    } catch (err) {
      console.error('SARIF export error:', err);
    }
  };

  return (
    <div className="min-h-screen cyber-bg text-slate-100 flex flex-col">
      <Header onExportSarif={handleExportSarif} hasFindings={findings.length > 0} />

      <main className="flex-1 max-w-7xl w-full mx-auto p-4 sm:p-6 lg:p-8 space-y-6">
        {/* Row 1: Target Selector & Scope Invariants */}
        <TargetSelector
          selectedTarget={selectedTarget}
          onSelectTarget={(target) => {
            setSelectedTarget(target);
            setFindings([]);
            setSteps([]);
            setSelectedFinding(null);
          }}
          onUpdateTarget={(updated) => {
            setSelectedTarget(updated);
            setFindings([]);
            setSteps([]);
            setSelectedFinding(null);
          }}
        />

        {/* Row 2: Tool Catalog (MCP Introspection & Deficiencies) */}
        <ToolCatalog tools={selectedTarget.tools} />

        {/* Row 3: Multi-Agent Orchestration Canvas */}
        <OrchestrationCanvas
          isRunning={isRunning}
          onLaunchCampaign={handleLaunchCampaign}
          selectedVectors={selectedVectors}
          onToggleVector={handleToggleVector}
        />

        {/* Row 4: Execution Stream & Out-of-Band Canary Radar */}
        <OracleTelemetry
          steps={steps}
          canaryTokens={canaryTokens}
          isRunning={isRunning}
        />

        {/* Row 5: Vulnerability Dossier & Patch Studio */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 items-start">
          <VulnerabilityDossier
            findings={findings}
            selectedFinding={selectedFinding}
            onSelectFinding={(f) => setSelectedFinding(f)}
          />

          <PatchStudio finding={selectedFinding} />
        </div>
      </main>

      <footer className="border-t border-slate-900/80 py-6 text-center text-xs text-slate-500 font-mono">
        Isihlangu: The Shield • Deterministic Agentic SaaS Security Evaluation Engine • Zero Refusal Bias
      </footer>
    </div>
  );
}
