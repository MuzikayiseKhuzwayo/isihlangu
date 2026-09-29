'use client';

import React from 'react';
import { Play, Sparkles, Cpu, Crosshair, Radio, GitBranch, AlertTriangle } from 'lucide-react';

interface OrchestrationCanvasProps {
  isRunning: boolean;
  onLaunchCampaign: () => void;
  selectedVectors: string[];
  onToggleVector: (vector: string) => void;
  executionMode: 'simulate' | 'live';
  onToggleExecutionMode: (mode: 'simulate' | 'live') => void;
}

export const OrchestrationCanvas: React.FC<OrchestrationCanvasProps> = ({
  isRunning,
  onLaunchCampaign,
  selectedVectors,
  onToggleVector,
  executionMode,
  onToggleExecutionMode,
}) => {
  const attackVectors = [
    {
      id: 'ssrf_canary',
      label: 'SSRF via OOB Canary',
      owasp: 'API07 / SSRF',
      desc: 'Generates unique cryptographic UUID tokens to detect blind egress.',
    },
    {
      id: 'mcp_privilege_escalation',
      label: 'Tenant Isolation / BOLA',
      owasp: 'LLM06 / BOLA',
      desc: 'Probes tool parameters for cross-tenant ID mutation vulnerabilities.',
    },
    {
      id: 'excessive_agency',
      label: 'Excessive Agency Audit',
      owasp: 'LLM06 / Agency',
      desc: 'Checks for unconstrained database query or destructive shell execution tools.',
    },
    {
      id: 'indirect_prompt_injection',
      label: 'RAG Context Poisoning',
      owasp: 'LLM01 / Injection',
      desc: 'Tests semantic prompt overrides in dynamic context retrieval pipelines.',
    },
  ];

  return (
    <div className="glass-panel rounded-2xl p-5 border border-cyan-500/20">
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 mb-5 pb-3 border-b border-slate-800/80">
        <div>
          <div className="flex items-center gap-2">
            <GitBranch className="w-4 h-4 text-cyan-400" />
            <h2 className="text-sm font-bold tracking-wide uppercase text-white font-mono">
              Multi-Agent Orchestration Pipeline
            </h2>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Hierarchical reasoning workflow powered by abliterated security models.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          {/* Execution Mode Selector */}
          <div className="flex items-center gap-1 bg-slate-950/80 p-1 rounded-xl border border-slate-800/80">
            <button
              type="button"
              onClick={() => onToggleExecutionMode('simulate')}
              className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-all cursor-pointer ${
                executionMode === 'simulate'
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Simulation Benchmark
            </button>
            <button
              type="button"
              onClick={() => onToggleExecutionMode('live')}
              className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-all flex items-center gap-1.5 cursor-pointer ${
                executionMode === 'live'
                  ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <span className={`w-2 h-2 rounded-full ${executionMode === 'live' ? 'bg-amber-400 animate-pulse' : 'bg-slate-500'}`} />
              Live Target Network
            </button>
          </div>

          {/* Primary Launch Action */}
          <button
            onClick={onLaunchCampaign}
            disabled={isRunning || selectedVectors.length === 0}
            className={`flex items-center gap-2 px-5 py-2.5 rounded-xl font-mono text-xs font-bold transition-all duration-300 shadow-lg cursor-pointer ${
              isRunning
                ? 'bg-cyan-500/30 text-cyan-200 border border-cyan-400/50 cursor-wait animate-pulse'
                : executionMode === 'live'
                ? 'bg-gradient-to-r from-amber-500 to-orange-600 hover:from-amber-400 hover:to-orange-500 text-slate-950 shadow-amber-500/25 hover:shadow-amber-500/40 hover:scale-[1.02]'
                : 'bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 shadow-cyan-500/25 hover:shadow-cyan-500/40 hover:scale-[1.02]'
            }`}
          >
            {isRunning ? (
              <>
                <div className="w-4 h-4 rounded-full border-2 border-slate-950 border-t-transparent animate-spin" />
                <span>ORCHESTRATING CAMPAIGN...</span>
              </>
            ) : (
              <>
                <Play className="w-4 h-4 fill-current" />
                <span>LAUNCH {executionMode === 'live' ? 'LIVE' : 'BENCHMARK'} EVALUATION</span>
              </>
            )}
          </button>
        </div>
      </div>

      {executionMode === 'live' && (
        <div className="mb-4 p-3 rounded-xl bg-amber-950/30 border border-amber-500/30 flex items-start gap-2.5 text-xs text-amber-300/90 font-mono">
          <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
          <div>
            <span className="font-bold text-amber-200">LIVE NETWORK DISPATCH ACTIVE: </span>
            Requests will be transmitted directly to the target endpoint. OOB canaries will be registered and polled against the local Oracle listener (127.0.0.1:8877). Ensure <code className="text-amber-300">uv run isihlangu run-canary</code> is running in background.
          </div>
        </div>
      )}

      {/* Visual Pipeline Nodes */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-3 mb-5">
        {/* Node 1: The Strategist */}
        <div className="p-3.5 rounded-xl bg-slate-950/70 border border-purple-500/30 relative overflow-hidden">
          <div className="flex items-center justify-between mb-2">
            <span className="text-[10px] font-mono uppercase tracking-wider text-purple-400 font-bold">
              Node 1: Strategist
            </span>
            <Cpu className="w-3.5 h-3.5 text-purple-400" />
          </div>
          <p className="font-mono text-xs font-bold text-white mb-1">
            Qwen-2.5-32B Abliterated
          </p>
          <p className="text-[11px] text-slate-400 leading-snug">
            Analyzes schemas, detects authorization boundaries, formulates hypotheses without refusals.
          </p>
        </div>

        {/* Node 2: The Operator */}
        <div className="p-3.5 rounded-xl bg-slate-950/70 border border-cyan-500/30 relative overflow-hidden">
          <div className="flex items-center justify-between mb-2">
            <span className="text-[10px] font-mono uppercase tracking-wider text-cyan-400 font-bold">
              Node 2: Operator
            </span>
            <Crosshair className="w-3.5 h-3.5 text-cyan-400" />
          </div>
          <p className="font-mono text-xs font-bold text-white mb-1">
            Qwen-7B Code Specialist
          </p>
          <p className="text-[11px] text-slate-400 leading-snug">
            Synthesizes strict JSON-RPC calls, HTTP parameters, and canary tokens with scope compliance.
          </p>
        </div>

        {/* Node 3: Execution Oracle */}
        <div className="p-3.5 rounded-xl bg-slate-950/70 border border-emerald-500/30 relative overflow-hidden">
          <div className="flex items-center justify-between mb-2">
            <span className="text-[10px] font-mono uppercase tracking-wider text-emerald-400 font-bold">
              Node 3: Execution Oracle
            </span>
            <Radio className="w-3.5 h-3.5 text-emerald-400" />
          </div>
          <p className="font-mono text-xs font-bold text-white mb-1">
            OOB Canary & State Diff
          </p>
          <p className="text-[11px] text-slate-400 leading-snug">
            Zero-hallucination guarantee: Confirms vulnerabilities only via network pings or live DB diffs.
          </p>
        </div>

        {/* Node 4: Remediation Engine */}
        <div className="p-3.5 rounded-xl bg-slate-950/70 border border-blue-500/30 relative overflow-hidden">
          <div className="flex items-center justify-between mb-2">
            <span className="text-[10px] font-mono uppercase tracking-wider text-blue-400 font-bold">
              Node 4: Patch Synthesizer
            </span>
            <Sparkles className="w-3.5 h-3.5 text-blue-400" />
          </div>
          <p className="font-mono text-xs font-bold text-white mb-1">
            Deterministic Patching
          </p>
          <p className="text-[11px] text-slate-400 leading-snug">
            Synthesizes strict JSON schema regex constraints and Supabase RLS SQL policies.
          </p>
        </div>
      </div>

      {/* Attack Vector Matrix Selector */}
      <div>
        <span className="text-xs font-mono text-slate-400 uppercase tracking-wider block mb-2 font-semibold">
          Active Evaluation Vectors ({selectedVectors.length}/{attackVectors.length})
        </span>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5">
          {attackVectors.map((vec) => {
            const isSelected = selectedVectors.includes(vec.id);
            return (
              <button
                key={vec.id}
                onClick={() => onToggleVector(vec.id)}
                className={`p-3 rounded-xl border text-left transition-all duration-200 cursor-pointer flex flex-col justify-between ${
                  isSelected
                    ? 'bg-slate-900/90 border-cyan-500/50 shadow-md shadow-cyan-500/10'
                    : 'bg-slate-950/40 border-slate-800/60 opacity-60 hover:opacity-90'
                }`}
              >
                <div>
                  <div className="flex items-center justify-between gap-1 mb-1">
                    <span className="font-mono text-xs font-bold text-white">
                      {vec.label}
                    </span>
                    <span className="text-[10px] font-mono text-cyan-400 px-1.5 py-0.2 bg-cyan-950/80 rounded border border-cyan-800/40">
                      {vec.owasp}
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400 leading-tight">
                    {vec.desc}
                  </p>
                </div>
                <div className="mt-2 pt-1.5 flex items-center justify-between text-[10px] font-mono">
                  <span className={isSelected ? 'text-cyan-400 font-bold' : 'text-slate-500'}>
                    {isSelected ? '✓ ACTIVE' : '○ DISABLED'}
                  </span>
                </div>
              </button>
            );
          })}
        </div>
      </div>
    </div>
  );
};
