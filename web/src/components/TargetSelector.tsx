'use client';

import React from 'react';
import { TargetSpec } from '@/types';
import { TARGET_PRESETS } from '@/lib/data/presets';
import { Server, Globe, ShieldCheck, Box } from 'lucide-react';

interface TargetSelectorProps {
  selectedTarget: TargetSpec;
  onSelectTarget: (target: TargetSpec) => void;
}

export const TargetSelector: React.FC<TargetSelectorProps> = ({
  selectedTarget,
  onSelectTarget,
}) => {
  return (
    <div className="glass-panel rounded-2xl p-5 border border-cyan-500/20">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-4 pb-3 border-b border-slate-800/80">
        <div>
          <div className="flex items-center gap-2">
            <Server className="w-4 h-4 text-cyan-400" />
            <h2 className="text-sm font-bold tracking-wide uppercase text-white font-mono">
              Target Infrastructure & Scope
            </h2>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Select or customize an agentic target to introspect and evaluate.
          </p>
        </div>

        {/* Preset Selector */}
        <div className="flex items-center gap-2">
          <span className="text-xs text-slate-400 font-mono">Preset:</span>
          <div className="flex gap-1.5 p-1 rounded-xl bg-slate-950/80 border border-slate-800">
            {TARGET_PRESETS.map((preset) => {
              const isSelected = selectedTarget.id === preset.id;
              return (
                <button
                  key={preset.id}
                  onClick={() => onSelectTarget(preset)}
                  className={`px-3 py-1 text-xs rounded-lg font-medium transition-all duration-200 cursor-pointer ${
                    isSelected
                      ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm shadow-cyan-500/20 font-semibold'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60'
                  }`}
                >
                  {preset.name}
                </button>
              );
            })}
          </div>
        </div>
      </div>

      {/* Target Spec Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
        <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800/80">
          <div className="flex items-center gap-1.5 text-xs text-slate-400 mb-1">
            <Box className="w-3.5 h-3.5 text-cyan-400" />
            <span>Target Architecture</span>
          </div>
          <p className="font-mono text-xs text-white font-semibold capitalize">
            {selectedTarget.target_type.replace('_', ' ')}
          </p>
          <span className="text-[11px] text-cyan-400/80 font-mono">{selectedTarget.name}</span>
        </div>

        <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800/80">
          <div className="flex items-center gap-1.5 text-xs text-slate-400 mb-1">
            <Globe className="w-3.5 h-3.5 text-purple-400" />
            <span>Endpoint Base URL</span>
          </div>
          <p className="font-mono text-xs text-white font-semibold truncate">
            {selectedTarget.base_url}
          </p>
          <span className="text-[11px] text-slate-500 font-mono">JSON-RPC / REST Gateway</span>
        </div>

        <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800/80">
          <div className="flex items-center gap-1.5 text-xs text-slate-400 mb-1">
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
            <span>Whitelisted Domains</span>
          </div>
          <p className="font-mono text-xs text-emerald-400 font-semibold truncate">
            {selectedTarget.allowed_domains.join(', ')}
          </p>
          <span className="text-[11px] text-slate-500 font-mono">Scope Egress Gate Active</span>
        </div>

        <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800/80">
          <div className="flex items-center gap-1.5 text-xs text-slate-400 mb-1">
            <Server className="w-3.5 h-3.5 text-amber-400" />
            <span>Allowed CIDR Ranges</span>
          </div>
          <p className="font-mono text-xs text-amber-300 font-semibold truncate">
            {selectedTarget.allowed_cidrs.join(', ')}
          </p>
          <span className="text-[11px] text-slate-500 font-mono">Internal Network Subnets</span>
        </div>
      </div>
    </div>
  );
};
