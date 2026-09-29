'use client';

import React from 'react';
import { Shield, Radio, Lock, Download, CheckCircle2 } from 'lucide-react';

interface HeaderProps {
  onExportSarif: () => void;
  hasFindings: boolean;
}

export const Header: React.FC<HeaderProps> = ({ onExportSarif, hasFindings }) => {
  return (
    <header className="sticky top-0 z-50 w-full glass-panel border-b border-cyan-500/20 backdrop-blur-xl px-6 py-3.5">
      <div className="max-w-7xl mx-auto flex items-center justify-between">
        {/* Brand & Emblem */}
        <div className="flex items-center gap-3">
          <div className="relative flex items-center justify-center w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500/20 to-blue-600/30 border border-cyan-400/40 shadow-lg shadow-cyan-500/20">
            <Shield className="w-5 h-5 text-cyan-400" />
            <div className="absolute inset-0 rounded-xl bg-cyan-400/10 blur-sm -z-10" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-extrabold tracking-tight text-lg text-white font-mono">
                ISIHLANGU
              </span>
              <span className="text-[11px] px-2 py-0.5 rounded-full font-mono bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 font-semibold tracking-wider uppercase">
                The Shield
              </span>
            </div>
            <p className="text-xs text-slate-400">Agentic SaaS Security Evaluation & Testing Harness</p>
          </div>
        </div>

        {/* Telemetry Status Indicators */}
        <div className="hidden lg:flex items-center gap-3">
          {/* Canary Listener Status */}
          <div className="flex items-center gap-2 px-3 py-1 rounded-lg bg-slate-900/80 border border-slate-700/60 text-xs">
            <div className="relative flex h-2 w-2">
              <span className="radar-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
              <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500" />
            </div>
            <span className="text-slate-400">OOB Canary:</span>
            <span className="font-mono text-emerald-400 font-semibold">:8877 LISTENING</span>
          </div>

          {/* Scope Guardrail Status */}
          <div className="flex items-center gap-2 px-3 py-1 rounded-lg bg-slate-900/80 border border-slate-700/60 text-xs">
            <Lock className="w-3.5 h-3.5 text-cyan-400" />
            <span className="text-slate-400">Scope Gate:</span>
            <span className="font-mono text-cyan-400 font-semibold">STRICT ENFORCED</span>
          </div>

          {/* Verification Engine */}
          <div className="flex items-center gap-2 px-3 py-1 rounded-lg bg-slate-900/80 border border-slate-700/60 text-xs">
            <CheckCircle2 className="w-3.5 h-3.5 text-purple-400" />
            <span className="text-slate-400">Oracle:</span>
            <span className="font-mono text-purple-400 font-semibold">ZERO-HALLUCINATION</span>
          </div>
        </div>

        {/* Action Buttons */}
        <div className="flex items-center gap-3">
          <button
            onClick={onExportSarif}
            disabled={!hasFindings}
            className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all duration-200 border ${
              hasFindings
                ? 'bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 border-cyan-500/40 shadow-lg shadow-cyan-500/10 cursor-pointer'
                : 'bg-slate-800/40 text-slate-500 border-slate-800 cursor-not-allowed'
            }`}
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export SARIF 2.1.0</span>
          </button>
        </div>
      </div>
    </header>
  );
};
