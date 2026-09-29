'use client';

import React, { useState } from 'react';
import { VulnerabilityFinding } from '@/types';
import { Sparkles, Copy, Check, FileCode, Database, ShieldCheck } from 'lucide-react';

interface PatchStudioProps {
  finding: VulnerabilityFinding | null;
}

export const PatchStudio: React.FC<PatchStudioProps> = ({ finding }) => {
  const [activeTab, setActiveTab] = useState<'schema' | 'rls'>('schema');
  const [copied, setCopied] = useState(false);

  if (!finding) {
    return (
      <div className="glass-panel rounded-2xl p-6 border border-cyan-500/20 text-center py-16">
        <Sparkles className="w-8 h-8 text-cyan-400 mx-auto mb-2 opacity-50" />
        <h3 className="text-sm font-bold font-mono text-white">Remediation Patch Studio</h3>
        <p className="text-xs text-slate-400 max-w-sm mx-auto mt-1">
          Select any finding from the dossier to inspect its auto-synthesized JSON schema constraints or Supabase Row-Level Security policies.
        </p>
      </div>
    );
  }

  const schemaContent = finding.remediation_patch?.schema_patch
    ? JSON.stringify(finding.remediation_patch.schema_patch, null, 2)
    : '// No schema patch required for this vector';

  const rlsContent = finding.remediation_patch?.rls_sql || `-- No SQL RLS patch generated for this vector`;

  const currentCode = activeTab === 'schema' ? schemaContent : rlsContent;

  const handleCopy = () => {
    navigator.clipboard.writeText(currentCode);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="glass-panel rounded-2xl p-5 border border-cyan-500/20">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4 pb-3 border-b border-slate-800/80">
        <div>
          <div className="flex items-center gap-2">
            <Sparkles className="w-4 h-4 text-cyan-400" />
            <h2 className="text-sm font-bold tracking-wide uppercase text-white font-mono">
              Verifiable Remediation Studio
            </h2>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Auto-synthesized patches targeting <strong className="text-cyan-300 font-mono">{finding.target_tool}</strong>
          </p>
        </div>

        {/* Tab & Copy Actions */}
        <div className="flex items-center gap-2">
          <div className="flex gap-1 p-1 rounded-xl bg-slate-950/80 border border-slate-800">
            <button
              onClick={() => setActiveTab('schema')}
              className={`flex items-center gap-1.5 px-3 py-1 text-xs rounded-lg font-mono transition-all cursor-pointer ${
                activeTab === 'schema'
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-bold'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              <FileCode className="w-3.5 h-3.5" />
              <span>MCP Schema Patch</span>
            </button>
            <button
              onClick={() => setActiveTab('rls')}
              className={`flex items-center gap-1.5 px-3 py-1 text-xs rounded-lg font-mono transition-all cursor-pointer ${
                activeTab === 'rls'
                  ? 'bg-purple-500/20 text-purple-300 border border-purple-500/40 font-bold'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              <Database className="w-3.5 h-3.5" />
              <span>PostgreSQL RLS SQL</span>
            </button>
          </div>

          <button
            onClick={handleCopy}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-white text-xs font-mono font-semibold transition-all cursor-pointer border border-slate-700"
          >
            {copied ? (
              <>
                <Check className="w-3.5 h-3.5 text-emerald-400" />
                <span className="text-emerald-400">COPIED</span>
              </>
            ) : (
              <>
                <Copy className="w-3.5 h-3.5" />
                <span>COPY</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Code Viewer */}
      <div className="relative rounded-xl bg-slate-950/90 border border-slate-800/90 p-4 font-mono text-xs overflow-x-auto max-h-96">
        <pre className="text-slate-300 leading-relaxed">
          <code>{currentCode}</code>
        </pre>
      </div>

      {/* Rationale & Defense Summary */}
      <div className="mt-3.5 p-3 rounded-xl bg-slate-950/60 border border-slate-800/80 flex items-start gap-2 text-xs">
        <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
        <p className="text-slate-400 leading-snug">
          <strong className="text-slate-200">Defense Invariant:</strong> Applying this patch enforces strict domain regex matching and tenant boundaries directly at the schema validation layer before parameters are passed to execution tools.
        </p>
      </div>
    </div>
  );
};
