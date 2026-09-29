'use client';

import React from 'react';
import { MCPToolDefinition } from '@/types';
import { Wrench, AlertTriangle, ShieldAlert, CheckCircle, Code } from 'lucide-react';

interface ToolCatalogProps {
  tools: MCPToolDefinition[];
}

export const ToolCatalog: React.FC<ToolCatalogProps> = ({ tools }) => {
  return (
    <div className="glass-panel rounded-2xl p-5 border border-cyan-500/20">
      <div className="flex items-center justify-between mb-4 pb-3 border-b border-slate-800/80">
        <div>
          <div className="flex items-center gap-2">
            <Wrench className="w-4 h-4 text-cyan-400" />
            <h2 className="text-sm font-bold tracking-wide uppercase text-white font-mono">
              Discovered MCP Tools & Introspection ({tools.length})
            </h2>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Model Context Protocol schemas parsed and analyzed for argument vulnerabilities.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
        {tools.map((tool) => {
          const props = tool.input_schema.properties || {};
          const propKeys = Object.keys(props);
          const hasDeficiencies = (tool.deficiencies || []).length > 0;

          return (
            <div
              key={tool.name}
              className="p-4 rounded-xl bg-slate-950/70 border border-slate-800/90 hover:border-cyan-500/30 transition-all duration-200 flex flex-col justify-between"
            >
              <div>
                {/* Header */}
                <div className="flex items-start justify-between gap-2 mb-2">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs font-bold text-cyan-300">
                      {tool.name}
                    </span>
                  </div>
                  {tool.is_sensitive ? (
                    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-500/10 text-rose-400 border border-rose-500/30">
                      <ShieldAlert className="w-3 h-3" />
                      SENSITIVE ACTION
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono text-slate-400 bg-slate-800/40 border border-slate-700/40">
                      <CheckCircle className="w-3 h-3 text-slate-500" />
                      BENIGN
                    </span>
                  )}
                </div>

                {/* Description */}
                <p className="text-xs text-slate-400 line-clamp-2 mb-3">
                  {tool.description}
                </p>

                {/* Parameters */}
                <div className="mb-3">
                  <div className="flex items-center gap-1 text-[11px] text-slate-400 font-mono mb-1">
                    <Code className="w-3 h-3 text-cyan-400" />
                    <span>Parameters ({propKeys.length}):</span>
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    {propKeys.length > 0 ? (
                      propKeys.map((k) => (
                        <span
                          key={k}
                          className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-[11px] font-mono text-slate-300"
                        >
                          {k}
                          {props[k]?.type && (
                            <span className="text-slate-500 ml-1">:{props[k].type}</span>
                          )}
                        </span>
                      ))
                    ) : (
                      <span className="text-[11px] text-slate-500 italic">No parameters required</span>
                    )}
                  </div>
                </div>
              </div>

              {/* Schema Deficiencies Warning */}
              {hasDeficiencies ? (
                <div className="mt-2 pt-2 border-t border-slate-900">
                  <div className="p-2.5 rounded-lg bg-amber-500/10 border border-amber-500/30">
                    <div className="flex items-center gap-1.5 text-[11px] font-mono font-bold text-amber-300 mb-1">
                      <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                      <span>Schema Deficiencies Detected</span>
                    </div>
                    <ul className="space-y-1">
                      {tool.deficiencies?.map((def, idx) => (
                        <li key={idx} className="text-[11px] text-amber-200/90 leading-tight">
                          • {def}
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>
              ) : (
                <div className="mt-2 pt-2 border-t border-slate-900 text-[11px] text-emerald-400/80 font-mono flex items-center gap-1">
                  <CheckCircle className="w-3 h-3 text-emerald-400" />
                  <span>Schema constraints validated</span>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};
