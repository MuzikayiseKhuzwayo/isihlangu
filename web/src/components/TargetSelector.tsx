'use client';

import React, { useState, useEffect } from 'react';
import { TargetSpec, TargetType, MCPToolDefinition } from '@/types';
import { TARGET_PRESETS } from '@/lib/data/presets';
import { auditTool } from '@/lib/audit';
import {
  Server,
  Globe,
  ShieldCheck,
  Box,
  Edit3,
  Check,
  RotateCcw,
  PlusCircle,
  FileCode,
  AlertCircle,
  Sliders,
} from 'lucide-react';

interface TargetSelectorProps {
  selectedTarget: TargetSpec;
  onSelectTarget: (target: TargetSpec) => void;
  onUpdateTarget: (target: TargetSpec) => void;
}

export const TargetSelector: React.FC<TargetSelectorProps> = ({
  selectedTarget,
  onSelectTarget,
  onUpdateTarget,
}) => {
  const [isEditing, setIsEditing] = useState(false);
  const [formName, setFormName] = useState(selectedTarget.name);
  const [formType, setFormType] = useState<TargetType>(selectedTarget.target_type);
  const [formBaseUrl, setFormBaseUrl] = useState(selectedTarget.base_url);
  const [formDomains, setFormDomains] = useState(selectedTarget.allowed_domains.join(', '));
  const [formCidrs, setFormCidrs] = useState(selectedTarget.allowed_cidrs.join(', '));
  const [formToolsJson, setFormToolsJson] = useState(
    JSON.stringify(selectedTarget.tools, null, 2)
  );
  const [jsonError, setJsonError] = useState<string | null>(null);

  // Sync state whenever selectedTarget changes externally
  useEffect(() => {
    setFormName(selectedTarget.name);
    setFormType(selectedTarget.target_type);
    setFormBaseUrl(selectedTarget.base_url);
    setFormDomains(selectedTarget.allowed_domains.join(', '));
    setFormCidrs(selectedTarget.allowed_cidrs.join(', '));
    setFormToolsJson(JSON.stringify(selectedTarget.tools, null, 2));
    setJsonError(null);
  }, [selectedTarget]);

  const handleApplyChanges = () => {
    try {
      setJsonError(null);
      let parsedTools: MCPToolDefinition[] = [];
      if (formToolsJson.trim()) {
        const raw = JSON.parse(formToolsJson);
        const list = Array.isArray(raw) ? raw : raw.tools || [];
        parsedTools = list.map((t: MCPToolDefinition) => auditTool(t));
      }

      const updated: TargetSpec = {
        ...selectedTarget,
        name: formName.trim() || 'Custom Target',
        target_type: formType,
        base_url: formBaseUrl.trim() || 'http://127.0.0.1:8000',
        allowed_domains: formDomains
          .split(',')
          .map((d) => d.trim().toLowerCase())
          .filter(Boolean),
        allowed_cidrs: formCidrs
          .split(',')
          .map((c) => c.trim())
          .filter(Boolean),
        tools: parsedTools,
      };

      onUpdateTarget(updated);
      setIsEditing(false);
    } catch (e: any) {
      setJsonError(e.message || 'Invalid JSON format in tools definition');
    }
  };

  const handleResetPreset = () => {
    const original = TARGET_PRESETS.find((p) => p.id === selectedTarget.id) || TARGET_PRESETS[0];
    onSelectTarget(original);
    setIsEditing(false);
  };

  const handleCreateNewCustom = () => {
    const custom: TargetSpec = {
      id: `custom_${Date.now().toString(36)}`,
      name: 'Custom Target',
      target_type: 'mcp_server',
      base_url: 'http://localhost:8000',
      allowed_domains: ['localhost', '127.0.0.1'],
      allowed_cidrs: ['127.0.0.1/32'],
      tools: [
        {
          name: 'custom_service_tool',
          description: 'Custom service tool ready for evaluation',
          input_schema: {
            type: 'object',
            properties: {
              url: { type: 'string' },
            },
            required: ['url'],
          },
        },
      ],
    };
    onSelectTarget(custom);
    setIsEditing(true);
  };

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
            Select, edit parameters, or define custom endpoints for security evaluation.
          </p>
        </div>

        {/* Preset Selector & Edit Toggle */}
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs text-slate-400 font-mono">Preset:</span>
          <div className="flex gap-1.5 p-1 rounded-xl bg-slate-950/80 border border-slate-800">
            {TARGET_PRESETS.map((preset) => {
              const isSelected = selectedTarget.id === preset.id;
              return (
                <button
                  key={preset.id}
                  onClick={() => {
                    onSelectTarget(preset);
                    setIsEditing(false);
                  }}
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

          <button
            onClick={handleCreateNewCustom}
            title="Create Custom Target"
            className="flex items-center gap-1.5 px-3 py-1 text-xs rounded-xl bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-700 font-mono transition-all cursor-pointer"
          >
            <PlusCircle className="w-3.5 h-3.5 text-cyan-400" />
            <span>New</span>
          </button>

          <button
            onClick={() => setIsEditing(!isEditing)}
            className={`flex items-center gap-1.5 px-3 py-1 text-xs rounded-xl font-mono font-semibold transition-all cursor-pointer border ${
              isEditing
                ? 'bg-cyan-500 text-slate-950 border-cyan-400 font-bold shadow-md shadow-cyan-500/20'
                : 'bg-slate-900/80 hover:bg-slate-800 text-cyan-300 border-cyan-500/30'
            }`}
          >
            <Sliders className="w-3.5 h-3.5" />
            <span>{isEditing ? 'Close Editor' : 'Edit Target & Scope'}</span>
          </button>
        </div>
      </div>

      {/* Editing Mode Drawer */}
      {isEditing ? (
        <div className="p-4 rounded-xl bg-slate-950/90 border border-cyan-500/30 space-y-4 animate-in fade-in duration-200">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3.5">
            <div>
              <label className="text-[11px] font-mono text-slate-400 uppercase tracking-wider block mb-1">
                Target Name
              </label>
              <input
                type="text"
                value={formName}
                onChange={(e) => setFormName(e.target.value)}
                className="w-full px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-700 text-white text-xs font-mono focus:border-cyan-400 focus:outline-none"
                placeholder="e.g. My Production MCP Server"
              />
            </div>

            <div>
              <label className="text-[11px] font-mono text-slate-400 uppercase tracking-wider block mb-1">
                Architecture Type
              </label>
              <select
                value={formType}
                onChange={(e) => setFormType(e.target.value as TargetType)}
                className="w-full px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-700 text-white text-xs font-mono focus:border-cyan-400 focus:outline-none"
              >
                <option value="mcp_server">MCP Server (JSON-RPC 2.0)</option>
                <option value="rest_api">REST / OpenAPI Gateway</option>
                <option value="agent_pipeline">Agentic Pipeline Harness</option>
              </select>
            </div>

            <div>
              <label className="text-[11px] font-mono text-slate-400 uppercase tracking-wider block mb-1">
                Target Base URL
              </label>
              <input
                type="text"
                value={formBaseUrl}
                onChange={(e) => setFormBaseUrl(e.target.value)}
                className="w-full px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-700 text-white text-xs font-mono focus:border-cyan-400 focus:outline-none"
                placeholder="e.g. http://localhost:8000"
              />
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
            <div>
              <label className="text-[11px] font-mono text-slate-400 uppercase tracking-wider block mb-1">
                Whitelisted Domains (comma-separated scope)
              </label>
              <input
                type="text"
                value={formDomains}
                onChange={(e) => setFormDomains(e.target.value)}
                className="w-full px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-700 text-emerald-400 text-xs font-mono focus:border-cyan-400 focus:outline-none"
                placeholder="localhost, 127.0.0.1, api.internal"
              />
            </div>

            <div>
              <label className="text-[11px] font-mono text-slate-400 uppercase tracking-wider block mb-1">
                Allowed CIDRs (comma-separated subnets)
              </label>
              <input
                type="text"
                value={formCidrs}
                onChange={(e) => setFormCidrs(e.target.value)}
                className="w-full px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-700 text-amber-300 text-xs font-mono focus:border-cyan-400 focus:outline-none"
                placeholder="127.0.0.1/32, 10.0.0.0/8"
              />
            </div>
          </div>

          {/* Tools JSON Definition Editor */}
          <div>
            <div className="flex items-center justify-between mb-1">
              <label className="text-[11px] font-mono text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
                <FileCode className="w-3.5 h-3.5 text-cyan-400" />
                <span>MCP Tools Specification (JSON Array or {`{"tools": [...]}`})</span>
              </label>
              <span className="text-[11px] text-slate-500 font-mono">
                Paste real tool definitions from your target MCP server
              </span>
            </div>
            <textarea
              value={formToolsJson}
              onChange={(e) => setFormToolsJson(e.target.value)}
              rows={7}
              className="w-full p-3 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 font-mono text-xs focus:border-cyan-400 focus:outline-none leading-relaxed"
              placeholder='[ { "name": "my_tool", "description": "...", "inputSchema": { ... } } ]'
            />
            {jsonError && (
              <div className="flex items-center gap-1.5 mt-1.5 text-xs text-rose-400 font-mono">
                <AlertCircle className="w-3.5 h-3.5 shrink-0" />
                <span>{jsonError}</span>
              </div>
            )}
          </div>

          {/* Save & Reset Actions */}
          <div className="flex items-center justify-between pt-2 border-t border-slate-800">
            <button
              onClick={handleResetPreset}
              className="flex items-center gap-1 px-3 py-1.5 rounded-lg text-xs font-mono text-slate-400 hover:text-white hover:bg-slate-900 transition-colors cursor-pointer"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              <span>Reset Preset Defaults</span>
            </button>

            <div className="flex items-center gap-2">
              <button
                onClick={() => setIsEditing(false)}
                className="px-3 py-1.5 rounded-lg text-xs font-mono text-slate-400 hover:text-slate-200 transition-colors cursor-pointer"
              >
                Cancel
              </button>
              <button
                onClick={handleApplyChanges}
                className="flex items-center gap-1.5 px-4 py-1.5 rounded-lg bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-mono text-xs font-bold transition-all shadow-md shadow-cyan-500/20 cursor-pointer"
              >
                <Check className="w-4 h-4" />
                <span>Save & Apply Target</span>
              </button>
            </div>
          </div>
        </div>
      ) : (
        /* Summary View */
        <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
          <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800/80">
            <div className="flex items-center gap-1.5 text-xs text-slate-400 mb-1">
              <Box className="w-3.5 h-3.5 text-cyan-400" />
              <span>Target Architecture</span>
            </div>
            <p className="font-mono text-xs text-white font-semibold capitalize">
              {selectedTarget.target_type.replace('_', ' ')}
            </p>
            <span className="text-[11px] text-cyan-400/80 font-mono truncate block">
              {selectedTarget.name}
            </span>
          </div>

          <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800/80">
            <div className="flex items-center gap-1.5 text-xs text-slate-400 mb-1">
              <Globe className="w-3.5 h-3.5 text-purple-400" />
              <span>Endpoint Base URL</span>
            </div>
            <p className="font-mono text-xs text-white font-semibold truncate">
              {selectedTarget.base_url}
            </p>
            <span className="text-[11px] text-slate-500 font-mono">Gateway Listener</span>
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
            <span className="text-[11px] text-slate-500 font-mono">Internal Subnets</span>
          </div>
        </div>
      )}
    </div>
  );
};
