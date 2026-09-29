'use client';

import React from 'react';
import { OrchestrationStep, OOBToken } from '@/types';
import { Radio, Terminal, CheckCircle2, Clock, AlertCircle } from 'lucide-react';

interface OracleTelemetryProps {
  steps: OrchestrationStep[];
  canaryTokens: OOBToken[];
  isRunning: boolean;
}

export const OracleTelemetry: React.FC<OracleTelemetryProps> = ({
  steps,
  canaryTokens,
  isRunning,
}) => {
  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
      {/* Live Orchestration Stream */}
      <div className="lg:col-span-2 glass-panel rounded-2xl p-5 border border-cyan-500/20">
        <div className="flex items-center justify-between mb-4 pb-3 border-b border-slate-800/80">
          <div className="flex items-center gap-2">
            <Terminal className="w-4 h-4 text-cyan-400" />
            <h2 className="text-sm font-bold tracking-wide uppercase text-white font-mono">
              Live Agent Execution Stream
            </h2>
          </div>
          <span className="text-[11px] font-mono text-slate-400">
            {isRunning ? (
              <span className="text-cyan-400 animate-pulse flex items-center gap-1.5 font-bold">
                <span className="w-2 h-2 rounded-full bg-cyan-400" />
                EXECUTION IN PROGRESS
              </span>
            ) : steps.length > 0 ? (
              <span className="text-emerald-400 flex items-center gap-1">
                <CheckCircle2 className="w-3.5 h-3.5" />
                CAMPAIGN CONCLUDED
              </span>
            ) : (
              'IDLE / READY'
            )}
          </span>
        </div>

        <div className="space-y-2.5 max-h-72 overflow-y-auto pr-1">
          {steps.length === 0 ? (
            <div className="py-10 text-center text-slate-500 font-mono text-xs">
              Waiting for campaign launch. Select attack vectors and click 'Launch Evaluation Campaign'.
            </div>
          ) : (
            steps.map((step) => {
              const statusColors = {
                pending: 'text-slate-500',
                running: 'text-cyan-400 animate-pulse font-semibold',
                completed: 'text-emerald-400',
                warning: 'text-amber-400',
                error: 'text-rose-400',
              }[step.status];

              const agentBadges = {
                Strategist: 'bg-purple-500/10 text-purple-300 border-purple-500/30',
                Operator: 'bg-cyan-500/10 text-cyan-300 border-cyan-500/30',
                Oracle: 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30',
                Remediator: 'bg-blue-500/10 text-blue-300 border-blue-500/30',
              }[step.agent];

              return (
                <div
                  key={step.id}
                  className="p-2.5 rounded-lg bg-slate-950/60 border border-slate-800/80 flex items-start justify-between gap-3 text-xs"
                >
                  <div className="flex items-start gap-2.5">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${agentBadges}`}>
                      {step.agent}
                    </span>
                    <div>
                      <p className="text-slate-200 font-medium">{step.action}</p>
                      {step.details && (
                        <p className="text-[11px] font-mono text-slate-400 mt-0.5">
                          {step.details}
                        </p>
                      )}
                    </div>
                  </div>
                  <span className={`font-mono text-[11px] uppercase ${statusColors}`}>
                    {step.status}
                  </span>
                </div>
              );
            })
          )}
        </div>
      </div>

      {/* Out-of-Band Canary Radar */}
      <div className="glass-panel rounded-2xl p-5 border border-cyan-500/20">
        <div className="flex items-center justify-between mb-4 pb-3 border-b border-slate-800/80">
          <div className="flex items-center gap-2">
            <Radio className="w-4 h-4 text-emerald-400" />
            <h2 className="text-sm font-bold tracking-wide uppercase text-white font-mono">
              OOB Canary Radar
            </h2>
          </div>
          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 font-bold">
            LISTENER :8877
          </span>
        </div>

        <p className="text-xs text-slate-400 mb-3">
          Unique cryptographic UUID tokens injected into payloads. Verified only upon receiving a genuine network callback.
        </p>

        <div className="space-y-2.5 max-h-72 overflow-y-auto pr-1">
          {canaryTokens.length === 0 ? (
            <div className="py-8 text-center text-slate-500 font-mono text-xs">
              No active canary tokens deployed yet.
            </div>
          ) : (
            canaryTokens.map((token) => (
              <div
                key={token.token_uuid}
                className="p-3 rounded-xl bg-slate-950/80 border border-slate-800 text-xs flex flex-col gap-1.5"
              >
                <div className="flex items-center justify-between">
                  <span className="font-mono text-[10px] text-cyan-400 truncate max-w-[170px]">
                    UUID: {token.token_uuid}
                  </span>
                  {token.callback_received ? (
                    <span className="px-1.5 py-0.5 rounded text-[9px] font-mono font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
                      ✓ HIT CONFIRMED
                    </span>
                  ) : (
                    <span className="px-1.5 py-0.5 rounded text-[9px] font-mono text-slate-400 bg-slate-800">
                      LISTENING
                    </span>
                  )}
                </div>

                <div className="text-[11px] text-slate-300 flex items-center justify-between">
                  <span className="text-slate-400">Target Tool:</span>
                  <span className="font-mono text-white">{token.target_component}</span>
                </div>

                {token.callback_received && (
                  <div className="text-[10px] font-mono text-emerald-400 bg-emerald-950/40 p-1.5 rounded border border-emerald-800/40">
                    Source: {token.callback_source_ip} | {token.callback_payload}
                  </div>
                )}
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
};
