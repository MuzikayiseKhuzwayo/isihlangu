export type TargetType = 'mcp_server' | 'rest_api' | 'agent_pipeline';

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export interface MCPToolDefinition {
  name: string;
  description: string;
  input_schema: {
    type?: string;
    properties?: Record<string, any>;
    required?: string[];
  };
  is_sensitive?: boolean;
  deficiencies?: string[];
}

export interface TargetSpec {
  id: string;
  name: string;
  target_type: TargetType;
  base_url: string;
  allowed_domains: string[];
  allowed_cidrs: string[];
  tools: MCPToolDefinition[];
}

export interface AttackHypothesis {
  id: string;
  category: 'ssrf_canary' | 'mcp_privilege_escalation' | 'excessive_agency' | 'indirect_prompt_injection';
  description: string;
  target_component: string;
  proposed_test: string;
  status: 'unverified' | 'verified' | 'refuted';
}

export interface OOBToken {
  token_uuid: string;
  expected_type: string;
  target_component: string;
  callback_received: boolean;
  callback_source_ip?: string;
  callback_payload?: string;
  timestamp: string;
}

export interface VulnerabilityFinding {
  id: string;
  title: string;
  severity: Severity;
  owasp_category: string;
  description: string;
  target_tool: string;
  evidence: Record<string, any>;
  remediation_patch: {
    schema_patch?: Record<string, any>;
    rls_sql?: string;
  };
  timestamp: string;
}

export interface OrchestrationStep {
  id: string;
  timestamp: string;
  agent: 'Strategist' | 'Operator' | 'Oracle' | 'Remediator';
  action: string;
  status: 'pending' | 'running' | 'completed' | 'warning' | 'error';
  details?: string;
}
