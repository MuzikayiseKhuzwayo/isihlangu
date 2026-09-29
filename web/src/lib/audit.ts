import { MCPToolDefinition } from '@/types';

export function auditTool(tool: MCPToolDefinition): MCPToolDefinition {
  const name = tool.name || 'unnamed_tool';
  const description = tool.description || '';
  const schema = tool.input_schema || { type: 'object', properties: {} };
  const props = schema.properties || {};

  const textCorpus = `${name} ${description} ${JSON.stringify(schema)}`.toLowerCase();
  const sensitiveKeywords = [
    'sql', 'exec', 'bash', 'shell', 'eval', 'file', 'write', 'delete',
    'drop', 'admin', 'user', 'token', 'secret', 'credential', 'payment',
    'stripe', 'webhook', 'ssrf', 'fetch', 'http', 'transfer', 'export',
  ];

  const isSensitive = sensitiveKeywords.some((k) => textCorpus.includes(k));

  const deficiencies: string[] = [];

  for (const [propName, propSpec] of Object.entries(props)) {
    const spec = propSpec as any;
    if (spec.type === 'string') {
      if (!spec.maxLength && !spec.pattern && !spec.enum) {
        deficiencies.push(
          `Unbounded string parameter: '${propName}' has no maxLength, pattern, or enum constraint.`
        );
      }
    }
    if (['id', 'record_id', 'user_id', 'account_id'].includes(propName) && !props.tenant_id && !props.org_id) {
      deficiencies.push(
        `Potential multi-tenant risk: Parameter '${propName}' exists without tenant isolation parameter.`
      );
    }
  }

  if (name.includes('sql') || name.includes('query')) {
    deficiencies.push('Direct database query tool: Unbounded agency allows arbitrary SQL execution.');
  }

  return {
    ...tool,
    name,
    description,
    input_schema: schema,
    is_sensitive: isSensitive,
    deficiencies,
  };
}
