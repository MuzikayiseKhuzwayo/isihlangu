import { TargetSpec } from '@/types';

export const TARGET_PRESETS: TargetSpec[] = [
  {
    id: 'target_prod_sandbox',
    name: 'Production Agent Sandbox',
    target_type: 'mcp_server',
    base_url: 'http://127.0.0.1:8000',
    allowed_domains: ['localhost', '127.0.0.1', 'api.internal'],
    allowed_cidrs: ['127.0.0.1/32', '10.0.0.0/8'],
    tools: [
      {
        name: 'fetch_web_documentation',
        description: 'Fetches external web documentation, developer links, or API specs from a given URL.',
        is_sensitive: true,
        input_schema: {
          type: 'object',
          properties: {
            url: { type: 'string', description: 'The destination URL to fetch content from' },
          },
          required: ['url'],
        },
        deficiencies: [
          "Unbounded string parameter: 'url' has no maxLength, pattern, or enum constraint.",
        ],
      },
      {
        name: 'delete_user_record',
        description: 'Deletes a specified user profile and associated metadata from the database.',
        is_sensitive: true,
        input_schema: {
          type: 'object',
          properties: {
            user_id: { type: 'string', description: 'Identifier of the user record to delete' },
          },
          required: ['user_id'],
        },
        deficiencies: [
          "Unbounded string parameter: 'user_id' has no maxLength or pattern constraint.",
          "Missing multi-tenant isolation parameter: 'tenant_id' or 'org_id' is absent.",
        ],
      },
      {
        name: 'query_analytics_database',
        description: 'Executes raw analytical SQL queries across system metrics.',
        is_sensitive: true,
        input_schema: {
          type: 'object',
          properties: {
            sql_query: { type: 'string', description: 'The SQL query string to execute' },
          },
          required: ['sql_query'],
        },
        deficiencies: [
          "Direct database query tool: Unbounded agency allows arbitrary SQL execution.",
        ],
      },
      {
        name: 'get_system_status',
        description: 'Returns current service health and uptime statistics.',
        is_sensitive: false,
        input_schema: {
          type: 'object',
          properties: {
            detail_level: { type: 'string', enum: ['basic', 'verbose'] },
          },
        },
        deficiencies: [],
      },
    ],
  },
  {
    id: 'target_enterprise_crm',
    name: 'Enterprise CRM MCP Server',
    target_type: 'mcp_server',
    base_url: 'https://crm-agent.internal',
    allowed_domains: ['crm-agent.internal', 'localhost'],
    allowed_cidrs: ['10.200.0.0/16'],
    tools: [
      {
        name: 'dispatch_partner_webhook',
        description: 'Dispatches lead updates or notification payloads to arbitrary partner URLs.',
        is_sensitive: true,
        input_schema: {
          type: 'object',
          properties: {
            callback_endpoint: { type: 'string' },
            payload_data: { type: 'object' },
          },
          required: ['callback_endpoint'],
        },
        deficiencies: [
          "Unrestricted webhook destination: Potential SSRF / Intranet scanning vector.",
        ],
      },
      {
        name: 'export_customer_data',
        description: 'Exports customer PII and conversation transcripts for a specific account.',
        is_sensitive: true,
        input_schema: {
          type: 'object',
          properties: {
            account_id: { type: 'string' },
          },
          required: ['account_id'],
        },
        deficiencies: [
          "Missing Row-Level Security guard: Cross-tenant BOLA leak risk without session tenant validation.",
        ],
      },
      {
        name: 'list_crm_pipelines',
        description: 'Lists active sales pipelines and stages.',
        is_sensitive: false,
        input_schema: {
          type: 'object',
          properties: {},
        },
        deficiencies: [],
      },
    ],
  },
  {
    id: 'target_fintech_copilot',
    name: 'FinTech Banking Assistant',
    target_type: 'agent_pipeline',
    base_url: 'http://127.0.0.1:9090',
    allowed_domains: ['localhost', 'fintech.internal'],
    allowed_cidrs: ['127.0.0.1/32'],
    tools: [
      {
        name: 'execute_transfer',
        description: 'Executes funds transfer between accounts.',
        is_sensitive: true,
        input_schema: {
          type: 'object',
          properties: {
            source_account: { type: 'string' },
            destination_account: { type: 'string' },
            amount: { type: 'number' },
          },
          required: ['source_account', 'destination_account', 'amount'],
        },
        deficiencies: [
          "High financial risk: Tool lacks secondary confirmation or authorization token.",
        ],
      },
      {
        name: 'fetch_regulatory_filing',
        description: 'Fetches PDF or web filing from regulatory URL.',
        is_sensitive: true,
        input_schema: {
          type: 'object',
          properties: {
            filing_url: { type: 'string' },
          },
          required: ['filing_url'],
        },
        deficiencies: [
          "Unbounded URL parameter: Susceptible to Out-of-Band SSRF via canary pings.",
        ],
      },
    ],
  },
];
