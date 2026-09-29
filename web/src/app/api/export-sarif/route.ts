import { NextResponse } from 'next/server';
import { VulnerabilityFinding } from '@/types';

export async function POST(req: Request) {
  try {
    const body = await req.json();
    const findings: VulnerabilityFinding[] = body.findings || [];
    const targetName: string = body.targetName || 'Agentic SaaS Target';

    const rulesMap: Record<string, any> = {};
    const results: any[] = [];

    const levelMap: Record<string, string> = {
      CRITICAL: 'error',
      HIGH: 'error',
      MEDIUM: 'warning',
      LOW: 'note',
      INFO: 'none',
    };

    for (const f of findings) {
      const ruleId = f.owasp_category.split(':')[0] || 'LLM01';
      if (!rulesMap[ruleId]) {
        rulesMap[ruleId] = {
          id: ruleId,
          name: f.owasp_category,
          shortDescription: { text: f.owasp_category },
          defaultConfiguration: { level: levelMap[f.severity] || 'warning' },
        };
      }

      results.push({
        ruleId,
        message: { text: `${f.title}: ${f.description}` },
        level: levelMap[f.severity] || 'warning',
        locations: [
          {
            physicalLocation: {
              artifactLocation: { uri: `mcp://${f.target_tool}` },
              region: { startLine: 1 },
            },
          },
        ],
        fixes: [
          {
            description: { text: 'Isihlangu synthesized remediation patch' },
            artifactChanges: [],
          },
        ],
        properties: {
          severity: f.severity,
          remediation: f.remediation_patch,
        },
      });
    }

    const sarifDoc = {
      $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
      version: '2.1.0',
      runs: [
        {
          tool: {
            driver: {
              name: 'Isihlangu',
              version: '0.1.0',
              informationUri: 'https://github.com/isihlangu/isihlangu',
              rules: Object.values(rulesMap),
            },
          },
          results,
        },
      ],
    };

    return new NextResponse(JSON.stringify(sarifDoc, null, 2), {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'Content-Disposition': `attachment; filename="isihlangu_${targetName.toLowerCase().replace(/\s+/g, '_')}.sarif"`,
      },
    });
  } catch (error: any) {
    return NextResponse.json(
      { error: error.message || 'Failed to generate SARIF report' },
      { status: 500 }
    );
  }
}
