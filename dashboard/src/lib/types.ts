export interface Finding {
  tool: string;
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  package: string | null;
  version: string | null;
  fix_version: string | null;
  url: string | null;
  description: string;
}

export interface Summary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface NormalizedFindings {
  repo: string;
  run_id: number;
  scanned_at: string;
  findings: Finding[];
  summary: Summary;
}

export interface PostureSnapshot {
  generated_at: string;
  total: Summary;
  by_repo: Record<string, Summary>;
  last_scanned: Record<string, string>;
}
