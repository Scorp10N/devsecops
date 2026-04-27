<script lang="ts">
  import type { NormalizedFindings } from '$lib/types';

  let {
    findings,
    repos,
  }: {
    findings: Record<string, NormalizedFindings>;
    repos: string[];
  } = $props();

  const TOOLS = ['trivy', 'pip-audit', 'govulncheck', 'trufflehog', 'semgrep'];
  const SEVERITY_DOT: Record<string, string> = {
    critical: 'bg-red-500',
    high: 'bg-orange-500',
    medium: 'bg-yellow-400',
    low: 'bg-blue-400',
    info: 'bg-gray-300',
  };

  function findingsByTool(repoFindings: NormalizedFindings, tool: string) {
    return repoFindings.findings.filter((f) => f.tool === tool);
  }
</script>

<div class="space-y-8">
  {#each repos as repo}
    {@const repoFindings = findings[repo]}
    <div>
      <h2 class="text-lg font-semibold mb-3">{repo}</h2>

      {#if !repoFindings}
        <p class="text-sm text-gray-400">No scan data yet.</p>
      {:else}
        <div class="grid grid-cols-1 gap-3">
          {#each TOOLS as tool}
            {@const toolFindings = findingsByTool(repoFindings, tool)}
            <div class="border rounded-lg p-4">
              <div class="flex justify-between items-center mb-2">
                <span class="text-sm font-medium capitalize">{tool}</span>
                <span class="text-sm text-gray-500">
                  {toolFindings.length} finding{toolFindings.length !== 1 ? 's' : ''}
                </span>
              </div>

              {#if toolFindings.length === 0}
                <p class="text-xs text-green-600">✓ Clean</p>
              {:else}
                <ul class="space-y-1">
                  {#each toolFindings as f}
                    <li class="flex items-start gap-2 text-xs">
                      <span
                        class="mt-1 w-2 h-2 rounded-full flex-shrink-0 {SEVERITY_DOT[f.severity] ?? 'bg-gray-300'}"
                      ></span>
                      <span class="flex-1">
                        {#if f.url}
                          <a
                            href={f.url}
                            target="_blank"
                            rel="noreferrer"
                            class="text-blue-600 hover:underline">{f.title}</a
                          >
                        {:else}
                          {f.title}
                        {/if}
                        {#if f.package}
                          <span class="text-gray-400"> — {f.package} {f.version ?? ''}</span>
                        {/if}
                        {#if f.fix_version}
                          <span class="text-green-600"> → fix: {f.fix_version}</span>
                        {/if}
                      </span>
                    </li>
                  {/each}
                </ul>
              {/if}
            </div>
          {/each}
        </div>
      {/if}
    </div>
  {/each}
</div>
