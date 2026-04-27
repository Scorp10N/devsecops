<script lang="ts">
  import type { PostureSnapshot } from '$lib/types';

  let {
    posture,
    history,
  }: {
    posture: PostureSnapshot;
    history: PostureSnapshot[];
  } = $props();

  const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;
  const COLORS: Record<string, string> = {
    critical: 'bg-red-100 text-red-800 border-red-200',
    high: 'bg-orange-100 text-orange-800 border-orange-200',
    medium: 'bg-yellow-100 text-yellow-800 border-yellow-200',
    low: 'bg-blue-100 text-blue-800 border-blue-200',
    info: 'bg-gray-100 text-gray-600 border-gray-200',
  };

  const sparkline = $derived.by(() => {
    if (history.length < 2) return '';
    const points = history.map((s) => {
      const t = s.total;
      return t.critical * 10 + t.high * 3 + t.medium;
    });
    const max = Math.max(...points, 1);
    const w = 200, h = 40;
    const coords = points.map((v, i) => {
      const x = (i / (points.length - 1)) * w;
      const y = h - (v / max) * h;
      return `${x},${y}`;
    });
    return `M ${coords.join(' L ')}`;
  });

  function ago(iso: string): string {
    const diff = Date.now() - new Date(iso).getTime();
    const mins = Math.floor(diff / 60000);
    if (mins < 60) return `${mins}m ago`;
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return `${hrs}h ago`;
    return `${Math.floor(hrs / 24)}d ago`;
  }
</script>

<div class="space-y-6">
  <div class="grid grid-cols-5 gap-3">
    {#each SEVERITIES as sev}
      <div class="border rounded-lg p-4 text-center {COLORS[sev]}">
        <div class="text-2xl font-bold">{posture.total[sev] ?? 0}</div>
        <div class="text-xs mt-1 capitalize">{sev}</div>
      </div>
    {/each}
  </div>

  {#if history.length >= 2}
    <div class="border rounded-lg p-4">
      <p class="text-xs text-gray-500 mb-2">Weighted findings — last {history.length} scans</p>
      <svg viewBox="0 0 200 40" class="w-full h-10">
        <path d={sparkline} fill="none" stroke="#3b82f6" stroke-width="1.5" />
      </svg>
    </div>
  {/if}

  <div class="text-sm text-gray-500 space-y-1">
    {#each Object.entries(posture.last_scanned) as [repo, ts]}
      <div>
        <span class="font-medium text-gray-700">{repo.split('/')[1]}</span>
        — last scanned {ago(ts)}
      </div>
    {/each}
  </div>
</div>
