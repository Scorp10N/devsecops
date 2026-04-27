<script lang="ts">
  import { onMount } from 'svelte';
  import '../app.css';
  import { getToken, setToken, clearToken } from '$lib/auth';
  import { fetchPosture, fetchFindings, fetchPostureHistory } from '$lib/github';
  import TokenGate from '$lib/components/TokenGate.svelte';
  import PostureOverview from '$lib/components/PostureOverview.svelte';
  import ToolDrilldown from '$lib/components/ToolDrilldown.svelte';
  import type { NormalizedFindings, PostureSnapshot } from '$lib/types';

  const REPOS = ['resumeforge', 'resumeforge-cloud'];

  let token = $state<string | null>(null);
  let posture = $state<PostureSnapshot | null>(null);
  let findings = $state<Record<string, NormalizedFindings>>({});
  let history = $state<PostureSnapshot[]>([]);
  let error = $state<string | null>(null);
  let loading = $state(false);

  onMount(() => {
    token = getToken();
    if (token) loadData(token);
  });

  async function loadData(pat: string) {
    loading = true;
    error = null;
    try {
      posture = await fetchPosture(pat);

      const findingsMap: Record<string, NormalizedFindings> = {};
      for (const repo of REPOS) {
        try {
          findingsMap[repo] = await fetchFindings(pat, repo);
        } catch (e) {
          if (e instanceof Error && e.message === 'auth') throw e;
        }
      }
      findings = findingsMap;
      history = await fetchPostureHistory(pat);
    } catch (e) {
      if (e instanceof Error && e.message === 'auth') {
        clearToken();
        token = null;
        error = 'Token invalid or expired — please sign in again.';
      } else {
        error = e instanceof Error ? e.message : 'Unknown error loading data.';
      }
    } finally {
      loading = false;
    }
  }

  function handleToken(pat: string) {
    setToken(pat);
    token = pat;
    loadData(pat);
  }

  function handleSignOut() {
    clearToken();
    token = null;
    posture = null;
    findings = {};
    history = [];
    error = null;
  }
</script>

<svelte:head>
  <title>Security Dashboard — Scorp10N</title>
</svelte:head>

{#if !token}
  <TokenGate onToken={handleToken} />
{:else if loading}
  <div class="flex items-center justify-center min-h-screen">
    <p class="text-gray-400 text-sm">Loading security data...</p>
  </div>
{:else}
  <div class="max-w-4xl mx-auto px-6 py-10">
    <div class="flex justify-between items-center mb-8">
      <div>
        <h1 class="text-2xl font-bold">Security Posture</h1>
        <p class="text-sm text-gray-400">Scorp10N</p>
      </div>
      <button
        onclick={handleSignOut}
        class="text-sm text-gray-400 hover:text-gray-600 underline"
      >
        Sign out
      </button>
    </div>

    {#if error}
      <div class="bg-red-50 border border-red-200 rounded p-4 mb-6 text-sm text-red-700">
        {error}
      </div>
    {/if}

    {#if posture}
      <section class="mb-10">
        <PostureOverview {posture} {history} />
      </section>

      <section>
        <h2 class="text-lg font-semibold mb-4">Findings by tool</h2>
        <ToolDrilldown {findings} repos={REPOS} />
      </section>
    {/if}
  </div>
{/if}
