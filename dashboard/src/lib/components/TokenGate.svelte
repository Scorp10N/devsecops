<script lang="ts">
  let { onToken }: { onToken: (token: string) => void } = $props();
  let input = $state('');
  let error = $state('');

  function submit() {
    const t = input.trim();
    if (!t) { error = 'Enter a GitHub PAT'; return; }
    error = '';
    onToken(t);
  }
</script>

<div class="flex items-center justify-center min-h-screen bg-gray-50">
  <div class="bg-white rounded-lg shadow p-8 w-full max-w-sm">
    <h1 class="text-xl font-bold mb-1">Security Dashboard</h1>
    <p class="text-sm text-gray-500 mb-6">
      Enter a GitHub fine-grained PAT with <strong>Contents: read</strong>
      access to <code>security-data</code>.
    </p>

    <label class="block text-sm font-medium text-gray-700 mb-1" for="pat">
      GitHub PAT
    </label>
    <input
      id="pat"
      type="password"
      bind:value={input}
      onkeydown={(e) => e.key === 'Enter' && submit()}
      placeholder="github_pat_..."
      class="w-full border border-gray-300 rounded px-3 py-2 text-sm mb-3
             focus:outline-none focus:ring-2 focus:ring-blue-500"
    />

    {#if error}
      <p class="text-red-600 text-sm mb-3">{error}</p>
    {/if}

    <button
      onclick={submit}
      class="w-full bg-blue-600 text-white rounded px-4 py-2 text-sm font-medium
             hover:bg-blue-700 transition-colors"
    >
      Sign in
    </button>

    <p class="text-xs text-gray-400 mt-4">
      Token is stored in <code>sessionStorage</code> only — never sent to any server.
    </p>
  </div>
</div>
