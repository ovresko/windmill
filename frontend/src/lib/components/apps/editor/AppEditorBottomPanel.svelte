<script lang="ts">
	import InlineScriptsPanel from './inlineScriptsPanel/InlineScriptsPanel.svelte'
	import RunnableJobPanel from './RunnableJobPanel.svelte'

	export let rightPanelSize: number = 0
	export let centerPanelWidth: number = 0
	export let runnablePanelSize: number = 0
</script>

{#if rightPanelSize !== 0}
	<!-- svelte-ignore a11y-no-static-element-interactions -->
	<div class="relative h-full w-full overflow-x-visible" on:mouseenter on:mouseleave>
		<InlineScriptsPanel on:hidePanel />
		<RunnableJobPanel hidden={runnablePanelSize === 0} />
	</div>
{:else}
	<div class="flex flex-row relative w-full h-full">
		<InlineScriptsPanel width={centerPanelWidth * 0.66} on:hidePanel />
		<RunnableJobPanel float={false} hidden={runnablePanelSize === 0} />
	</div>
{/if}
