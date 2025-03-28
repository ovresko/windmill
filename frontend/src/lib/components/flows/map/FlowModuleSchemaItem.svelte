<script lang="ts">
	import type { FlowCopilotContext } from '$lib/components/copilot/flow'
	import Popover from '$lib/components/Popover.svelte'
	import { classNames } from '$lib/utils'
	import {
		AlertTriangle,
		Bed,
		Database,
		Gauge,
		Move,
		PhoneIncoming,
		Repeat,
		Square,
		SkipForward,
		Voicemail,
		X
	} from 'lucide-svelte'
	import { createEventDispatcher, getContext } from 'svelte'
	import { fade } from 'svelte/transition'
	import type { FlowEditorContext, FlowInput } from '../types'
	import { get, type Writable } from 'svelte/store'
	import { twMerge } from 'tailwind-merge'
	import IdEditorInput from '$lib/components/IdEditorInput.svelte'
	import { dfs } from '../dfs'
	import { Drawer } from '$lib/components/common'
	import DrawerContent from '$lib/components/common/drawer/DrawerContent.svelte'
	import { getDependeeAndDependentComponents } from '../flowExplorer'
	import { replaceId } from '../flowStore'
	import FlowModuleSchemaItemViewer from './FlowModuleSchemaItemViewer.svelte'
	import FlowPropPicker from '$lib/components/flows/propPicker/FlowPropPicker.svelte'
	import type { PropPickerContext } from '$lib/components/prop_picker'
	export let selected: boolean = false
	export let deletable: boolean = false
	export let retry: boolean = false
	export let cache: boolean = false
	export let earlyStop: boolean = false
	export let skip: boolean = false
	export let suspend: boolean = false
	export let sleep: boolean = false
	export let mock: boolean = false
	export let bold: boolean = false
	export let id: string | undefined = undefined
	export let label: string
	export let path: string = ''
	export let modType: string | undefined = undefined
	export let bgColor: string = ''
	export let concurrency: boolean = false
	export let retries: number | undefined = undefined
	export let warningMessage: string | undefined = undefined
	export let isTrigger: boolean = false
	let pickableIds: Record<string, any> | undefined = undefined

	const { flowInputsStore } = getContext<{ flowInputsStore: Writable<FlowInput | undefined> }>(
		'FlowGraphContext'
	)

	const flowEditorContext = getContext<FlowEditorContext>('FlowEditorContext')

	const dispatch = createEventDispatcher()

	const { currentStepStore: copilotCurrentStepStore } =
		getContext<FlowCopilotContext | undefined>('FlowCopilotContext') || {}

	const propPickerContext = getContext<PropPickerContext>('PropPickerContext')
	const flowPropPickerConfig = propPickerContext?.flowPropPickerConfig
	const pickablePropertiesFiltered = propPickerContext?.pickablePropertiesFiltered

	$: pickableIds = $pickablePropertiesFiltered?.priorIds

	let editId = false

	let newId: string = id ?? ''

	let hover = false
</script>

{#if deletable && id && editId}
	{@const flowStore = flowEditorContext?.flowStore ? get(flowEditorContext?.flowStore) : undefined}
	{@const getDeps = getDependeeAndDependentComponents(
		id,
		flowStore?.value.modules ?? [],
		flowStore?.value.failure_module
	)}
	<Drawer bind:open={editId}>
		<DrawerContent title="Edit Step Id {id}" on:close={() => (editId = false)}>
			<div>
				<IdEditorInput
					buttonText="Edit Id "
					btnClasses="!ml-1"
					label=""
					initialId={id}
					acceptUnderScores
					reservedIds={dfs(flowStore?.value.modules ?? [], (x) => x.id)}
					bind:value={newId}
					on:save={(e) => {
						dispatch('changeId', { id, newId: e.detail, deps: getDeps?.dependents ?? {} })
						editId = false
					}}
					on:close={() => {
						editId = false
					}}
				/>
				<div class="mt-8">
					<h3>Step Inputs Replacements</h3>
					<div class="text-2xs text-tertiary pt-0.5">
						Replace all occurrences of `results.<span class="font-bold">{id}</span>` with{' '}
						results.<span class="font-bold">{newId}</span> in the step inputs of all steps that depend
						on it.
					</div>
					<div class="pt-8 flex flex-col gap-y-4">
						{#if Object.keys(getDeps?.dependents ?? {})?.length > 0}
							{#each Object.entries(getDeps?.dependents ?? {}) as dependents}
								<div>
									<h4>{dependents[0]}</h4>
									<div>
										{#each dependents?.[1] as d}
											<div>
												<span class="font-mono text-sm">{d}</span> &rightarrow;
												<span class="font-mono text-sm">{replaceId(d, id, newId)}</span>
											</div>
										{/each}
									</div>
								</div>
							{/each}
						{:else}
							<div class="text-2xs text-tertiary"> No dependents </div>
						{/if}
					</div>
				</div>
			</div>
		</DrawerContent>
	</Drawer>
{/if}

<!-- svelte-ignore a11y-click-events-have-key-events -->
<!-- svelte-ignore a11y-no-static-element-interactions -->
<div
	class={classNames(
		'w-full module flex rounded-sm cursor-pointer max-w-full',
		selected ? 'outline outline-offset-0  outline-2  outline-slate-500 dark:outline-gray-400' : '',
		'flex relative',
		$copilotCurrentStepStore === id ? 'z-[901]' : ''
	)}
	style="width: 275px; height: 34px; background-color: {bgColor};"
	on:mouseenter={() => (hover = true)}
	on:mouseleave={() => (hover = false)}
	on:click|preventDefault|stopPropagation
>
	<div class="absolute text-sm right-12 -bottom-3 flex flex-row gap-1 z-10">
		{#if retry}
			<Popover notClickable>
				<div
					transition:fade|local={{ duration: 200 }}
					class="center-center rounded border bg-surface border-gray-400 text-secondary px-1 py-0.5"
				>
					{#if retries}<span class="text-red-400 mr-2">{retries}</span>{/if}
					<Repeat size={12} />
				</div>
				<svelte:fragment slot="text">Retries</svelte:fragment>
			</Popover>
		{/if}

		{#if concurrency}
			<Popover notClickable>
				<div
					transition:fade|local={{ duration: 200 }}
					class="center-center rounded border bg-surface border-gray-400 text-secondary px-1 py-0.5"
				>
					<Gauge size={12} />
				</div>
				<svelte:fragment slot="text">Concurrency Limits</svelte:fragment>
			</Popover>
		{/if}
		{#if cache}
			<Popover notClickable>
				<div
					transition:fade|local={{ duration: 200 }}
					class="center-center rounded border bg-surface border-gray-400 text-secondary px-1 py-0.5"
				>
					<Database size={12} />
				</div>
				<svelte:fragment slot="text">Cached</svelte:fragment>
			</Popover>
		{/if}
		{#if earlyStop}
			<Popover notClickable>
				<div
					transition:fade|local={{ duration: 200 }}
					class="center-center bg-surface rounded border border-gray-400 text-secondary px-1 py-0.5"
				>
					<Square size={12} />
				</div>
				<svelte:fragment slot="text"
					>{isTrigger
						? 'Stop early if there are no new events'
						: 'Early stop/break'}</svelte:fragment
				>
			</Popover>
		{/if}
		{#if skip}
			<Popover notClickable>
				<div
					transition:fade|local={{ duration: 200 }}
					class="center-center bg-surface rounded border border-gray-400 text-secondary px-1 py-0.5"
				>
					<SkipForward size={12} />
				</div>
				<svelte:fragment slot="text">Skip</svelte:fragment>
			</Popover>
		{/if}
		{#if suspend}
			<Popover notClickable>
				<div
					transition:fade|local={{ duration: 200 }}
					class="center-center bg-surface rounded border border-gray-400 text-secondary px-1 py-0.5"
				>
					<PhoneIncoming size={12} />
				</div>
				<svelte:fragment slot="text">Suspend</svelte:fragment>
			</Popover>
		{/if}
		{#if sleep}
			<Popover notClickable>
				<div
					transition:fade|local={{ duration: 200 }}
					class="center-center bg-surface rounded border border-gray-400 text-secondary px-1 py-0.5"
				>
					<Bed size={12} />
				</div>
				<svelte:fragment slot="text">Sleep</svelte:fragment>
			</Popover>
		{/if}
		{#if mock}
			<Popover notClickable>
				<div
					transition:fade|local={{ duration: 200 }}
					class="center-center bg-surface rounded border border-gray-400 text-secondary px-1 py-0.5"
				>
					<Voicemail size={12} />
				</div>
				<svelte:fragment slot="text">Mocked</svelte:fragment>
			</Popover>
		{/if}
	</div>

	<FlowModuleSchemaItemViewer {label} {path} {id} {deletable} {bold} bind:editId {hover}>
		<svelte:fragment slot="icon">
			<slot name="icon" />
		</svelte:fragment>
	</FlowModuleSchemaItemViewer>

	{#if id && $flowPropPickerConfig && pickableIds && Object.keys(pickableIds).includes(id)}
		<div class="absolute -bottom-[14px] right-[21px] translate-x-[50%] center-center">
			<FlowPropPicker
				json={{
					[id]: pickableIds[id]
				}}
				prefix={'results'}
			/>
		</div>
	{/if}

	{#if deletable}
		<button
			class="absolute -top-[10px] -right-[10px] rounded-full h-[20px] w-[20px] trash center-center text-secondary
	outline-[1px] outline dark:outline-gray-500 outline-gray-300 bg-surface duration-150 hover:bg-red-400 hover:text-white
	 {hover || selected ? '' : '!hidden'}"
			title="Delete"
			on:click|preventDefault|stopPropagation={(event) =>
				dispatch('delete', { event, id, type: modType })}
		>
			<X class="mx-[3px]" size={12} strokeWidth={2} />
		</button>

		{#if id !== 'preprocessor'}
			<button
				class="absolute -top-[10px] right-[60px] rounded-full h-[20px] w-[20px] trash center-center text-secondary
outline-[1px] outline dark:outline-gray-500 outline-gray-300 bg-surface duration-150 hover:bg-blue-400 hover:text-white
 {hover ? '' : '!hidden'}"
				on:click|preventDefault|stopPropagation={(event) => dispatch('move')}
				title="Move"
			>
				<Move class="mx-[3px]" size={12} strokeWidth={2} />
			</button>
		{/if}

		{#if (id && Object.values($flowInputsStore?.[id]?.flowStepWarnings || {}).length > 0) || Boolean(warningMessage)}
			<div class="absolute -top-[10px] -left-[10px]">
				<Popover>
					<svelte:fragment slot="text">
						<ul class="list-disc px-2">
							{#if id}
								{#each Object.values($flowInputsStore?.[id]?.flowStepWarnings || {}) as m}
									<li>
										{m.message}
									</li>
								{/each}
							{/if}
						</ul>
					</svelte:fragment>
					<div
						class={twMerge(
							'flex items-center justify-center h-full w-full rounded-md p-0.5 border  duration-150 ',
							id &&
								Object.values($flowInputsStore?.[id]?.flowStepWarnings || {})?.some(
									(x) => x.type === 'error'
								)
								? 'border-red-600 text-red-600 bg-red-100 hover:bg-red-300'
								: 'border-yellow-600 text-yellow-600 bg-yellow-100 hover:bg-yellow-300'
						)}
					>
						<AlertTriangle size={14} strokeWidth={2} />
					</div>
				</Popover>
			</div>
		{/if}
	{/if}
</div>

<style>
	.module:hover .trash {
		display: flex !important;
	}
</style>
