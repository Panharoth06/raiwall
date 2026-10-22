<script setup lang="ts">
import { ref, computed, watch, type HTMLAttributes } from 'vue';
import { cn } from '@/lib/utils';

const props = withDefaults(
  defineProps<{
    class?: HTMLAttributes['class'];
    inputClass?: HTMLAttributes['class'];
    type?: string;
    placeholder?: string;
    disabled?: boolean;
    readonly?: boolean;
    required?: boolean;
    min?: number | string;
    max?: number | string;
    step?: number | string;
    suffix?: string;
    unit?: string;
    prefix?: string;
    id?: string;
    name?: string;
  }>(),
  {
    type: 'number',
  }
);

const modelValue = defineModel<number | null | undefined>();

const emit = defineEmits<{
  (e: 'change', value: number | undefined): void;
  (e: 'blur', event: FocusEvent): void;
  (e: 'focus', event: FocusEvent): void;
}>();

const inputRef = ref<HTMLInputElement | null>(null);
const isFocused = ref(false);
const displayValue = ref('');

const unitSuffix = computed(() => props.suffix || props.unit);

const numMin = computed(() => {
  if (props.min === undefined || props.min === null || props.min === '') return undefined;
  const n = Number(props.min);
  return isNaN(n) ? undefined : n;
});

const numMax = computed(() => {
  if (props.max === undefined || props.max === null || props.max === '') return undefined;
  const n = Number(props.max);
  return isNaN(n) ? undefined : n;
});

const numStep = computed(() => {
  if (props.step === undefined || props.step === null || props.step === '') return 1;
  const n = Number(props.step);
  return isNaN(n) || n <= 0 ? 1 : n;
});

function clamp(val: number): number {
  let res = val;
  if (numMin.value !== undefined && res < numMin.value) {
    res = numMin.value;
  }
  if (numMax.value !== undefined && res > numMax.value) {
    res = numMax.value;
  }
  return res;
}

watch(
  () => modelValue.value,
  (newVal) => {
    if (isFocused.value) {
      const trimmed = displayValue.value.trim();
      if (trimmed !== '') {
        const current = Number(trimmed);
        if (!isNaN(current) && current === newVal) {
          return;
        }
      }
    }
    if (typeof newVal === 'number' && !isNaN(newVal)) {
      displayValue.value = String(newVal);
    } else {
      displayValue.value = '';
    }
  },
  { immediate: true }
);

function onInput(e: Event) {
  const target = e.target as HTMLInputElement;
  displayValue.value = target.value;
  const raw = target.value.trim();
  if (raw !== '') {
    const parsed = Number(raw);
    if (!isNaN(parsed)) {
      modelValue.value = parsed;
    }
  } else {
    modelValue.value = undefined;
  }
}

function commit() {
  const raw = displayValue.value.trim();

  if (raw === '') {
    if (numMin.value !== undefined) {
      const clamped = clamp(numMin.value);
      displayValue.value = String(clamped);
      modelValue.value = clamped;
      emit('change', clamped);
    } else {
      displayValue.value = '';
      modelValue.value = undefined;
      emit('change', undefined);
    }
    return;
  }

  const parsed = Number(raw);
  if (isNaN(parsed)) {
    if (typeof modelValue.value === 'number' && !isNaN(modelValue.value)) {
      displayValue.value = String(modelValue.value);
    } else if (numMin.value !== undefined) {
      const clamped = clamp(numMin.value);
      displayValue.value = String(clamped);
      modelValue.value = clamped;
      emit('change', clamped);
    } else {
      displayValue.value = '';
      modelValue.value = undefined;
      emit('change', undefined);
    }
    return;
  }

  const clamped = clamp(parsed);
  displayValue.value = String(clamped);
  if (modelValue.value !== clamped) {
    modelValue.value = clamped;
    emit('change', clamped);
  }
}

function onFocus(e: FocusEvent) {
  isFocused.value = true;
  emit('focus', e);
}

function onBlur(e: FocusEvent) {
  isFocused.value = false;
  commit();
  emit('blur', e);
}

function onChange() {
  commit();
}

function stepBy(delta: number) {
  if (props.disabled || props.readonly) return;
  let current: number;
  const raw = displayValue.value.trim();
  const parsed = Number(raw);
  if (raw === '' || isNaN(parsed)) {
    current = numMin.value !== undefined ? numMin.value : 0;
  } else {
    current = parsed + delta;
  }
  current = Math.round(current * 1e10) / 1e10;
  const clamped = clamp(current);
  displayValue.value = String(clamped);
  modelValue.value = clamped;
  emit('change', clamped);
}

function onKeyDown(e: KeyboardEvent) {
  if (e.key === 'Enter') {
    commit();
  } else if (e.key === 'ArrowUp') {
    e.preventDefault();
    stepBy(numStep.value);
  } else if (e.key === 'ArrowDown') {
    e.preventDefault();
    stepBy(-numStep.value);
  }
}

function focusInput() {
  inputRef.value?.focus();
}

function focus() {
  inputRef.value?.focus();
}

function blur() {
  inputRef.value?.blur();
}

function select() {
  inputRef.value?.select();
}

defineExpose({
  input: inputRef,
  focus,
  blur,
  select,
});
</script>

<template>
  <div
    :class="
      cn(
        'group relative flex h-9 w-full items-center rounded-md border border-input bg-card px-3 py-1 shadow-none transition-colors',
        'focus-within:border-primary focus-within:ring-0 focus-within:outline-none',
        disabled ? 'cursor-not-allowed opacity-50' : '',
        props.class
      )
    "
    @click="focusInput"
  >
    <slot name="prefix">
      <span
        v-if="prefix"
        class="mr-1.5 shrink-0 text-xs font-mono text-muted-foreground select-none pointer-events-none"
      >
        {{ prefix }}
      </span>
    </slot>
    <input
      ref="inputRef"
      :id="id"
      :name="name"
      :type="type || 'number'"
      inputmode="numeric"
      :min="min"
      :max="max"
      :step="step ?? 'any'"
      :placeholder="placeholder"
      :disabled="disabled"
      :readonly="readonly"
      :required="required"
      :value="displayValue"
      :class="
        cn(
          'w-full min-w-0 bg-transparent p-0 border-0 text-xs text-foreground placeholder:text-muted-foreground font-mono tabular-nums shadow-none outline-none focus:outline-none focus:ring-0',
          'disabled:cursor-not-allowed',
          '[appearance:textfield] [&::-webkit-outer-spin-button]:appearance-none [&::-webkit-inner-spin-button]:appearance-none [&::-webkit-outer-spin-button]:m-0 [&::-webkit-inner-spin-button]:m-0',
          inputClass
        )
      "
      @input="onInput"
      @change="onChange"
      @blur="onBlur"
      @focus="onFocus"
      @keydown="onKeyDown"
    />
    <slot name="suffix">
      <span
        v-if="unitSuffix"
        class="ml-1.5 shrink-0 text-[11px] font-mono text-muted-foreground select-none pointer-events-none"
      >
        {{ unitSuffix }}
      </span>
    </slot>
  </div>
</template>
