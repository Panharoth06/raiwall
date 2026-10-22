import { describe, it, expect } from 'vitest';
import { mount } from '@vue/test-utils';
import { nextTick, ref } from 'vue';
import NumberInput from '../NumberInput.vue';

describe('NumberInput.vue', () => {
  it('renders initial modelValue with font-mono tabular-nums and shadow-none', () => {
    const wrapper = mount(NumberInput, {
      props: {
        modelValue: 42,
        placeholder: 'Enter number',
      },
    });

    const input = wrapper.find('input');
    expect(input.exists()).toBe(true);
    expect(input.element.value).toBe('42');
    expect(input.classes()).toContain('font-mono');
    expect(input.classes()).toContain('tabular-nums');
    expect(input.classes()).toContain('shadow-none');
    expect(wrapper.classes()).toContain('shadow-none');
  });

  it('renders contextual unit suffix when provided', () => {
    const wrapper = mount(NumberInput, {
      props: {
        modelValue: 100,
        suffix: 'reqs',
      },
    });

    expect(wrapper.text()).toContain('reqs');
  });

  it('renders unit prop when unit is used instead of suffix', () => {
    const wrapper = mount(NumberInput, {
      props: {
        modelValue: 60,
        unit: 'sec',
      },
    });

    expect(wrapper.text()).toContain('sec');
  });

  it('allows typing freely without prematurely clamping before blur', async () => {
    const wrapper = mount(NumberInput, {
      props: {
        modelValue: 50,
        min: 10,
        max: 100,
      },
    });

    const input = wrapper.find('input');
    await input.trigger('focus');

    // Simulate typing a number below min (e.g. '5' when typing '55')
    input.element.value = '5';
    await input.trigger('input');
    await nextTick();

    // While typing freely, input displays what was typed without premature clamping
    expect(input.element.value).toBe('5');
  });

  it('clamps to min on blur when value is below min', async () => {
    const wrapper = mount(NumberInput, {
      props: {
        modelValue: 50,
        min: 10,
        max: 100,
        'onUpdate:modelValue': (val: number | undefined) => wrapper.setProps({ modelValue: val }),
      },
    });

    const input = wrapper.find('input');
    input.element.value = '4';
    await input.trigger('input');
    await input.trigger('blur');
    await nextTick();

    expect(input.element.value).toBe('10');
    expect(wrapper.emitted('update:modelValue')?.slice(-1)[0]).toEqual([10]);
    expect(wrapper.emitted('change')?.slice(-1)[0]).toEqual([10]);
  });

  it('clamps to max on blur when value is above max', async () => {
    const wrapper = mount(NumberInput, {
      props: {
        modelValue: 50,
        min: 1,
        max: 100,
        'onUpdate:modelValue': (val: number | undefined) => wrapper.setProps({ modelValue: val }),
      },
    });

    const input = wrapper.find('input');
    input.element.value = '150';
    await input.trigger('input');
    await input.trigger('blur');
    await nextTick();

    expect(input.element.value).toBe('100');
    expect(wrapper.emitted('update:modelValue')?.slice(-1)[0]).toEqual([100]);
    expect(wrapper.emitted('change')?.slice(-1)[0]).toEqual([100]);
  });

  it('clamps to min on blur when field is cleared and min is defined', async () => {
    const wrapper = mount(NumberInput, {
      props: {
        modelValue: 50,
        min: 1,
        'onUpdate:modelValue': (val: number | undefined) => wrapper.setProps({ modelValue: val }),
      },
    });

    const input = wrapper.find('input');
    input.element.value = '';
    await input.trigger('input');
    await input.trigger('blur');
    await nextTick();

    expect(input.element.value).toBe('1');
    expect(wrapper.emitted('update:modelValue')?.slice(-1)[0]).toEqual([1]);
  });

  it('validates and clamps on Enter keydown', async () => {
    const wrapper = mount(NumberInput, {
      props: {
        modelValue: 50,
        min: 1,
        max: 100,
        'onUpdate:modelValue': (val: number | undefined) => wrapper.setProps({ modelValue: val }),
      },
    });

    const input = wrapper.find('input');
    input.element.value = '250';
    await input.trigger('input');
    await input.trigger('keydown', { key: 'Enter' });
    await nextTick();

    expect(input.element.value).toBe('100');
    expect(wrapper.emitted('update:modelValue')?.slice(-1)[0]).toEqual([100]);
  });

  it('steps with ArrowUp and ArrowDown keys while respecting bounds', async () => {
    const wrapper = mount(NumberInput, {
      props: {
        modelValue: 99,
        min: 1,
        max: 100,
        step: 1,
        'onUpdate:modelValue': (val: number | undefined) => wrapper.setProps({ modelValue: val }),
      },
    });

    const input = wrapper.find('input');

    // ArrowUp -> 100
    await input.trigger('keydown', { key: 'ArrowUp' });
    await nextTick();
    expect(input.element.value).toBe('100');
    expect(wrapper.emitted('update:modelValue')?.slice(-1)[0]).toEqual([100]);

    // ArrowUp again -> capped at max 100
    await input.trigger('keydown', { key: 'ArrowUp' });
    await nextTick();
    expect(input.element.value).toBe('100');

    // ArrowDown -> 99
    await input.trigger('keydown', { key: 'ArrowDown' });
    await nextTick();
    expect(input.element.value).toBe('99');
    expect(wrapper.emitted('update:modelValue')?.slice(-1)[0]).toEqual([99]);
  });

  it('updates display when modelValue is changed externally', async () => {
    const wrapper = mount(NumberInput, {
      props: {
        modelValue: 10,
      },
    });

    const input = wrapper.find('input');
    expect(input.element.value).toBe('10');

    await wrapper.setProps({ modelValue: 200 });
    await nextTick();

    expect(input.element.value).toBe('200');
  });

  it('respects disabled state', () => {
    const wrapper = mount(NumberInput, {
      props: {
        modelValue: 10,
        disabled: true,
      },
    });

    const input = wrapper.find('input');
    expect(input.attributes('disabled')).toBeDefined();
    expect(wrapper.classes()).toContain('cursor-not-allowed');
    expect(wrapper.classes()).toContain('opacity-50');
  });

  it('contains native spinner removal classes', () => {
    const wrapper = mount(NumberInput, {
      props: {
        modelValue: 10,
      },
    });

    const input = wrapper.find('input');
    expect(input.classes()).toContain('[appearance:textfield]');
  });

  it('handles string min, max, and step props without string concatenation on ArrowUp', async () => {
    const wrapper = mount(NumberInput, {
      props: {
        modelValue: 10,
        min: '5',
        max: '50',
        step: '2',
        'onUpdate:modelValue': (val: number | undefined) => wrapper.setProps({ modelValue: val }),
      },
    });

    const input = wrapper.find('input');
    await input.trigger('keydown', { key: 'ArrowUp' });
    await nextTick();

    // Must be 12 (number 10 + 2), NOT '102' (string concatenation)
    expect(input.element.value).toBe('12');
    expect(wrapper.emitted('update:modelValue')?.slice(-1)[0]).toEqual([12]);
  });

  it('updates display to "0" when external modelValue changes to 0 while focused and empty', async () => {
    const wrapper = mount(NumberInput, {
      props: {
        modelValue: undefined,
      },
    });

    const input = wrapper.find('input');
    await input.trigger('focus');
    expect(input.element.value).toBe('');

    // External change to 0
    await wrapper.setProps({ modelValue: 0 });
    await nextTick();

    // Must display '0' even if focused
    expect(input.element.value).toBe('0');
  });

  it('sets modelValue to undefined when input is cleared during typing, then clamps on blur', async () => {
    const wrapper = mount(NumberInput, {
      props: {
        modelValue: 50,
        min: 10,
        'onUpdate:modelValue': (val: number | undefined) => wrapper.setProps({ modelValue: val }),
      },
    });

    const input = wrapper.find('input');
    await input.trigger('focus');
    input.element.value = '';
    await input.trigger('input');
    await nextTick();

    // While typing and empty, modelValue should be undefined
    expect(wrapper.emitted('update:modelValue')?.slice(-1)[0]).toEqual([undefined]);

    // On blur, clamps to min=10
    await input.trigger('blur');
    await nextTick();

    expect(input.element.value).toBe('10');
    expect(wrapper.emitted('update:modelValue')?.slice(-1)[0]).toEqual([10]);
  });
});
