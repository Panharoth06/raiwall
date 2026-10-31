import { describe, it, expect, beforeEach } from 'vitest';
import { mount } from '@vue/test-utils';
import { createPinia, setActivePinia } from 'pinia';
import PolicyPresetEditor from '../PolicyPresetEditor.vue';
import type { WAFPolicy } from '@/api/detection';

const basePolicy: WAFPolicy = {
  detection_mode: 'alert',
  sensitivity: 'high',
  crs: {
    enabled: true,
    paranoia_level: 2,
    inbound_threshold: 3,
    outbound_threshold: 2,
  },
};

describe('PolicyPresetEditor.vue', () => {
  beforeEach(() => {
    setActivePinia(createPinia());
  });

  it('emits the full policy with the selected mode on save', async () => {
    const wrapper = mount(PolicyPresetEditor, { props: { policy: basePolicy } });

    await wrapper.find('[data-testid="detection-mode-block"]').trigger('click');
    await wrapper.find('[data-testid="detection-policy-save"]').trigger('click');

    const emitted = wrapper.emitted('save');
    expect(emitted).toBeTruthy();
    const payload = emitted![0][0] as WAFPolicy;
    expect(payload.detection_mode).toBe('block');
    expect(payload.sensitivity).toBe('high');
    expect(payload.crs?.enabled).toBe(true);
    expect(payload.crs?.paranoia_level).toBe(2);
    expect(payload.crs?.inbound_threshold).toBe(3);
  });

  it('renders the active mode and sensitivity description', () => {
    const wrapper = mount(PolicyPresetEditor, { props: { policy: basePolicy } });

    expect(wrapper.text()).toContain('All modules strict');
    expect(wrapper.find('[data-testid="detection-mode-alert"]').classes()).toContain('bg-primary');
  });
});
