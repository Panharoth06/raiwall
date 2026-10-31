import { describe, it, expect, beforeEach } from 'vitest';
import { mount } from '@vue/test-utils';
import { createPinia, setActivePinia } from 'pinia';
import DetectionAppPolicyTable from '../DetectionAppPolicyTable.vue';
import type { AppDetectionPolicy } from '@/api/detection';

const policies: AppDetectionPolicy[] = [
  {
    app_id: 'app-1',
    name: 'Storefront',
    policy: { detection_mode: 'alert', sensitivity: 'high' },
    raw: { detection_mode: 'alert', sensitivity: 'high' },
    overridden: true,
  },
  {
    app_id: 'app-2',
    name: 'Admin Portal',
    policy: { detection_mode: 'inherit', sensitivity: 'inherit' },
    raw: { detection_mode: 'inherit', sensitivity: 'inherit' },
    overridden: false,
  },
];

describe('DetectionAppPolicyTable.vue', () => {
  beforeEach(() => {
    setActivePinia(createPinia());
  });

  it('renders per-site effective policies with override source', () => {
    const wrapper = mount(DetectionAppPolicyTable, { props: { policies } });

    expect(wrapper.find('[data-testid="app-policy-row-app-1"]').text()).toContain('OVERRIDE');
    expect(wrapper.find('[data-testid="app-policy-row-app-2"]').text()).toContain('INHERITED');
    expect(wrapper.find('[data-testid="app-policy-reset-app-1"]').exists()).toBe(true);
    expect(wrapper.find('[data-testid="app-policy-reset-app-2"]').exists()).toBe(false);
  });

  it('shows an actionable empty state when no applications are protected', () => {
    const wrapper = mount(DetectionAppPolicyTable, { props: { policies: [] } });

    expect(wrapper.text()).toContain('No protected applications');
    expect(wrapper.text()).toContain('Open Applications');
  });
});
