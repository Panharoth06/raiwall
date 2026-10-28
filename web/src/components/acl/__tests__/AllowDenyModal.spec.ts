import { describe, it, expect } from 'vitest';
import { mount } from '@vue/test-utils';
import { nextTick } from 'vue';
import AllowDenyModal from '../AllowDenyModal.vue';
import type { ACLRule } from '@/api/client';

describe('AllowDenyModal.vue', () => {
  const existingRule: ACLRule = {
    id: 'acl-test-1',
    name: 'Allow Test Subnet',
    expression: 'client_ip == "192.168.1.1"',
    action: 'allow',
    priority: 100,
    enabled: true,
    is_active: true,
    continue_inspection: true,
  };

  it('initializes form state correctly from props.rule including continue_inspection', async () => {
    const wrapper = mount(AllowDenyModal, {
      props: {
        open: true,
        rule: existingRule,
      },
      attachTo: document.body,
    });

    await nextTick();

    const continueCb = document.body.querySelector('#continue-inspection');
    expect(continueCb).not.toBeNull();
    expect(continueCb?.getAttribute('data-state')).toBe('checked');

    const enabledCb = document.body.querySelector('#rule-enabled');
    expect(enabledCb).not.toBeNull();
    expect(enabledCb?.getAttribute('data-state')).toBe('checked');

    wrapper.unmount();
  });

  it('initializes form state as disabled when rule.enabled is false', async () => {
    const disabledRule: ACLRule = {
      ...existingRule,
      enabled: false,
      is_active: false,
      continue_inspection: false,
    };

    const wrapper = mount(AllowDenyModal, {
      props: {
        open: true,
        rule: disabledRule,
      },
      attachTo: document.body,
    });

    await nextTick();

    const continueCb = document.body.querySelector('#continue-inspection');
    expect(continueCb?.getAttribute('data-state')).toBe('unchecked');

    const enabledCb = document.body.querySelector('#rule-enabled');
    expect(enabledCb?.getAttribute('data-state')).toBe('unchecked');

    wrapper.unmount();
  });

  it('emits save event with continue_inspection and enabled values on submit', async () => {
    const wrapper = mount(AllowDenyModal, {
      props: {
        open: true,
        rule: existingRule,
      },
      attachTo: document.body,
    });

    await nextTick();

    // Find submit button in document body
    const submitBtn = Array.from(document.body.querySelectorAll('button')).find((b) =>
      b.textContent?.includes('SUBMIT')
    );
    expect(submitBtn).toBeDefined();

    submitBtn?.click();
    await nextTick();

    const saveEvents = wrapper.emitted('save');
    expect(saveEvents).toBeDefined();
    expect(saveEvents![0][0]).toMatchObject({
      id: 'acl-test-1',
      name: 'Allow Test Subnet',
      action: 'allow',
      enabled: true,
      is_active: true,
      continue_inspection: true,
    });

    wrapper.unmount();
  });
});
