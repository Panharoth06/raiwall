import { describe, it, expect, beforeEach, vi } from 'vitest';
import { flushPromises, mount } from '@vue/test-utils';
import RuleTesterPanel from '../RuleTesterPanel.vue';
import { api } from '@/api/client';

vi.mock('@/api/client', () => ({
  api: { testRule: vi.fn() },
}));

class MockResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
}

const testRule = vi.mocked(api.testRule);

beforeEach(() => {
  vi.clearAllMocks();
  global.ResizeObserver = MockResizeObserver as unknown as typeof ResizeObserver;
});

describe('RuleTesterPanel.vue', () => {
  it('renders CRS verdict, anomaly score and matched rules', async () => {
    testRule.mockResolvedValue({
      duration_ms: 1.25,
      verdict: {
        action: 'audit',
        rule_id: 'CRS_949110',
        reason: 'OWASP CRS rule 949110 (deny)',
        engine: 'crs',
        anomaly_score: 8,
        paranoia_level: 1,
        status_code: 403,
        attack_category: 'crs',
        matched_rules: [
          { rule_id: '920340', message: 'Content-Type header missing', severity: 'critical', engine: 'crs' },
        ],
      },
    });

    const wrapper = mount(RuleTesterPanel);
    await wrapper.find('input[aria-label="Query string"]').setValue("q=1' OR '1'='1");
    await wrapper.find('form').trigger('submit');
    await flushPromises();

    expect(testRule).toHaveBeenCalledOnce();
    expect(testRule.mock.calls[0][0]).toMatchObject({ method: 'GET', path: '/' });

    expect(wrapper.text()).toContain('audit');
    expect(wrapper.text()).toContain('CRS_949110');
    expect(wrapper.text()).toContain('Anomaly');
    expect(wrapper.text()).toContain('920340');
    expect(wrapper.text()).toContain('1.25 ms');
  });

  it('shows a retryable error when evaluation fails', async () => {
    testRule.mockRejectedValue(new Error('inspection unavailable'));

    const wrapper = mount(RuleTesterPanel);
    await wrapper.find('form').trigger('submit');
    await flushPromises();

    const alert = wrapper.find('[role="alert"]');
    expect(alert.exists()).toBe(true);
    expect(alert.text()).toContain('inspection unavailable');
  });

  it('rejects malformed header lines before calling the API', async () => {
    const wrapper = mount(RuleTesterPanel);
    await wrapper.find('textarea[aria-label="Headers"]').setValue('not-a-header');
    await wrapper.find('form').trigger('submit');
    await flushPromises();

    expect(testRule).not.toHaveBeenCalled();
    expect(wrapper.find('[role="alert"]').text()).toContain('Invalid header line');
  });
});
