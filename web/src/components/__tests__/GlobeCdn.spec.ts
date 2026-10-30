import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mount } from '@vue/test-utils';
import GlobeCdn from '@/components/GlobeCdn.vue';
import type { CdnMarker, CdnArc } from '@/components/cobeDefaults';

describe('GlobeCdn.vue', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  it('renders an empty globe with no markers by default', () => {
    const wrapper = mount(GlobeCdn);
    const canvas = wrapper.find('canvas');
    expect(canvas.exists()).toBe(true);

    // No synthetic markers: only telemetry-derived data is ever drawn.
    expect(wrapper.findAll('.cobe-marker-anchor').length).toBe(0);
  });

  it('renders dynamic markers and arcs passed via props', () => {
    const customMarkers: CdnMarker[] = [
      { id: 'gw-primary', location: [37.77, -122.42], region: 'US-WEST' },
      { id: 'edge-tokyo', location: [35.68, 139.69], region: 'AP-NORTHEAST' },
    ];
    const customArcs: CdnArc[] = [
      { id: 'arc-traffic-1', from: [37.77, -122.42], to: [35.68, 139.69], value: 750 },
    ];

    const wrapper = mount(GlobeCdn, {
      props: {
        markers: customMarkers,
        arcs: customArcs,
        speed: 0.005,
      },
    });

    const markerTags = wrapper.findAll('.cobe-marker-anchor');
    expect(markerTags.length).toBe(2);
    expect(wrapper.text()).toContain('US-WEST');
    expect(wrapper.text()).toContain('AP-NORTHEAST');
  });
});
