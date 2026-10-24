export interface CdnMarker {
  id: string;
  location: [number, number];
  region: string;
}

export interface CdnArc {
  id: string;
  from: [number, number];
  to: [number, number];
  value?: number;
}

export const defaultMarkers: CdnMarker[] = [
  { id: 'cdn-iad', location: [38.95, -77.45], region: 'iad1' },
  { id: 'cdn-sfo', location: [37.62, -122.38], region: 'sfo1' },
  { id: 'cdn-cdg', location: [49.01, 2.55], region: 'cdg1' },
  { id: 'cdn-hnd', location: [35.55, 139.78], region: 'hnd1' },
  { id: 'cdn-syd', location: [-33.95, 151.18], region: 'syd1' },
  { id: 'cdn-gru', location: [-23.43, -46.47], region: 'gru1' },
  { id: 'cdn-sin', location: [1.36, 103.99], region: 'sin1' },
  { id: 'cdn-arn', location: [59.65, 17.93], region: 'arn1' },
  { id: 'cdn-dub', location: [53.43, -6.25], region: 'dub1' },
  { id: 'cdn-bom', location: [19.09, 72.87], region: 'bom1' },
];

export const defaultArcs: CdnArc[] = [
  { id: 'cdn-arc-1', from: [38.95, -77.45], to: [49.01, 2.55] },
  { id: 'cdn-arc-2', from: [37.62, -122.38], to: [35.55, 139.78] },
  { id: 'cdn-arc-3', from: [49.01, 2.55], to: [1.36, 103.99] },
  { id: 'cdn-arc-4', from: [38.95, -77.45], to: [-23.43, -46.47] },
  { id: 'cdn-arc-5', from: [35.55, 139.78], to: [-33.95, 151.18] },
  { id: 'cdn-arc-6', from: [49.01, 2.55], to: [19.09, 72.87] },
];
