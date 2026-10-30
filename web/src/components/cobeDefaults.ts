export interface CdnMarker {
  id: string;
  location: [number, number];
  region: string;
}

export interface CdnArc {
  id: string;
  from: [number, number];
  to: [number, number];
  /** Observed traffic volume; omitted when no real measurement exists. */
  value?: number;
}
