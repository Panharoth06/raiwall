// Geographical continent boundary coordinates and country origins for WAF Geo Location mapping.

export interface ContinentOutline {
  name: string;
  points: [number, number][];
}

export const continents: ContinentOutline[] = [
  // North America
  {
    name: 'North America',
    points: [
      [71, -156], [70, -130], [60, -140], [58, -136], [54, -130], [48, -124],
      [38, -123], [32, -117], [23, -110], [19, -104], [16, -93], [14, -88],
      [9, -78], [11, -74], [21, -87], [29, -89], [25, -80], [35, -75],
      [44, -64], [52, -56], [62, -64], [68, -80], [74, -95], [72, -125],
    ],
  },
  // South America
  {
    name: 'South America',
    points: [
      [12, -72], [8, -60], [5, -52], [-2, -44], [-8, -35], [-18, -39],
      [-23, -43], [-32, -52], [-41, -63], [-54, -68], [-52, -75], [-42, -74],
      [-30, -71], [-18, -71], [-4, -81], [5, -77], [9, -79],
    ],
  },
  // Eurasia
  {
    name: 'Eurasia',
    points: [
      [71, 28], [77, 104], [72, 140], [66, 170], [60, 162], [54, 156],
      [44, 136], [38, 120], [30, 122], [22, 114], [10, 105], [14, 98],
      [22, 90], [10, 79], [25, 66], [25, 57], [30, 48], [31, 35],
      [37, 27], [36, -5], [44, -1], [50, -4], [54, 8], [58, 6],
      [64, 12], [70, 20],
    ],
  },
  // Africa
  {
    name: 'Africa',
    points: [
      [36, -5], [37, 11], [32, 32], [22, 37], [12, 44], [-1, 42],
      [-12, 40], [-26, 33], [-34, 26], [-34, 18], [-22, 14], [-5, 12],
      [4, 9], [6, 2], [5, -3], [12, -16], [21, -17], [28, -13],
    ],
  },
  // Australia
  {
    name: 'Australia',
    points: [
      [-12, 131], [-14, 144], [-24, 153], [-33, 151], [-38, 146], [-36, 137],
      [-32, 132], [-35, 115], [-26, 113], [-20, 119], [-15, 125],
    ],
  },
  // Greenland
  {
    name: 'Greenland',
    points: [
      [82, -30], [76, -18], [69, -25], [60, -44], [65, -53], [76, -60], [82, -50],
    ],
  },
  // Japan
  {
    name: 'Japan',
    points: [
      [45, 142], [43, 145], [35, 140], [31, 131], [34, 132], [40, 140],
    ],
  },
];

export const countryCoords: Record<string, { lat: number; lon: number }> = {
  CN: { lat: 35.86, lon: 104.19 },
  China: { lat: 35.86, lon: 104.19 },
  US: { lat: 37.09, lon: -95.71 },
  'United States': { lat: 37.09, lon: -95.71 },
  NL: { lat: 52.13, lon: 5.29 },
  Netherlands: { lat: 52.13, lon: 5.29 },
  BG: { lat: 42.73, lon: 25.48 },
  Bulgaria: { lat: 42.73, lon: 25.48 },
  BE: { lat: 50.5, lon: 4.47 },
  Belgium: { lat: 50.5, lon: 4.47 },
  GB: { lat: 55.37, lon: -3.43 },
  'United Kingdom': { lat: 55.37, lon: -3.43 },
  FR: { lat: 46.22, lon: 2.21 },
  France: { lat: 46.22, lon: 2.21 },
  DE: { lat: 51.16, lon: 10.45 },
  Germany: { lat: 51.16, lon: 10.45 },
  RU: { lat: 61.52, lon: 105.31 },
  Russia: { lat: 61.52, lon: 105.31 },
  JP: { lat: 36.2, lon: 138.25 },
  Japan: { lat: 36.2, lon: 138.25 },
  SG: { lat: 1.35, lon: 103.82 },
  Singapore: { lat: 1.35, lon: 103.82 },
};
