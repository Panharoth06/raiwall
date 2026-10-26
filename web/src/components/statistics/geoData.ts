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
  // Asia
  CN: { lat: 35.86, lon: 104.19 }, China: { lat: 35.86, lon: 104.19 },
  IN: { lat: 20.59, lon: 78.96 }, India: { lat: 20.59, lon: 78.96 },
  JP: { lat: 36.2, lon: 138.25 }, Japan: { lat: 36.2, lon: 138.25 },
  KR: { lat: 35.9, lon: 127.76 }, 'South Korea': { lat: 35.9, lon: 127.76 }, Korea: { lat: 35.9, lon: 127.76 },
  SG: { lat: 1.35, lon: 103.82 }, Singapore: { lat: 1.35, lon: 103.82 },
  VN: { lat: 14.05, lon: 108.27 }, Vietnam: { lat: 14.05, lon: 108.27 },
  ID: { lat: -0.78, lon: 113.92 }, Indonesia: { lat: -0.78, lon: 113.92 },
  TH: { lat: 15.87, lon: 100.99 }, Thailand: { lat: 15.87, lon: 100.99 },
  MY: { lat: 4.21, lon: 101.97 }, Malaysia: { lat: 4.21, lon: 101.97 },
  PH: { lat: 12.87, lon: 121.77 }, Philippines: { lat: 12.87, lon: 121.77 },
  PK: { lat: 30.37, lon: 69.34 }, Pakistan: { lat: 30.37, lon: 69.34 },
  BD: { lat: 23.68, lon: 90.35 }, Bangladesh: { lat: 23.68, lon: 90.35 },
  HK: { lat: 22.39, lon: 114.1 }, 'Hong Kong': { lat: 22.39, lon: 114.1 },
  TW: { lat: 23.69, lon: 120.96 }, Taiwan: { lat: 23.69, lon: 120.96 },
  IR: { lat: 32.42, lon: 53.68 }, Iran: { lat: 32.42, lon: 53.68 },
  IL: { lat: 31.04, lon: 34.85 }, Israel: { lat: 31.04, lon: 34.85 },
  SA: { lat: 23.88, lon: 45.07 }, 'Saudi Arabia': { lat: 23.88, lon: 45.07 },
  AE: { lat: 23.42, lon: 53.84 }, 'United Arab Emirates': { lat: 23.42, lon: 53.84 }, UAE: { lat: 23.42, lon: 53.84 },
  TR: { lat: 38.96, lon: 35.24 }, Turkey: { lat: 38.96, lon: 35.24 },

  // Europe
  GB: { lat: 55.37, lon: -3.43 }, 'United Kingdom': { lat: 55.37, lon: -3.43 }, UK: { lat: 55.37, lon: -3.43 },
  DE: { lat: 51.16, lon: 10.45 }, Germany: { lat: 51.16, lon: 10.45 },
  FR: { lat: 46.22, lon: 2.21 }, France: { lat: 46.22, lon: 2.21 },
  NL: { lat: 52.13, lon: 5.29 }, Netherlands: { lat: 52.13, lon: 5.29 },
  IT: { lat: 41.87, lon: 12.56 }, Italy: { lat: 41.87, lon: 12.56 },
  ES: { lat: 40.46, lon: -3.74 }, Spain: { lat: 40.46, lon: -3.74 },
  RU: { lat: 61.52, lon: 105.31 }, Russia: { lat: 61.52, lon: 105.31 },
  UA: { lat: 48.37, lon: 31.16 }, Ukraine: { lat: 48.37, lon: 31.16 },
  PL: { lat: 51.91, lon: 19.14 }, Poland: { lat: 51.91, lon: 19.14 },
  SE: { lat: 60.12, lon: 18.64 }, Sweden: { lat: 60.12, lon: 18.64 },
  NO: { lat: 60.47, lon: 8.46 }, Norway: { lat: 60.47, lon: 8.46 },
  FI: { lat: 61.92, lon: 25.74 }, Finland: { lat: 61.92, lon: 25.74 },
  DK: { lat: 56.26, lon: 9.5 }, Denmark: { lat: 56.26, lon: 9.5 },
  BE: { lat: 50.5, lon: 4.47 }, Belgium: { lat: 50.5, lon: 4.47 },
  CH: { lat: 46.81, lon: 8.22 }, Switzerland: { lat: 46.81, lon: 8.22 },
  AT: { lat: 47.51, lon: 14.55 }, Austria: { lat: 47.51, lon: 14.55 },
  IE: { lat: 53.41, lon: -8.24 }, Ireland: { lat: 53.41, lon: -8.24 },
  PT: { lat: 39.39, lon: -8.22 }, Portugal: { lat: 39.39, lon: -8.22 },
  GR: { lat: 39.07, lon: 21.82 }, Greece: { lat: 39.07, lon: 21.82 },
  CZ: { lat: 49.81, lon: 15.47 }, 'Czech Republic': { lat: 49.81, lon: 15.47 }, Czechia: { lat: 49.81, lon: 15.47 },
  RO: { lat: 45.94, lon: 24.96 }, Romania: { lat: 45.94, lon: 24.96 },
  HU: { lat: 47.16, lon: 19.5 }, Hungary: { lat: 47.16, lon: 19.5 },
  BG: { lat: 42.73, lon: 25.48 }, Bulgaria: { lat: 42.73, lon: 25.48 },

  // Americas
  US: { lat: 37.09, lon: -95.71 }, 'United States': { lat: 37.09, lon: -95.71 }, USA: { lat: 37.09, lon: -95.71 },
  CA: { lat: 56.13, lon: -106.34 }, Canada: { lat: 56.13, lon: -106.34 },
  MX: { lat: 23.63, lon: -102.55 }, Mexico: { lat: 23.63, lon: -102.55 },
  BR: { lat: -14.23, lon: -51.92 }, Brazil: { lat: -14.23, lon: -51.92 },
  AR: { lat: -38.41, lon: -63.61 }, Argentina: { lat: -38.41, lon: -63.61 },
  CL: { lat: -35.67, lon: -71.54 }, Chile: { lat: -35.67, lon: -71.54 },
  CO: { lat: 4.57, lon: -74.29 }, Colombia: { lat: 4.57, lon: -74.29 },
  PE: { lat: -9.18, lon: -75.01 }, Peru: { lat: -9.18, lon: -75.01 },

  // Oceania
  AU: { lat: -25.27, lon: 133.77 }, Australia: { lat: -25.27, lon: 133.77 },
  NZ: { lat: -40.9, lon: 174.88 }, 'New Zealand': { lat: -40.9, lon: 174.88 },

  // Africa
  ZA: { lat: -30.55, lon: 22.93 }, 'South Africa': { lat: -30.55, lon: 22.93 },
  EG: { lat: 26.82, lon: 30.8 }, Egypt: { lat: 26.82, lon: 30.8 },
  NG: { lat: 9.08, lon: 8.67 }, Nigeria: { lat: 9.08, lon: 8.67 },
  KE: { lat: -0.02, lon: 37.9 }, Kenya: { lat: -0.02, lon: 37.9 },
  MA: { lat: 31.79, lon: -7.09 }, Morocco: { lat: 31.79, lon: -7.09 },
};
