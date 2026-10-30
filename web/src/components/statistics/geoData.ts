// Geographical continent boundary coordinates and country origins for WAF Geo Location mapping.

import { countryCentroids } from './country-coordinates';

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

// Country names and common aliases resolve to their ISO 3166-1 alpha-2 centroid
// so telemetry keys work whether they are stored as "US" or "United States".
const countryNameAliases: Record<string, string> = {
  China: 'CN', India: 'IN', Japan: 'JP', 'South Korea': 'KR', Korea: 'KR',
  Singapore: 'SG', Vietnam: 'VN', Indonesia: 'ID', Thailand: 'TH',
  Malaysia: 'MY', Philippines: 'PH', Pakistan: 'PK', Bangladesh: 'BD',
  'Hong Kong': 'HK', Taiwan: 'TW', Iran: 'IR', Israel: 'IL',
  'Saudi Arabia': 'SA', 'United Arab Emirates': 'AE', UAE: 'AE',
  Turkey: 'TR', Türkiye: 'TR',

  'United Kingdom': 'GB', UK: 'GB', Germany: 'DE', France: 'FR',
  Netherlands: 'NL', Italy: 'IT', Spain: 'ES', Russia: 'RU', Ukraine: 'UA',
  Poland: 'PL', Sweden: 'SE', Norway: 'NO', Finland: 'FI', Denmark: 'DK',
  Belgium: 'BE', Switzerland: 'CH', Austria: 'AT', Ireland: 'IE',
  Portugal: 'PT', Greece: 'GR', 'Czech Republic': 'CZ', Czechia: 'CZ',
  Romania: 'RO', Hungary: 'HU', Bulgaria: 'BG',

  'United States': 'US', USA: 'US', Canada: 'CA', Mexico: 'MX', Brazil: 'BR',
  Argentina: 'AR', Chile: 'CL', Colombia: 'CO', Peru: 'PE',

  Australia: 'AU', 'New Zealand': 'NZ',

  'South Africa': 'ZA', Egypt: 'EG', Nigeria: 'NG', Kenya: 'KE', Morocco: 'MA',
};

export const countryCoords: Record<string, { lat: number; lon: number }> = {
  ...countryCentroids,
  ...Object.fromEntries(
    Object.entries(countryNameAliases)
      .filter(([, iso]) => countryCentroids[iso] !== undefined)
      .map(([name, iso]) => [name, countryCentroids[iso]]),
  ),
};
