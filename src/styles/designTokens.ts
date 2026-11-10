/**
 * VAJRA — Centralized Design System Tokens
 * Prompt 0006 & Prompt 0009: Luxury Security Console + Cinematic Vajra Visual System
 *
 * Aesthetic Direction: Private digital security console — smoked obsidian depth,
 * warm bronze/champagne metallic atmosphere (#C79A5A / #C8A66A), and restrained
 * semantic status indicators (#78B999 / #D6A15A / #D06C64).
 */

export type VajraAtmosphereIntensity = 'focused' | 'balanced' | 'ambient';

export interface VajraAtmospherePreset {
  id: VajraAtmosphereIntensity;
  label: string;
  description: string;
  videoOpacity: number;
  videoBrightness: number;
  videoContrast: number;
  videoSaturation: number;
  scrimTopAlpha: number;
  scrimCenterAlpha: number;
  scrimBottomAlpha: number;
  bronzeGlowAlpha: number;
}

export const VAJRA_ATMOSPHERE_PRESETS: Record<
  VajraAtmosphereIntensity,
  VajraAtmospherePreset
> = {
  focused: {
    id: 'focused',
    label: 'Focused',
    description: 'Deep smoked obsidian with subtle bronze atmosphere for high-density workflows.',
    videoOpacity: 0.72,
    videoBrightness: 0.90,
    videoContrast: 1.08,
    videoSaturation: 1.06,
    scrimTopAlpha: 0.56,
    scrimCenterAlpha: 0.42,
    scrimBottomAlpha: 0.64,
    bronzeGlowAlpha: 0.08,
  },
  balanced: {
    id: 'balanced',
    label: 'Balanced',
    description: 'Default luxury security console balance — calm legibility with living Vajra depth.',
    videoOpacity: 0.86,
    videoBrightness: 0.96,
    videoContrast: 1.10,
    videoSaturation: 1.10,
    scrimTopAlpha: 0.44,
    scrimCenterAlpha: 0.28,
    scrimBottomAlpha: 0.52,
    bronzeGlowAlpha: 0.12,
  },
  ambient: {
    id: 'ambient',
    label: 'Ambient',
    description: 'Enhanced sculptural Vajra presence for overview and command center display.',
    videoOpacity: 0.94,
    videoBrightness: 1.02,
    videoContrast: 1.12,
    videoSaturation: 1.14,
    scrimTopAlpha: 0.34,
    scrimCenterAlpha: 0.18,
    scrimBottomAlpha: 0.42,
    bronzeGlowAlpha: 0.15,
  },
} as const;

export const VAJRA_TOKENS = {
  colors: {
    // Primary Base & Smoked Obsidian Surfaces (Prompt 0006 + Prompt 0009)
    background: '#08090B',
    deepObsidian: '#08090B',
    charcoalBlack: '#111216',
    smokedObsidianSurface: '#151519',
    surface: '#101216',
    elevatedSurface: '#15171C',
    border: '#25282E',

    // Translucent Surface Hierarchy
    translucent: {
      primaryCard: 'rgba(18, 19, 24, 0.72)',
      elevatedCard: 'rgba(24, 25, 31, 0.80)',
      modalSurface: 'rgba(15, 16, 20, 0.88)',
      sidebarSurface: 'rgba(12, 13, 17, 0.66)',
      headerSurface: 'rgba(12, 13, 17, 0.62)',
    },

    // Borders & Hairlines
    borders: {
      neutral: 'rgba(244, 241, 234, 0.08)',
      subtle: 'rgba(244, 241, 234, 0.06)',
      hoverBronze: 'rgba(199, 154, 90, 0.24)',
      activeBronze: 'rgba(199, 154, 90, 0.34)',
    },

    // Typography Colors
    text: {
      primary: '#F4F1EA',
      secondary: '#A6A8B1',
      legacySecondary: '#9499A3',
      muted: '#6E727D',
      legacyMuted: '#646A74',
    },

    // Brand Metallic & Semantic Status Accents (Restrained use)
    brand: {
      warmBronze: '#C79A5A',
      champagneGold: '#C8A66A',
      softChampagne: '#D9B980',
      mutedAntiqueGold: '#9E7B47',
      secondaryGold: '#A98750',
      protectedJade: '#78B999',
      legacyJade: '#75B798',
      information: '#7D9BB8',
      warning: '#D6A15A',
      legacyWarning: '#D1A15B',
      threat: '#D06C64',
      legacyThreat: '#C97972',
    },
  },
  typography: {
    wordmarkFamily: "'Cormorant Garamond', Georgia, serif",
    fontFamily: "'Manrope', -apple-system, BlinkMacSystemFont, sans-serif",
    monoFamily: "'IBM Plex Mono', monospace",
    wordmarkTracking: '0.06em',
    subtitleTracking: '0.22em',
    weights: {
      body: 400,
      medium: 500,
      semibold: 600,
      bold: 700,
      display: 800,
    },
  },
  spacing: {
    railWidthCollapsed: '82px',
    railWidthExpanded: '232px',
    pageMaxWidth: '1180px',
    sectionGap: '3.25rem',
  },
  radius: {
    sm: '6px',
    md: '10px',
    lg: '14px',
    xl: '18px',
  },
  transitions: {
    fast: '160ms cubic-bezier(0.22, 1, 0.36, 1)',
    smooth: '220ms cubic-bezier(0.22, 1, 0.36, 1)',
  },
} as const;
