import React from 'react';
import {
  CheckCircle2,
  ShieldAlert,
  Info,
  X,
  Laptop,
  Smartphone,
  ChevronRight,
  Bell,
} from 'lucide-react';
import { NotificationItemDto, NotificationSeverity } from '../../packages/shared-types/src/index.ts';
import {
  VAJRA_ATMOSPHERE_PRESETS,
  VajraAtmosphereIntensity,
} from '../styles/designTokens.ts';

/**
 * VajraCinematicBackground — Part 1, Part 17, Part 19
 * Adaptive 5-layer visual atmosphere for the authenticated VAJRA console:
 * 1. VIDEO (Cloudinary sculptural Vajra video with controlled brightness/contrast/opacity)
 * 2. COLOR-PRESERVING DARK SCRIM (deep smoked obsidian gradient preserving warm bronze highlights)
 * 3. SUBTLE ATMOSPHERIC BLEND (edge vignette + soft bronze/jade ambient depth)
 * 4. UI SURFACES (rendered above in z-10)
 * 5. CONTENT
 *
 * Respects prefers-reduced-motion, user video toggle, and automatic network fallback.
 */
export function VajraCinematicBackground({
  videoUrl,
  enabled = true,
  intensity = 'balanced',
  videoFailed = false,
  onVideoError,
}: {
  videoUrl: string;
  enabled?: boolean;
  intensity?: VajraAtmosphereIntensity;
  videoFailed?: boolean;
  onVideoError?: () => void;
}) {
  const preset = VAJRA_ATMOSPHERE_PRESETS[intensity] ?? VAJRA_ATMOSPHERE_PRESETS.balanced;
  const showVideo = Boolean(enabled && videoUrl && !videoFailed);

  return (
    <div className="vajra-cinematic-root" aria-hidden="true">
      {showVideo && (
        <video
          className="vajra-cinematic-video"
          src={videoUrl}
          autoPlay
          loop
          muted
          playsInline
          preload="auto"
          style={{
            opacity: preset.videoOpacity,
            filter: `brightness(${preset.videoBrightness}) contrast(${preset.videoContrast}) saturate(${preset.videoSaturation})`,
          }}
          onError={onVideoError}
        />
      )}

      {/* Layer 2: Color-preserving warm bronze-obsidian scrim */}
      <div
        className="vajra-cinematic-scrim"
        style={{
          background: `linear-gradient(180deg, rgba(10, 9, 8, ${preset.scrimTopAlpha}) 0%, rgba(16, 13, 10, ${preset.scrimCenterAlpha}) 48%, rgba(8, 9, 11, ${preset.scrimBottomAlpha}) 100%)`,
        }}
      />

      {/* Layer 3: Subtle warm bronze & champagne atmospheric blend */}
      <div
        className="vajra-cinematic-blend"
        style={{
          backgroundImage: `radial-gradient(ellipse 92% 86% at 50% 46%, rgba(199, 154, 90, 0.03) 0%, rgba(10, 9, 8, 0.22) 70%, rgba(8, 9, 11, 0.56) 100%), radial-gradient(ellipse 68% 48% at 50% 18%, rgba(199, 154, 90, ${preset.bronzeGlowAlpha}), transparent 72%), radial-gradient(ellipse 48% 36% at 84% 16%, rgba(120, 185, 153, 0.035), transparent 70%)`,
        }}
      />
    </div>
  );
}

/**
 * Refined Minimal VAJRA Protection Mark
 */
export function VajraSymbol({
  className = 'w-6 h-6',
  tone = 'gold',
}: {
  className?: string;
  tone?: 'gold' | 'bronze' | 'ivory' | 'jade' | 'monochrome';
}) {
  const colorMap: Record<typeof tone, string> = {
    gold: '#C79A5A',
    bronze: '#C79A5A',
    ivory: '#F4F1EA',
    jade: '#78B999',
    monochrome: 'currentColor',
  };
  const strokeColor = colorMap[tone];

  return (
    <svg
      viewBox="0 0 36 36"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={className}
      aria-hidden="true"
    >
      <path
        d="M18 3.5L24.2 12L18 17.2L11.8 12L18 3.5Z"
        stroke={strokeColor}
        strokeWidth="1.65"
        strokeLinejoin="round"
      />
      <path
        d="M18 32.5L24.2 24L18 18.8L11.8 24L18 32.5Z"
        stroke={strokeColor}
        strokeWidth="1.65"
        strokeLinejoin="round"
      />
      <path
        d="M5.5 18L11.5 14.2V21.8L5.5 18Z"
        stroke={strokeColor}
        strokeWidth="1.4"
        strokeLinejoin="round"
        strokeOpacity="0.82"
      />
      <path
        d="M30.5 18L24.5 14.2V21.8L30.5 18Z"
        stroke={strokeColor}
        strokeWidth="1.4"
        strokeLinejoin="round"
        strokeOpacity="0.82"
      />
      <rect
        x="16.1"
        y="16.1"
        width="3.8"
        height="3.8"
        transform="rotate(45 18 18)"
        fill={strokeColor}
      />
    </svg>
  );
}

export function VajraWordmarkSvg({
  className = 'h-6 w-auto',
  color = '#F4F1EA',
}: {
  className?: string;
  color?: string;
}) {
  return (
    <svg
      viewBox="0 0 218 40"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={className}
      role="img"
      aria-label="VAJRA"
    >
      <path
        d="M4.5 6.5H14.8V8.1H12.1L21.4 30.2L29.8 8.1H27.1V6.5H35.2V8.1H32.6L21.2 35.5H19.4L7.1 8.1H4.5V6.5Z"
        fill={color}
      />
      <path
        d="M54.8 5.8H56.6L68.4 33.4H71.1V35H60.6V33.4H63.5L60.4 25.8H48.7L45.5 33.4H48.4V35H39.8V33.4H42.5L54.8 5.8ZM54.6 11.4L49.5 23.8H59.6L54.6 11.4Z"
        fill={color}
      />
      <path
        d="M84.5 6.5H95.4V8.1H92.1V26.6C92.1 32.3 88.6 35.6 83.0 35.6C78.8 35.6 76.2 33.4 76.2 30.8C76.2 29.3 77.3 28.3 78.7 28.3C80.1 28.3 81.1 29.2 81.2 30.6C81.3 32.1 82.1 33.5 83.9 33.5C86.6 33.5 87.9 31.1 87.9 26.8V8.1H84.5V6.5Z"
        fill={color}
      />
      <path
        d="M107.6 6.5H120.8C127.6 6.5 131.6 9.6 131.6 14.3C131.6 18.4 128.5 21.3 123.5 22.1L131.8 33.4H134.5V35H127.8L119.8 22.6H115.6V33.4H118.8V35H107.6V33.4H111.4V8.1H107.6V6.5ZM115.6 8.5V20.6H120.2C124.8 20.6 127.1 18.3 127.1 14.4C127.1 10.6 124.7 8.5 120.3 8.5H115.6Z"
        fill={color}
      />
      <path
        d="M155.2 5.8H157.0L168.8 33.4H171.5V35H161.0V33.4H163.9L160.8 25.8H149.1L145.9 33.4H148.8V35H140.2V33.4H142.9L155.2 5.8ZM155.0 11.4L149.9 23.8H160.0L155.0 11.4Z"
        fill={color}
      />
    </svg>
  );
}

export function VajraWordmark({
  showSubtitle = false,
  size = 'md',
}: {
  showSubtitle?: boolean;
  size?: 'xs' | 'sm' | 'md' | 'lg' | 'xl';
}) {
  const sizeConfig: Record<
    typeof size,
    { wordmarkText: string; subtitleText: string; gap: string }
  > = {
    xs: {
      wordmarkText: 'text-base tracking-[0.06em]',
      subtitleText: 'text-[8px] tracking-[0.20em]',
      gap: 'mt-0.5',
    },
    sm: {
      wordmarkText: 'text-lg tracking-[0.06em]',
      subtitleText: 'text-[8.5px] tracking-[0.21em]',
      gap: 'mt-1',
    },
    md: {
      wordmarkText: 'text-2xl tracking-[0.065em]',
      subtitleText: 'text-[9.5px] tracking-[0.22em]',
      gap: 'mt-1',
    },
    lg: {
      wordmarkText: 'text-3xl sm:text-4xl tracking-[0.065em]',
      subtitleText: 'text-[10.5px] tracking-[0.22em]',
      gap: 'mt-1.5',
    },
    xl: {
      wordmarkText: 'text-4xl sm:text-5xl tracking-[0.07em]',
      subtitleText: 'text-[11px] tracking-[0.23em]',
      gap: 'mt-2',
    },
  };

  const current = sizeConfig[size];

  return (
    <div className="inline-flex flex-col justify-center">
      <span
        style={{ fontFamily: "'Cormorant Garamond', Georgia, serif" }}
        className={`font-wordmark font-semibold uppercase text-[#F4F1EA] leading-none select-none ${current.wordmarkText}`}
      >
        VAJRA
      </span>
      {showSubtitle && (
        <span
          className={`font-sans font-medium uppercase text-[#A6A8B1] leading-none ${current.subtitleText} ${current.gap}`}
        >
          PERSONAL SECURITY
        </span>
      )}
    </div>
  );
}

export function VajraBrandLockup({
  variant = 'primary',
}: {
  variant?: 'primary' | 'compact-sidebar' | 'wordmark-only' | 'emblem-wordmark' | 'small-app';
}) {
  if (variant === 'wordmark-only') {
    return <VajraWordmark showSubtitle size="lg" />;
  }

  if (variant === 'emblem-wordmark') {
    return (
      <div className="inline-flex items-center gap-4">
        <VajraSymbol className="w-6 h-6 shrink-0" tone="gold" />
        <VajraWordmark showSubtitle={false} size="lg" />
      </div>
    );
  }

  if (variant === 'compact-sidebar') {
    return (
      <div className="inline-flex items-center gap-3.5">
        <VajraSymbol className="w-5 h-5 shrink-0" tone="gold" />
        <VajraWordmark showSubtitle size="sm" />
      </div>
    );
  }

  if (variant === 'small-app') {
    return (
      <div className="inline-flex items-center gap-2.5">
        <VajraSymbol className="w-4 h-4 shrink-0" tone="gold" />
        <VajraWordmark showSubtitle={false} size="xs" />
      </div>
    );
  }

  return (
    <div className="inline-flex items-center gap-4">
      <VajraSymbol className="w-7 h-7 shrink-0" tone="gold" />
      <VajraWordmark showSubtitle size="md" />
    </div>
  );
}

/**
 * StatusBadge — Calm, unboxed status indicator using semantic colors:
 * - Protected / Jade: #78B999
 * - Attention / Warning: #D6A15A
 * - High Risk / Critical: #D06C64
 * - Neutral / Default: #A6A8B1
 */
export type StatusTone =
  | 'protected'
  | 'jade'
  | 'success'
  | 'attention'
  | 'warning'
  | 'risk'
  | 'critical'
  | 'error'
  | 'neutral'
  | 'default'
  | 'info'
  | 'gold';

export function StatusBadge({
  label,
  tone = 'neutral',
  showDot = true,
}: {
  label: string;
  tone?: StatusTone;
  showDot?: boolean;
}) {
  const toneConfig: Record<StatusTone, { dot: string; text: string }> = {
    protected: { dot: 'bg-[#78B999]', text: 'text-[#78B999]' },
    jade: { dot: 'bg-[#78B999]', text: 'text-[#78B999]' },
    success: { dot: 'bg-[#78B999]', text: 'text-[#78B999]' },
    attention: { dot: 'bg-[#D6A15A]', text: 'text-[#D6A15A]' },
    warning: { dot: 'bg-[#D6A15A]', text: 'text-[#D6A15A]' },
    risk: { dot: 'bg-[#D06C64]', text: 'text-[#D06C64]' },
    critical: { dot: 'bg-[#D06C64]', text: 'text-[#D06C64]' },
    error: { dot: 'bg-[#D06C64]', text: 'text-[#D06C64]' },
    gold: { dot: 'bg-[#C79A5A]', text: 'text-[#D9B980]' },
    info: { dot: 'bg-[#7D9BB8]', text: 'text-[#A6A8B1]' },
    neutral: { dot: 'bg-[#6E727D]', text: 'text-[#A6A8B1]' },
    default: { dot: 'bg-[#6E727D]', text: 'text-[#A6A8B1]' },
  };
  const current = toneConfig[tone] ?? toneConfig.neutral;

  return (
    <span className={`inline-flex items-center gap-2 text-xs font-medium tracking-wide ${current.text}`}>
      {showDot && <span className={`w-1.5 h-1.5 rounded-full ${current.dot} shrink-0`} />}
      {label ? <span>{label}</span> : null}
    </span>
  );
}

/**
 * PrimaryButton — Warm bronze/champagne action button (#C79A5A -> #D9B980 hover)
 * Used sparingly for primary commands across each view.
 */
export function PrimaryButton({
  children,
  onClick,
  disabled,
  type = 'button',
  tone = 'gold',
  className = '',
}: {
  children: React.ReactNode;
  onClick?: () => void;
  disabled?: boolean;
  type?: 'button' | 'submit';
  tone?: 'gold' | 'danger' | 'neutral';
  className?: string;
}) {
  const toneClasses =
    tone === 'danger'
      ? 'bg-[#D06C64] hover:bg-[#dc7d75] text-[#08090B] font-semibold'
      : tone === 'neutral'
      ? 'bg-[#F4F1EA] hover:bg-white text-[#08090B] font-semibold'
      : 'bg-[#C79A5A] hover:bg-[#D9B980] text-[#08090B] font-semibold shadow-[0_8px_24px_-8px_rgba(199,154,90,0.45)]';

  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled}
      className={`inline-flex items-center justify-center gap-2 px-4 py-2.5 rounded-[10px] text-xs tracking-wide transition-all duration-150 disabled:opacity-45 cursor-pointer ${toneClasses} ${className}`}
    >
      {children}
    </button>
  );
}

/**
 * SecondaryButton — Smoked translucent obsidian secondary action with subtle border
 */
export function SecondaryButton({
  children,
  onClick,
  disabled,
  type = 'button',
  tone = 'default',
  className = '',
}: {
  children: React.ReactNode;
  onClick?: () => void;
  disabled?: boolean;
  type?: 'button' | 'submit';
  tone?: 'default' | 'danger';
  className?: string;
}) {
  const toneClasses =
    tone === 'danger'
      ? 'bg-[#151519]/80 hover:bg-[#D06C64]/15 text-[#D06C64] border border-[#D06C64]/30 hover:border-[#D06C64]/60'
      : 'bg-[#151519]/80 hover:bg-[#1C1D23]/90 text-[#F4F1EA] border border-[#F4F1EA]/10 hover:border-[#C79A5A]/30';

  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled}
      className={`inline-flex items-center justify-center gap-2 px-4 py-2.5 rounded-[10px] text-xs font-medium tracking-wide transition-all duration-150 disabled:opacity-45 cursor-pointer ${toneClasses} ${className}`}
    >
      {children}
    </button>
  );
}

/**
 * PageHeader — Restrained editorial page title with optional right-aligned action
 */
export function PageHeader({
  eyebrow,
  title,
  subtitle,
  action,
}: {
  eyebrow?: string;
  title: string;
  subtitle?: string;
  action?: React.ReactNode;
}) {
  return (
    <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4 pb-6 border-b border-[#F4F1EA]/8">
      <div>
        {eyebrow && (
          <p className="text-[11px] font-medium uppercase tracking-[0.16em] text-[#C79A5A] mb-2">
            {eyebrow}
          </p>
        )}
        <h1 className="font-display text-2xl sm:text-3xl font-semibold text-[#F4F1EA] tracking-tight">
          {title}
        </h1>
        {subtitle && (
          <p className="text-sm text-[#A6A8B1] mt-1.5 max-w-2xl leading-relaxed">
            {subtitle}
          </p>
        )}
      </div>
      {action && <div className="shrink-0 flex items-center gap-2.5">{action}</div>}
    </div>
  );
}

/**
 * SecuritySection — Structured content section with optional eyebrow label ("01 · PROTECTION COMMAND CENTER")
 */
export function SecuritySection({
  eyebrow,
  title,
  subtitle,
  description,
  action,
  children,
  className = '',
}: {
  eyebrow?: string;
  title: string;
  subtitle?: string;
  description?: string;
  action?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
}) {
  const effectiveSubtitle = subtitle ?? description;
  return (
    <section className={`space-y-4 ${className}`}>
      <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-3">
        <div>
          {eyebrow && (
            <div className="text-[10px] font-semibold uppercase tracking-[0.20em] text-[#C79A5A] mb-1">
              {eyebrow}
            </div>
          )}
          <h2 className="font-display text-base sm:text-lg font-semibold text-[#F4F1EA] tracking-tight">
            {title}
          </h2>
          {effectiveSubtitle && (
            <p className="text-xs text-[#A6A8B1] mt-0.5">{effectiveSubtitle}</p>
          )}
        </div>
        {action && <div className="shrink-0">{action}</div>}
      </div>
      <div>{children}</div>
    </section>
  );
}

/**
 * SecurityScore — Part 9: Protection Score Centerpiece
 * Precision security instrument ring with warm bronze/jade status arc and sculptural Vajra emblem.
 */
export function SecurityScore({
  score,
  status,
  statusLabel,
  explanation,
  summary,
}: {
  score: number;
  status?: string;
  statusLabel?: string;
  explanation?: string;
  summary?: string;
}) {
  const effectiveStatus = statusLabel ?? status ?? 'Protected';
  const effectiveExplanation =
    summary ?? explanation ?? 'Continuous protection active across your devices.';
  const clampedScore = Math.max(0, Math.min(100, Math.round(score)));
  const radius = 58;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (clampedScore / 100) * circumference;

  const isHealthy = clampedScore >= 85;
  const isAttention = clampedScore >= 65 && clampedScore < 85;
  const arcColor = isHealthy ? '#78B999' : isAttention ? '#D6A15A' : '#D06C64';
  const statusTone: StatusTone = isHealthy ? 'protected' : isAttention ? 'attention' : 'risk';

  return (
    <div className="vajra-surface-elevated rounded-[18px] p-6 sm:p-7 flex flex-col sm:flex-row items-center gap-6">
      {/* Precision Ring Instrument */}
      <div className="relative w-36 h-36 flex items-center justify-center shrink-0 vajra-score-aura rounded-full">
        <svg className="w-36 h-36 -rotate-90" viewBox="0 0 136 136" aria-hidden="true">
          <circle
            cx="68"
            cy="68"
            r="64"
            stroke="rgba(244, 241, 234, 0.06)"
            strokeWidth="1"
            strokeDasharray="2 4"
            fill="none"
          />
          <circle
            cx="68"
            cy="68"
            r={radius}
            stroke="rgba(244, 241, 234, 0.09)"
            strokeWidth="4.5"
            fill="none"
          />
          <circle
            cx="68"
            cy="68"
            r={radius}
            stroke={arcColor}
            strokeWidth="4.5"
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            fill="none"
            className="transition-all duration-700 ease-out"
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
          <VajraSymbol
            className="w-4 h-4 mb-1 opacity-85"
            tone={isHealthy ? 'jade' : 'gold'}
          />
          <span className="font-display text-3xl font-bold text-[#F4F1EA] tracking-tight leading-none tabular-nums">
            {clampedScore}
          </span>
          <span className="text-[9px] uppercase tracking-[0.18em] text-[#A6A8B1] mt-1">
            INDEX
          </span>
        </div>
      </div>

      {/* Instrument Readout */}
      <div className="space-y-2 text-center sm:text-left">
        <StatusBadge label={effectiveStatus} tone={statusTone} />
        <div className="text-xs font-medium text-[#F4F1EA]">
          Protection Index · {clampedScore}/100
        </div>
        <p className="text-xs text-[#A6A8B1] leading-relaxed max-w-xs">
          {effectiveExplanation}
        </p>
      </div>
    </div>
  );
}

/**
 * SummaryStrip — Smoked obsidian metric strip with restrained semantic indicators
 */
export function SummaryStrip({
  items,
}: {
  items: ReadonlyArray<{
    label: string;
    value: string | number;
    subtext?: string;
    detail?: string;
    tone?: StatusTone;
    onClick?: () => void;
  }>;
}) {
  return (
    <div className="grid grid-cols-2 lg:grid-cols-4 divide-y sm:divide-y-0 sm:divide-x divide-[#F4F1EA]/8 vajra-surface-card rounded-[14px] overflow-hidden">
      {items.map((item, idx) => {
        const subLabel = item.subtext ?? item.detail;
        return (
          <div
            key={idx}
            onClick={item.onClick}
            className={`p-5 transition-colors ${
              item.onClick ? 'hover:bg-[#F4F1EA]/[0.03] cursor-pointer' : ''
            }`}
          >
            <p className="text-[11px] font-medium uppercase tracking-[0.14em] text-[#A6A8B1]">
              {item.label}
            </p>
            <div className="mt-2 flex items-baseline justify-between gap-2">
              <span className="font-display text-xl font-semibold text-[#F4F1EA] tracking-tight tabular-nums">
                {item.value}
              </span>
              {item.tone && <StatusBadge label="" tone={item.tone} showDot />}
            </div>
            {subLabel && (
              <p className="text-xs text-[#6E727D] mt-1 truncate">{subLabel}</p>
            )}
          </div>
        );
      })}
    </div>
  );
}

/**
 * DeviceCard — Part 10: Device Cards
 * Smoked obsidian surface card with restrained semantic status indicator and subtle bronze hover border.
 */
export function DeviceCard({
  name,
  platform,
  osVersion,
  securityHealthLabel,
  statusLabel,
  statusTone,
  lastSeenLabel,
  locationSummary,
  isCurrentSession,
  isDemo,
  onSelect,
}: {
  name: string;
  platform: 'WINDOWS' | 'ANDROID' | 'UNKNOWN' | string;
  osVersion?: string;
  securityHealthLabel?: string;
  statusLabel: string;
  statusTone: StatusTone;
  lastSeenLabel: string;
  locationSummary?: string;
  isCurrentSession?: boolean;
  isDemo?: boolean;
  onSelect?: () => void;
}) {
  const isMobile = platform.toLowerCase().includes('android');
  const Icon = isMobile ? Smartphone : Laptop;
  const platformDisplay = isMobile ? 'Android' : 'Windows';

  return (
    <div
      onClick={onSelect}
      className="group vajra-surface-card vajra-surface-card-interactive rounded-[14px] p-5 cursor-pointer flex flex-col justify-between gap-5"
    >
      <div className="flex items-start justify-between gap-4">
        <div className="flex items-start gap-3.5 min-w-0">
          <div className="w-10 h-10 rounded-[10px] bg-[#F4F1EA]/[0.04] border border-[#F4F1EA]/8 flex items-center justify-center text-[#A6A8B1] group-hover:text-[#D9B980] group-hover:border-[#C79A5A]/30 transition-colors shrink-0">
            <Icon className="w-4 h-4" />
          </div>
          <div className="min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <h3 className="font-display text-sm font-semibold text-[#F4F1EA] truncate group-hover:text-white transition-colors">
                {name}
              </h3>
              {isCurrentSession && (
                <span className="text-[10px] font-medium uppercase tracking-[0.12em] text-[#C79A5A]">
                  · Current
                </span>
              )}
              {isDemo && (
                <span className="text-[10px] font-medium uppercase tracking-[0.12em] text-[#6E727D]">
                  · Preview
                </span>
              )}
            </div>
            <p className="text-xs text-[#A6A8B1] mt-0.5 truncate">
              {platformDisplay}
              {securityHealthLabel ? ` · ${securityHealthLabel}` : osVersion ? ` · ${osVersion}` : ''}
            </p>
          </div>
        </div>
        <StatusBadge label={statusLabel} tone={statusTone} />
      </div>

      <div className="pt-3.5 border-t border-[#F4F1EA]/6 flex items-center justify-between gap-3 text-xs text-[#6E727D]">
        <span className="truncate">
          Last check-in: {lastSeenLabel}
          {locationSummary ? ` · ${locationSummary}` : ''}
        </span>
        <span className="inline-flex items-center gap-1 text-[#A6A8B1] group-hover:text-[#D9B980] transition-colors shrink-0 font-medium">
          Manage
          <ChevronRight className="w-3.5 h-3.5" />
        </span>
      </div>
    </div>
  );
}

/**
 * AlertCard — Part 11: Security Advisories
 * Editorial security advisory card with left semantic accent bar and calm actionable guidance.
 */
export function AlertCard({
  title,
  explanation,
  severity,
  timestampLabel,
  timeLabel,
  deviceName,
  primaryActionLabel,
  actionLabel,
  onPrimaryAction,
  onReview,
  secondaryActionLabel,
  onSecondaryAction,
}: {
  title: string;
  explanation: string;
  severity: 'High' | 'Attention' | 'Info' | 'Information' | 'Critical' | 'Warning';
  timestampLabel?: string;
  timeLabel?: string;
  deviceName?: string;
  primaryActionLabel?: string;
  actionLabel?: string;
  onPrimaryAction?: () => void;
  onReview?: () => void;
  secondaryActionLabel?: string;
  onSecondaryAction?: () => void;
}) {
  const effectiveTime = timestampLabel ?? timeLabel ?? 'Just now';
  const effectivePrimaryLabel = primaryActionLabel ?? actionLabel;
  const effectivePrimaryHandler = onPrimaryAction ?? onReview;

  const isHigh = severity === 'High' || severity === 'Critical';
  const isAttention = severity === 'Attention' || severity === 'Warning';

  const config = isHigh
    ? {
        accentBar: 'bg-[#D06C64]',
        iconColor: 'text-[#D06C64]',
        badgeLabel: 'High Risk',
        badgeTone: 'risk' as StatusTone,
        Icon: ShieldAlert,
      }
    : isAttention
    ? {
        accentBar: 'bg-[#D6A15A]',
        iconColor: 'text-[#D6A15A]',
        badgeLabel: 'Attention',
        badgeTone: 'attention' as StatusTone,
        Icon: ShieldAlert,
      }
    : {
        accentBar: 'bg-[#78B999]',
        iconColor: 'text-[#78B999]',
        badgeLabel: 'Advisory',
        badgeTone: 'protected' as StatusTone,
        Icon: Info,
      };

  const Icon = config.Icon;

  return (
    <div className="relative vajra-surface-card rounded-[14px] p-5 pl-6 overflow-hidden transition-colors hover:border-[#C79A5A]/25">
      <div className={`absolute left-0 top-0 bottom-0 w-1 ${config.accentBar}`} />

      <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4">
        <div className="flex items-start gap-3.5 min-w-0">
          <Icon className={`w-4 h-4 mt-0.5 shrink-0 ${config.iconColor}`} />
          <div className="space-y-1.5 min-w-0">
            <div className="flex items-center gap-2.5 flex-wrap">
              <StatusBadge label={config.badgeLabel} tone={config.badgeTone} showDot={false} />
              {deviceName && (
                <>
                  <span className="text-[#6E727D] text-xs">·</span>
                  <span className="text-xs font-medium text-[#A6A8B1]">{deviceName}</span>
                </>
              )}
              <span className="text-[#6E727D] text-xs">·</span>
              <span className="text-xs text-[#6E727D]">{effectiveTime}</span>
            </div>
            <h3 className="font-display text-sm font-semibold text-[#F4F1EA] leading-snug">
              {title}
            </h3>
            <p className="text-xs text-[#A6A8B1] leading-relaxed max-w-2xl">{explanation}</p>
          </div>
        </div>

        {(effectivePrimaryLabel || secondaryActionLabel) && (
          <div className="flex items-center gap-2 shrink-0 sm:self-center pl-7 sm:pl-0">
            {secondaryActionLabel && onSecondaryAction && (
              <SecondaryButton onClick={onSecondaryAction} className="px-3 py-1.5 text-[11px]">
                {secondaryActionLabel}
              </SecondaryButton>
            )}
            {effectivePrimaryLabel && effectivePrimaryHandler && (
              <PrimaryButton onClick={effectivePrimaryHandler} className="px-3.5 py-1.5 text-[11px]">
                {effectivePrimaryLabel}
              </PrimaryButton>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

/**
 * TimelineItem — Part 12: Activity Timeline
 * Chronological security event row with semantic status dot and clean metadata.
 */
export function TimelineItem({
  title,
  summary,
  description,
  category,
  subtitle,
  severity,
  relativeTime,
  clockTime,
  isLast,
}: {
  title: string;
  summary?: string;
  description?: string;
  category?: string;
  subtitle?: string;
  severity: 'Healthy' | 'Info' | 'Information' | 'Attention' | 'High' | 'Critical' | 'Warning';
  relativeTime?: string;
  clockTime?: string;
  isLast?: boolean;
}) {
  const effectiveSummary = summary ?? description ?? '';
  const effectiveCategory = category ?? subtitle ?? 'Security';
  const effectiveTime = relativeTime ?? clockTime ?? '';

  const dotColor =
    severity === 'High' || severity === 'Critical'
      ? 'bg-[#D06C64]'
      : severity === 'Attention' || severity === 'Warning'
      ? 'bg-[#D6A15A]'
      : severity === 'Healthy'
      ? 'bg-[#78B999]'
      : 'bg-[#C79A5A]';

  return (
    <div className="relative flex items-start gap-4 py-3.5 group">
      {!isLast && (
        <div
          className="absolute left-[7px] top-6 bottom-0 w-px bg-[#F4F1EA]/8"
          aria-hidden="true"
        />
      )}
      <div className="relative z-10 mt-1.5 w-3.5 h-3.5 rounded-full bg-[#111216] border border-[#F4F1EA]/15 flex items-center justify-center shrink-0">
        <span className={`w-1.5 h-1.5 rounded-full ${dotColor}`} />
      </div>

      <div className="flex-1 min-w-0 flex flex-col sm:flex-row sm:items-baseline justify-between gap-1 sm:gap-4">
        <div className="min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <p className="text-sm font-medium text-[#F4F1EA]">{title}</p>
            {effectiveCategory && (
              <span className="text-[11px] text-[#6E727D]">· {effectiveCategory}</span>
            )}
          </div>
          {effectiveSummary && (
            <p className="text-xs text-[#A6A8B1] mt-0.5 leading-relaxed">{effectiveSummary}</p>
          )}
        </div>
        <div className="shrink-0 text-right">
          <span className="text-xs text-[#A6A8B1] tabular-nums">{effectiveTime}</span>
          {relativeTime && clockTime && (
            <span className="hidden sm:inline text-[11px] text-[#6E727D] ml-1.5">
              ({clockTime})
            </span>
          )}
        </div>
      </div>
    </div>
  );
}

/**
 * EmptyState — Calm, reassuring empty state when no alerts or items are present
 */
export function EmptyState({
  title,
  description,
  action,
  actionLabel,
  onAction,
}: {
  title: string;
  description: string;
  action?: React.ReactNode;
  actionLabel?: string;
  onAction?: () => void;
}) {
  return (
    <div className="vajra-surface-card rounded-[14px] p-8 text-center max-w-xl mx-auto my-2">
      <div className="w-10 h-10 rounded-full bg-[#78B999]/10 border border-[#78B999]/25 flex items-center justify-center mx-auto mb-3.5 text-[#78B999]">
        <CheckCircle2 className="w-5 h-5" />
      </div>
      <h3 className="font-display text-base font-semibold text-[#F4F1EA]">{title}</h3>
      <p className="text-xs text-[#A6A8B1] mt-1.5 leading-relaxed">{description}</p>
      {action ? (
        <div className="mt-5 flex justify-center">{action}</div>
      ) : actionLabel && onAction ? (
        <div className="mt-5">
          <SecondaryButton onClick={onAction}>{actionLabel}</SecondaryButton>
        </div>
      ) : null}
    </div>
  );
}

const FOCUSABLE_SELECTOR =
  'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

function useDialogAccessibility(open: boolean, onClose: () => void) {
  const containerRef = React.useRef<HTMLElement | null>(null);
  const triggerRef = React.useRef<HTMLElement | null>(null);
  const onCloseRef = React.useRef(onClose);
  onCloseRef.current = onClose;

  React.useEffect(() => {
    if (!open) return;

    const previousActive =
      typeof document !== 'undefined' && document.activeElement instanceof HTMLElement
        ? document.activeElement
        : null;
    triggerRef.current = previousActive;

    const focusTimer = window.setTimeout(() => {
      const container = containerRef.current;
      if (!container) return;
      if (container.contains(document.activeElement)) return;
      const focusables = Array.from(
        container.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR)
      );
      if (focusables.length > 0) {
        focusables[0].focus();
      } else {
        container.focus();
      }
    }, 0);

    const handleKeyDown = (event: KeyboardEvent) => {
      const container = containerRef.current;
      if (!container) return;

      if (event.key === 'Escape') {
        event.preventDefault();
        event.stopPropagation();
        onCloseRef.current();
        return;
      }

      if (event.key === 'Tab') {
        const focusables = Array.from(
          container.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR)
        );
        if (focusables.length === 0) {
          event.preventDefault();
          return;
        }
        const first = focusables[0];
        const last = focusables[focusables.length - 1];
        const active = document.activeElement as HTMLElement | null;

        if (event.shiftKey) {
          if (!active || active === first || !container.contains(active)) {
            event.preventDefault();
            last.focus();
          }
        } else {
          if (!active || active === last || !container.contains(active)) {
            event.preventDefault();
            first.focus();
          }
        }
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => {
      window.clearTimeout(focusTimer);
      window.removeEventListener('keydown', handleKeyDown);
      const restoreTarget = triggerRef.current;
      if (restoreTarget && typeof restoreTarget.focus === 'function') {
        window.setTimeout(() => {
          try {
            restoreTarget.focus();
          } catch {
            // ignore focus restoration failure on unmounted element
          }
        }, 0);
      }
    };
  }, [open]);

  return containerRef;
}

/**
 * DetailDrawer — Smoked obsidian slide-over drawer for device inspection and controls
 */
export function DetailDrawer({
  open,
  eyebrow,
  title,
  subtitle,
  onClose,
  children,
}: {
  open: boolean;
  eyebrow?: string;
  title: string;
  subtitle?: string;
  onClose: () => void;
  children: React.ReactNode;
}) {
  const containerRef = useDialogAccessibility(open, onClose);
  const titleId = React.useId();

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      <div
        className="fixed inset-0 bg-[#08090B]/75 backdrop-blur-xs transition-opacity"
        onClick={onClose}
      />
      <aside
        ref={(el) => {
          containerRef.current = el;
        }}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
        className="relative z-10 w-full max-w-lg vajra-surface-modal h-full overflow-y-auto p-6 sm:p-8 flex flex-col justify-between border-l border-[#F4F1EA]/10 focus:outline-none"
      >
        <div className="space-y-6">
          <div className="flex items-start justify-between gap-4 pb-5 border-b border-[#F4F1EA]/8">
            <div>
              {eyebrow && (
                <div className="text-[10px] font-semibold uppercase tracking-[0.20em] text-[#C79A5A] mb-1">
                  {eyebrow}
                </div>
              )}
              <h2
                id={titleId}
                className="font-display text-lg font-semibold text-[#F4F1EA]"
              >
                {title}
              </h2>
              {subtitle && <p className="text-xs text-[#A6A8B1] mt-1">{subtitle}</p>}
            </div>
            <button
              type="button"
              onClick={onClose}
              className="p-2 rounded-lg text-[#A6A8B1] hover:text-[#F4F1EA] hover:bg-[#F4F1EA]/5 transition-colors cursor-pointer"
              aria-label="Close panel"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
          <div>{children}</div>
        </div>
      </aside>
    </div>
  );
}

/**
 * Modal — Smoked obsidian modal dialog for confirmations and enrollment flows
 */
export function Modal({
  open,
  title,
  subtitle,
  description,
  onClose,
  children,
}: {
  open: boolean;
  title: string;
  subtitle?: string;
  description?: string;
  onClose: () => void;
  children: React.ReactNode;
}) {
  const containerRef = useDialogAccessibility(open, onClose);
  const titleId = React.useId();

  if (!open) return null;
  const effectiveDescription = description ?? subtitle;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div
        className="fixed inset-0 bg-[#08090B]/80 backdrop-blur-xs"
        onClick={onClose}
      />
      <div
        ref={(el) => {
          containerRef.current = el;
        }}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
        className="relative z-10 w-full max-w-md vajra-surface-modal rounded-[16px] p-6 sm:p-7 space-y-5 focus:outline-none"
      >
        <div className="flex items-start justify-between gap-4">
          <div>
            <h2
              id={titleId}
              className="font-display text-base font-semibold text-[#F4F1EA]"
            >
              {title}
            </h2>
            {effectiveDescription && (
              <p className="text-xs text-[#A6A8B1] mt-1 leading-relaxed">
                {effectiveDescription}
              </p>
            )}
          </div>
          <button
            type="button"
            onClick={onClose}
            className="p-1.5 rounded-lg text-[#A6A8B1] hover:text-[#F4F1EA] hover:bg-[#F4F1EA]/5 transition-colors cursor-pointer"
            aria-label="Close modal"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
        <div>{children}</div>
      </div>
    </div>
  );
}

/**
 * Toast — Floating smoked obsidian feedback banner
 */
export function Toast({
  message,
  tone = 'protected',
  onDismiss,
}: {
  message: string;
  tone?: StatusTone;
  onDismiss: () => void;
}) {
  return (
    <div className="fixed bottom-5 right-5 z-50 max-w-md vajra-surface-elevated rounded-[12px] px-4 py-3 flex items-center gap-3.5 border border-[#C79A5A]/25">
      <StatusBadge label={message} tone={tone} />
      <button
        type="button"
        onClick={onDismiss}
        className="text-[#A6A8B1] hover:text-[#F4F1EA] p-1 transition-colors cursor-pointer"
        aria-label="Dismiss notification"
      >
        <X className="w-3.5 h-3.5" />
      </button>
    </div>
  );
}

/**
 * SettingsGroup — Smoked obsidian settings card container
 */
export function SettingsGroup({
  category,
  title,
  description,
  children,
}: {
  category?: string;
  title: string;
  description?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="vajra-surface-card rounded-[14px] p-6 space-y-5">
      <div className="pb-4 border-b border-[#F4F1EA]/8">
        {category && (
          <div className="text-[10px] font-semibold uppercase tracking-[0.20em] text-[#C79A5A] mb-1">
            {category}
          </div>
        )}
        <h3 className="font-display text-sm font-semibold text-[#F4F1EA]">{title}</h3>
        {description && <p className="text-xs text-[#A6A8B1] mt-1">{description}</p>}
      </div>
      <div className="space-y-4">{children}</div>
    </div>
  );
}

/**
 * NotificationBellButton — Part 6 & Part 13: Top Header Notification Trigger
 */
export function NotificationBellButton({
  unreadCount,
  onClick,
}: {
  unreadCount: number;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-label={`Notifications${unreadCount > 0 ? ` (${unreadCount} unread)` : ''}`}
      className="relative inline-flex items-center justify-center w-9 h-9 rounded-[10px] bg-[#151519]/80 hover:bg-[#1C1D23] border border-[#F4F1EA]/8 hover:border-[#C79A5A]/30 text-[#A6A8B1] hover:text-[#F4F1EA] transition-all cursor-pointer"
    >
      <Bell className="w-4 h-4" />
      {unreadCount > 0 && (
        <span className="absolute -top-1 -right-1 min-w-[18px] h-[18px] px-1 rounded-full bg-[#C79A5A] text-[#08090B] text-[10px] font-bold flex items-center justify-center">
          {unreadCount > 9 ? '9+' : unreadCount}
        </span>
      )}
    </button>
  );
}

/**
 * NotificationSlideOverPanel — Part 13: Notification Center
 * Smoked obsidian slide-over panel with blur, unread dot, and calm severity styling.
 */
export function NotificationSlideOverPanel({
  open,
  notifications,
  unreadCount,
  onClose,
  onMarkRead,
  onMarkAllRead,
  onDismiss,
  onSelectNotification,
  onActionClick,
  formatRelativeTimeFn,
  formatRelative,
}: {
  open: boolean;
  notifications: NotificationItemDto[];
  unreadCount: number;
  onClose: () => void;
  onMarkRead: (id: string) => void;
  onMarkAllRead: () => void;
  onDismiss: (id: string) => void;
  onSelectNotification?: (notification: NotificationItemDto) => void;
  onActionClick?: (notification: NotificationItemDto) => void;
  formatRelativeTimeFn?: (iso: string) => string;
  formatRelative?: (iso: string) => string;
}) {
  const containerRef = useDialogAccessibility(open, onClose);
  const titleId = React.useId();

  if (!open) return null;

  const formatTime = formatRelativeTimeFn ?? formatRelative ?? ((iso: string) => iso);
  const handleSelect = onSelectNotification ?? onActionClick ?? (() => {});

  const mapSeverityTone = (sev: NotificationSeverity): StatusTone => {
    if (sev === 'HIGH') return 'risk';
    if (sev === 'WARNING' || sev === 'ATTENTION') return 'attention';
    if (sev === 'PROTECTED') return 'protected';
    return 'neutral';
  };

  const mapSeverityLabel = (sev: NotificationSeverity): string => {
    if (sev === 'HIGH') return 'High Risk';
    if (sev === 'WARNING' || sev === 'ATTENTION') return 'Attention';
    if (sev === 'PROTECTED') return 'Protected';
    return 'Info';
  };

  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      <div
        className="fixed inset-0 bg-[#08090B]/75 backdrop-blur-xs transition-opacity"
        onClick={onClose}
      />
      <aside
        ref={(el) => {
          containerRef.current = el;
        }}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-label="Notification Center"
        tabIndex={-1}
        className="relative z-10 w-full max-w-md vajra-surface-modal h-full flex flex-col justify-between border-l border-[#F4F1EA]/10 focus:outline-none"
      >
        {/* Header */}
        <div className="p-6 border-b border-[#F4F1EA]/8 flex items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2.5">
              <h2
                id={titleId}
                className="font-display text-base font-semibold text-[#F4F1EA]"
              >
                Notifications
              </h2>
              {unreadCount > 0 && (
                <span className="text-xs font-medium text-[#C79A5A]">
                  · {unreadCount} unread
                </span>
              )}
            </div>
            <p className="text-xs text-[#A6A8B1] mt-0.5">
              Real-time protection updates and device advisories.
            </p>
          </div>
          <div className="flex items-center gap-2">
            {unreadCount > 0 && (
              <button
                type="button"
                onClick={onMarkAllRead}
                className="text-xs font-medium text-[#C79A5A] hover:text-[#D9B980] px-2.5 py-1.5 rounded-lg hover:bg-[#F4F1EA]/5 transition-colors cursor-pointer"
              >
                Mark all read
              </button>
            )}
            <button
              type="button"
              onClick={onClose}
              className="p-2 rounded-lg text-[#A6A8B1] hover:text-[#F4F1EA] hover:bg-[#F4F1EA]/5 transition-colors cursor-pointer"
              aria-label="Close notifications"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Notification List */}
        <div className="flex-1 overflow-y-auto divide-y divide-[#F4F1EA]/6">
          {notifications.length === 0 ? (
            <div className="p-10 text-center space-y-2">
              <CheckCircle2 className="w-6 h-6 text-[#78B999] mx-auto mb-2" />
              <p className="text-sm font-medium text-[#F4F1EA]">All caught up</p>
              <p className="text-xs text-[#A6A8B1]">
                No unread security notifications or pending device advisories.
              </p>
            </div>
          ) : (
            notifications.map((item) => {
              const isUnread = !item.readAt;
              return (
                <div
                  key={item.id}
                  onClick={() => handleSelect(item)}
                  className={`p-5 transition-colors cursor-pointer hover:bg-[#F4F1EA]/[0.03] ${
                    isUnread ? 'bg-[#C79A5A]/[0.035]' : ''
                  }`}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex items-center gap-2 flex-wrap">
                      {isUnread && (
                        <span
                          className="w-2 h-2 rounded-full bg-[#C79A5A] shrink-0"
                          title="Unread"
                        />
                      )}
                      <StatusBadge
                        label={mapSeverityLabel(item.severity)}
                        tone={mapSeverityTone(item.severity)}
                        showDot={false}
                      />
                      <span className="text-[11px] text-[#6E727D]">
                        · {item.category}
                      </span>
                      <span className="text-[11px] text-[#6E727D]">
                        · {formatTime(item.createdAt)}
                      </span>
                    </div>
                    <div
                      className="flex items-center gap-1 shrink-0"
                      onClick={(e) => e.stopPropagation()}
                    >
                      {isUnread && (
                        <button
                          type="button"
                          onClick={() => onMarkRead(item.id)}
                          className="text-[11px] text-[#A6A8B1] hover:text-[#F4F1EA] px-1.5 py-0.5 rounded hover:bg-[#F4F1EA]/5 cursor-pointer"
                        >
                          Read
                        </button>
                      )}
                      <button
                        type="button"
                        onClick={() => onDismiss(item.id)}
                        className="text-[#6E727D] hover:text-[#F4F1EA] p-1 rounded hover:bg-[#F4F1EA]/5 cursor-pointer"
                        aria-label="Dismiss notification"
                      >
                        <X className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </div>
                  <h3 className="font-display text-sm font-semibold text-[#F4F1EA] mt-2 leading-snug">
                    {item.title}
                  </h3>
                  <p className="text-xs text-[#A6A8B1] mt-1 leading-relaxed">
                    {item.message}
                  </p>
                </div>
              );
            })
          )}
        </div>
      </aside>
    </div>
  );
}
