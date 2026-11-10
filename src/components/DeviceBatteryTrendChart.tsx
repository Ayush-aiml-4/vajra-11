import React, { useMemo } from 'react';
import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  ReferenceLine,
} from 'recharts';
import { Battery, BatteryCharging, Zap, ArrowDown, ArrowUp, Info } from 'lucide-react';

export interface BatteryDataPoint {
  timestamp: string;
  time: string;
  batteryLevel: number;
  charging: boolean;
}

export interface DeviceBatteryTrendChartProps {
  deviceName: string;
  currentBatteryLevel?: number | null;
  isCharging?: boolean | null;
  readings?: BatteryDataPoint[] | null;
  loading?: boolean;
  error?: string | null;
  isSamplePreview?: boolean;
}

export function DeviceBatteryTrendChart({
  deviceName,
  currentBatteryLevel,
  isCharging,
  readings = [],
  loading = false,
  error = null,
  isSamplePreview = false,
}: DeviceBatteryTrendChartProps) {
  const data: BatteryDataPoint[] = useMemo(() => {
    if (!readings || !Array.isArray(readings)) return [];
    return readings;
  }, [readings]);

  const hasData = data.length > 0;

  // Derive metrics strictly from real readings
  const levels = data.map((d) => d.batteryLevel);
  const minLevel = levels.length > 0 ? Math.min(...levels) : currentBatteryLevel ?? null;
  const maxLevel = levels.length > 0 ? Math.max(...levels) : currentBatteryLevel ?? null;
  const avgLevel =
    levels.length > 0
      ? Math.round(levels.reduce((acc, curr) => acc + curr, 0) / levels.length)
      : currentBatteryLevel ?? null;

  const displayLevel =
    typeof currentBatteryLevel === 'number'
      ? currentBatteryLevel
      : levels.length > 0
      ? levels[levels.length - 1]
      : null;

  const displayCharging =
    typeof isCharging === 'boolean'
      ? isCharging
      : levels.length > 0
      ? data[data.length - 1].charging
      : false;

  const lineColor =
    displayLevel !== null && displayLevel <= 20
      ? '#D06C64' // Coral red
      : displayLevel !== null && displayLevel <= 40
      ? '#D6A15A' // Amber attention
      : '#78B999'; // Jade protected

  return (
    <section
      role="region"
      aria-label={`24-Hour Battery Trend for ${deviceName}`}
      className="space-y-3.5 border-t border-[#25282E] pt-5"
    >
      {/* Sample Device Preview Banner */}
      {isSamplePreview && (
        <div
          role="note"
          className="flex items-start gap-2 p-2.5 rounded-lg bg-[#C8A66A]/10 border border-[#C8A66A]/30 text-xs text-[#C8A66A]"
        >
          <Info className="w-4 h-4 mt-0.5 shrink-0 text-[#C8A66A]" />
          <div>
            <span className="font-semibold block uppercase tracking-wider text-[10px]">
              Sample Device Preview
            </span>
            <span className="text-[11px] text-[#E8D9B5] leading-relaxed">
              This is a catalog demonstration device. Live 24-hour battery telemetry requires
              an enrolled, active Android companion agent reporting heartbeats.
            </span>
          </div>
        </div>
      )}

      {/* Header with Title and Current State */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          {displayCharging ? (
            <BatteryCharging className="w-3.5 h-3.5 text-[#78B999]" aria-hidden="true" />
          ) : (
            <Battery className="w-3.5 h-3.5 text-[#C8A66A]" aria-hidden="true" />
          )}
          <h4 className="text-[10px] font-semibold uppercase tracking-[0.22em] text-[#C8A66A]">
            24-HOUR BATTERY TREND
          </h4>
        </div>
        <div className="flex items-center gap-1.5 text-xs">
          {displayLevel !== null ? (
            <>
              <span className="font-semibold text-[#F4F1EA] tabular-nums font-mono">
                {displayLevel}%
              </span>
              {displayCharging ? (
                <span className="inline-flex items-center gap-1 text-[11px] text-[#78B999]">
                  <Zap className="w-3 h-3 fill-current" aria-hidden="true" />
                  <span>Charging</span>
                </span>
              ) : (
                <span className="text-[11px] text-[#9499A3]">· Discharging</span>
              )}
            </>
          ) : (
            <span className="text-[11px] text-[#6E727D]">No reading</span>
          )}
        </div>
      </div>

      {/* Error state */}
      {error && (
        <div className="p-3 rounded-xl bg-[#2C1517] border border-[#D06C64]/40 text-xs text-[#F2B8B5]">
          {error}
        </div>
      )}

      {/* 24h Summary Stat Readouts (Zero-Pill Typography) */}
      {hasData && (
        <div className="grid grid-cols-3 gap-2 py-2 px-3 rounded-xl bg-[#08090B]/60 border border-[#25282E]/70 text-[11px]">
          <div>
            <span className="text-[#6E727D] block text-[10px] uppercase tracking-wider">
              24h High
            </span>
            <span className="text-[#F4F1EA] font-semibold tabular-nums inline-flex items-center gap-0.5">
              <ArrowUp className="w-2.5 h-2.5 text-[#78B999]" aria-hidden="true" />
              {maxLevel !== null ? `${maxLevel}%` : '—'}
            </span>
          </div>
          <div>
            <span className="text-[#6E727D] block text-[10px] uppercase tracking-wider">
              24h Low
            </span>
            <span className="text-[#F4F1EA] font-semibold tabular-nums inline-flex items-center gap-0.5">
              <ArrowDown className="w-2.5 h-2.5 text-[#D06C64]" aria-hidden="true" />
              {minLevel !== null ? `${minLevel}%` : '—'}
            </span>
          </div>
          <div>
            <span className="text-[#6E727D] block text-[10px] uppercase tracking-wider">
              Average
            </span>
            <span className="text-[#A6A8B1] font-semibold tabular-nums">
              {avgLevel !== null ? `${avgLevel}%` : '—'}
            </span>
          </div>
        </div>
      )}

      {/* Chart Surface or Honest Empty State */}
      <div className="relative w-full pt-1 pb-1 min-h-[160px]">
        {loading && (
          <div className="absolute inset-0 z-10 flex items-center justify-center bg-[#101216]/75 backdrop-blur-xs rounded-xl">
            <span className="text-xs text-[#9499A3]">Loading battery telemetry...</span>
          </div>
        )}

        {hasData ? (
          <div className="h-44 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart
                data={data}
                margin={{ top: 8, right: 12, bottom: 4, left: -14 }}
              >
                <CartesianGrid
                  strokeDasharray="3 3"
                  stroke="#25282E"
                  opacity={0.6}
                  horizontal={true}
                  vertical={false}
                />
                <XAxis
                  dataKey="time"
                  stroke="#646A74"
                  fontSize={10}
                  tickLine={false}
                  axisLine={false}
                />
                <YAxis
                  domain={[0, 100]}
                  unit="%"
                  stroke="#646A74"
                  fontSize={10}
                  tickLine={false}
                  axisLine={false}
                  tickFormatter={(v) => `${v}%`}
                />
                <ReferenceLine
                  y={20}
                  stroke="#D06C64"
                  strokeDasharray="4 4"
                  strokeWidth={1}
                />
                <Tooltip
                  content={({ active, payload, label }) => {
                    if (!active || !payload || !payload.length) return null;
                    const point = payload[0].payload as BatteryDataPoint;
                    return (
                      <div className="rounded-lg bg-[#15171C] border border-[#F4F1EA]/12 px-3 py-2 shadow-xl text-xs space-y-1">
                        <div className="text-[10px] text-[#A6A8B1] font-medium">
                          {label}
                        </div>
                        <div className="flex items-center gap-2">
                          <span
                            className="w-2 h-2 rounded-full"
                            style={{ backgroundColor: lineColor }}
                          />
                          <span className="font-semibold text-[#F4F1EA] font-mono tabular-nums">
                            {point.batteryLevel}%
                          </span>
                          {point.charging && (
                            <span className="text-[10px] text-[#78B999] inline-flex items-center gap-0.5">
                              <Zap className="w-2.5 h-2.5 fill-current" />
                              Charging
                            </span>
                          )}
                        </div>
                      </div>
                    );
                  }}
                />
                <Line
                  type="monotone"
                  dataKey="batteryLevel"
                  stroke={lineColor}
                  strokeWidth={2}
                  dot={data.length <= 12}
                  activeDot={{
                    r: 4.5,
                    fill: '#F4F1EA',
                    stroke: lineColor,
                    strokeWidth: 2,
                  }}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        ) : (
          <div className="p-4 rounded-xl bg-[#101216]/50 border border-[#25282E] text-center space-y-1.5 my-2">
            <div className="text-xs font-medium text-[#C8A66A]">
              No 24-hour battery history recorded
            </div>
            <p className="text-[11px] text-[#6E727D] max-w-xs mx-auto leading-relaxed">
              Battery readings are securely collected when the Android companion agent delivers
              authenticated heartbeats.
            </p>
            {displayLevel !== null && (
              <div className="text-[11px] text-[#9499A3] pt-1">
                Latest reported battery level: <span className="font-semibold text-[#F4F1EA]">{displayLevel}%</span>
              </div>
            )}
          </div>
        )}
      </div>

      <div className="flex items-center justify-between text-[10px] text-[#6E727D] pt-0.5">
        <span>{hasData ? `${data.length} telemetry readings recorded` : 'Telemetry awaiting device heartbeats'}</span>
        <span>Android Keystore & OS Agent</span>
      </div>
    </section>
  );
}
