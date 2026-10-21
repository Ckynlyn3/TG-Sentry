// Chart primitives ported from shadcn/ui (MIT, Copyright (c) 2023 shadcn):
// https://github.com/shadcn-ui/ui/blob/daaf156ee00ed91cc7e6bdd937c1b4973152d141/apps/v4/registry/new-york-v4/ui/chart.tsx
// (sha256 35e2fa755465ef8eb8ff8b483d493204d452152e7a8863474b1a69f5d44484db; MIT text verbatim in ./chart.LICENSE.md).
// Same component API and recharts 3.8.0 contract. Adaptations for this console (design §V2.3):
// - Tailwind v4 utility strings became the .chart* classes in styles/index.css (our Tailwind 3 theme only
//   exposes semantic tokens), and `cn` became `cx` below.
// - ChartStyle injected a <style> per light/dark selector. Our series colours are theme-switching CSS
//   variables already (--viz-*), so the container sets `--color-<key>` inline instead; no
//   dangerouslySetInnerHTML and no `theme` map.
import * as React from "react";
import * as RechartsPrimitive from "recharts";
import type { TooltipValueType } from "recharts";

const INITIAL_DIMENSION = { width: 320, height: 200 } as const;
type TooltipNameType = number | string;

const cx = (...c: Array<string | false | null | undefined>) => c.filter(Boolean).join(" ");

export type ChartConfig = Record<string, { label?: React.ReactNode; icon?: React.ComponentType; color?: string }>;

type ChartContextProps = { config: ChartConfig };

const ChartContext = React.createContext<ChartContextProps | null>(null);

function useChart() {
  const context = React.useContext(ChartContext);
  if (!context) throw new Error("useChart must be used within a <ChartContainer />");
  return context;
}

function ChartContainer({
  id,
  className,
  children,
  config,
  style,
  initialDimension = INITIAL_DIMENSION,
  ...props
}: React.ComponentProps<"div"> & {
  config: ChartConfig;
  children: React.ComponentProps<typeof RechartsPrimitive.ResponsiveContainer>["children"];
  initialDimension?: { width: number; height: number };
}) {
  const uniqueId = React.useId();
  const chartId = `chart-${id ?? uniqueId.replace(/:/g, "")}`;
  const colors = Object.fromEntries(
    Object.entries(config).flatMap(([key, c]) => (c.color ? [[`--color-${key}`, c.color]] : [])),
  ) as React.CSSProperties;

  return (
    <ChartContext.Provider value={{ config }}>
      <div data-slot="chart" data-chart={chartId} className={cx("chart", className)} style={{ ...colors, ...style }} {...props}>
        <RechartsPrimitive.ResponsiveContainer initialDimension={initialDimension}>{children}</RechartsPrimitive.ResponsiveContainer>
      </div>
    </ChartContext.Provider>
  );
}

const ChartTooltip = RechartsPrimitive.Tooltip;

function ChartTooltipContent({
  active,
  payload,
  className,
  indicator = "dot",
  hideLabel = false,
  hideIndicator = false,
  label,
  labelFormatter,
  labelClassName,
  formatter,
  color,
  nameKey,
  labelKey,
}: React.ComponentProps<typeof RechartsPrimitive.Tooltip> &
  React.ComponentProps<"div"> & {
    hideLabel?: boolean;
    hideIndicator?: boolean;
    indicator?: "line" | "dot" | "dashed";
    nameKey?: string;
    labelKey?: string;
  } & Omit<RechartsPrimitive.DefaultTooltipContentProps<TooltipValueType, TooltipNameType>, "accessibilityLayer">) {
  const { config } = useChart();

  const tooltipLabel = React.useMemo(() => {
    if (hideLabel || !payload?.length) return null;
    const [item] = payload;
    const key = `${labelKey ?? item?.dataKey ?? item?.name ?? "value"}`;
    const itemConfig = getPayloadConfigFromPayload(config, item, key);
    const value = !labelKey && typeof label === "string" ? (config[label]?.label ?? label) : itemConfig?.label;
    if (labelFormatter) return <div className={cx("chart-tooltip-label", labelClassName)}>{labelFormatter(value, payload)}</div>;
    if (!value) return null;
    return <div className={cx("chart-tooltip-label", labelClassName)}>{value}</div>;
  }, [label, labelFormatter, payload, hideLabel, labelClassName, config, labelKey]);

  if (!active || !payload?.length) return null;

  const nestLabel = payload.length === 1 && indicator !== "dot";

  return (
    <div className={cx("chart-tooltip", className)}>
      {!nestLabel ? tooltipLabel : null}
      <div className="chart-tooltip-items">
        {payload
          .filter((item) => item.type !== "none")
          .map((item, index) => {
            const key = `${nameKey ?? item.name ?? item.dataKey ?? "value"}`;
            const itemConfig = getPayloadConfigFromPayload(config, item, key);
            const indicatorColor = color ?? (item.payload as { fill?: string } | undefined)?.fill ?? item.color;

            return (
              <div key={index} className={cx("chart-tooltip-row", indicator === "dot" && "is-dot")}>
                {formatter && item?.value !== undefined && item.name ? (
                  formatter(item.value, item.name, item, index, item.payload)
                ) : (
                  <>
                    {itemConfig?.icon ? (
                      <itemConfig.icon />
                    ) : (
                      !hideIndicator && (
                        <div
                          className={cx("chart-indicator", `is-${indicator}`, nestLabel && indicator === "dashed" && "is-nested")}
                          style={{ "--color-bg": indicatorColor, "--color-border": indicatorColor } as React.CSSProperties}
                        />
                      )
                    )}
                    <div className={cx("chart-tooltip-value", nestLabel ? "is-end" : "is-center")}>
                      <div className="chart-tooltip-items">
                        {nestLabel ? tooltipLabel : null}
                        <span className="chart-tooltip-name">{itemConfig?.label ?? item.name}</span>
                      </div>
                      {item.value != null && (
                        <span className="chart-tooltip-number">
                          {typeof item.value === "number" ? item.value.toLocaleString() : String(item.value)}
                        </span>
                      )}
                    </div>
                  </>
                )}
              </div>
            );
          })}
      </div>
    </div>
  );
}

const ChartLegend = RechartsPrimitive.Legend;

function ChartLegendContent({
  className,
  hideIcon = false,
  payload,
  verticalAlign = "bottom",
  nameKey,
}: React.ComponentProps<"div"> & { hideIcon?: boolean; nameKey?: string } & RechartsPrimitive.DefaultLegendContentProps) {
  const { config } = useChart();
  if (!payload?.length) return null;

  return (
    <div className={cx("chart-legend", verticalAlign === "top" ? "is-top" : "is-bottom", className)}>
      {payload
        .filter((item) => item.type !== "none")
        .map((item, index) => {
          const key = `${nameKey ?? item.dataKey ?? "value"}`;
          const itemConfig = getPayloadConfigFromPayload(config, item, key);
          return (
            <div key={index} className="chart-legend-item">
              {itemConfig?.icon && !hideIcon ? (
                <itemConfig.icon />
              ) : (
                <div className="chart-legend-swatch" style={{ backgroundColor: item.color }} />
              )}
              {itemConfig?.label}
            </div>
          );
        })}
    </div>
  );
}

// Helper to extract item config from a payload (unchanged from upstream).
function getPayloadConfigFromPayload(config: ChartConfig, payload: unknown, key: string) {
  if (typeof payload !== "object" || payload === null) return undefined;

  const payloadPayload =
    "payload" in payload && typeof payload.payload === "object" && payload.payload !== null ? payload.payload : undefined;

  let configLabelKey: string = key;

  if (key in payload && typeof payload[key as keyof typeof payload] === "string") {
    configLabelKey = payload[key as keyof typeof payload] as string;
  } else if (payloadPayload && key in payloadPayload && typeof payloadPayload[key as keyof typeof payloadPayload] === "string") {
    configLabelKey = payloadPayload[key as keyof typeof payloadPayload] as string;
  }

  return configLabelKey in config ? config[configLabelKey] : config[key];
}

export { ChartContainer, ChartTooltip, ChartTooltipContent, ChartLegend, ChartLegendContent };
