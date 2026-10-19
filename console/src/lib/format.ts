// Times arrive as OCSF `time`: UTC epoch milliseconds. Rendered in the viewer's zone with its offset
// shown where precision matters (drawer), via Intl only.
const sameDay = (a: Date, b: Date) => a.toDateString() === b.toDateString();

export function formatListTime(ms: number, lng: string, now = new Date()) {
  const d = new Date(ms);
  const opts: Intl.DateTimeFormatOptions = { hour: "2-digit", minute: "2-digit", second: "2-digit", hourCycle: "h23" };
  if (!sameDay(d, now)) Object.assign(opts, { month: "2-digit", day: "2-digit" });
  return new Intl.DateTimeFormat(lng, opts).format(d);
}

export function formatFullTime(ms: number, lng: string) {
  return new Intl.DateTimeFormat(lng, {
    year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit",
    fractionalSecondDigits: 3, hourCycle: "h23", timeZoneName: "shortOffset",
  }).format(new Date(ms));
}

export const isoTime = (ms: number) => new Date(ms).toISOString();
