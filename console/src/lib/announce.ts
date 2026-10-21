import { useEffect, useState } from "react";

// One polite live region for short confirmations (theme switched, link copied). The mockup's #toast.
type Listener = (msg: string) => void;
const listeners = new Set<Listener>();
export const announce = (msg: string) => listeners.forEach((l) => l(msg));

// Visible time of a confirmation; the mockup's app.js value (2400 ms).
const TOAST_MS = 2400;

export function useAnnouncement() {
  const [msg, setMsg] = useState("");
  useEffect(() => {
    let timer: ReturnType<typeof setTimeout>;
    const l: Listener = (m) => {
      setMsg(m);
      clearTimeout(timer);
      timer = setTimeout(() => setMsg(""), TOAST_MS);
    };
    listeners.add(l);
    return () => {
      listeners.delete(l);
      clearTimeout(timer);
    };
  }, []);
  return msg;
}
