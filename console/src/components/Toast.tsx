import { useAnnouncement } from "../lib/announce";

export function Toast() {
  const msg = useAnnouncement();
  return (
    <div className="toast" role="status" aria-live="polite">
      {msg}
    </div>
  );
}
