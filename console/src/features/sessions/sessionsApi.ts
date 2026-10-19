import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { listClientNodes, listSessionSummaries, type SessionSummaryQuery } from "../../lib/api";

// Same cache entry as the overview's device tile: one /client-nodes fetch per session.
export const useClientNodes = () => useQuery({ queryKey: ["client-nodes"], queryFn: listClientNodes });

export function useSessionSummaries(q: SessionSummaryQuery, enabled = true) {
  return useQuery({
    queryKey: ["session-summaries", q],
    queryFn: () => listSessionSummaries(q),
    placeholderData: keepPreviousData,
    enabled,
  });
}
