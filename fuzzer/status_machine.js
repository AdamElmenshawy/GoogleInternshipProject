/**
 * Crash lifecycle state machine.
 *
 * A crash must pass through every state in order before it is visible to
 * external consumers as a published finding. Nothing in `pending_review` is a
 * finding yet — the human approval gate (`POST /api/crashes/:id/publish`) is
 * the only way to advance to `published`.
 *
 * States:
 *   ingested        → crash artifact received by the pipeline
 *   analyzed        → Gemini classification complete
 *   pending_review  → VRP report generated, awaiting human review
 *   published       → human approved; visible in the findings feed
 *   rejected        → human discarded (terminal, cannot be re-published)
 */

export const CRASH_STATUS_FLOW = ["ingested", "analyzed", "pending_review", "published"];
export const VALID_CRASH_STATUSES = new Set([...CRASH_STATUS_FLOW, "rejected"]);

/**
 * Returns true if transitioning `current` → `next` is legal.
 *
 * Rules:
 *   - Same-state is always valid (idempotent update).
 *   - `rejected` may be reached from any non-published state.
 *   - `published` is terminal; no transition out of it is allowed.
 *   - All other transitions must advance forward in CRASH_STATUS_FLOW order.
 */
export function isValidTransition(current, next) {
  if (current === next) return true;
  if (next === "rejected") return current !== "published";
  if (current === "rejected") return false;
  const fromIdx = CRASH_STATUS_FLOW.indexOf(current);
  const toIdx = CRASH_STATUS_FLOW.indexOf(next);
  if (fromIdx === -1 || toIdx === -1) return false;
  return toIdx > fromIdx;
}
