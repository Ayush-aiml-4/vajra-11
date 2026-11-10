-- VAJRA — Migration 0007_analytics_query_indexes
-- Provider: PostgreSQL
-- Purpose: Composite indexes supporting analytics aggregation, ThreatCheck history
-- pagination, and ownership-scoped event timelines (Prompt 0012).

-- Security events: owner timeline ordered by occurredAt (analytics + activity feed)
CREATE INDEX IF NOT EXISTS "SecurityEvent_userId_occurredAt_idx"
  ON "SecurityEvent" ("userId", "occurredAt" DESC);

-- ThreatCheck: owner history ordered by checkedAt (history API + export)
CREATE INDEX IF NOT EXISTS "ThreatCheck_userId_checkedAt_idx"
  ON "ThreatCheck" ("userId", "checkedAt" DESC);

-- Notifications: unread/open alerts for analytics summary
CREATE INDEX IF NOT EXISTS "Notification_userId_dismissedAt_readAt_idx"
  ON "Notification" ("userId", "dismissedAt", "readAt");

-- Remote commands: issuer-scoped recent commands for analytics/export
CREATE INDEX IF NOT EXISTS "RemoteCommand_issuerUserId_requestedAt_idx"
  ON "RemoteCommand" ("issuerUserId", "requestedAt" DESC);
