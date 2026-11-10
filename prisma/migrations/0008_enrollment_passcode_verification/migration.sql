-- VAJRA — Migration 0008_enrollment_passcode_verification
-- Provider: PostgreSQL
-- Purpose: Adds passcodeHash and failedAttempts to EnrollmentChallenge table for
-- physical-possession verification and atomic lockout defense (Prompt 0010 / VAJRA 2.0).

ALTER TABLE "EnrollmentChallenge" ADD COLUMN IF NOT EXISTS "passcodeHash" TEXT;
ALTER TABLE "EnrollmentChallenge" ADD COLUMN IF NOT EXISTS "failedAttempts" INTEGER NOT NULL DEFAULT 0;
