-- Prompt 0011D: MFA step-up action scope binding
ALTER TABLE "DeviceSession" ADD COLUMN IF NOT EXISTS "stepUpActionScope" TEXT;
