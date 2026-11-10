#!/usr/bin/env node
/**
 * VAJRA — Android Companion Build & Unit-Test Verification Runner (Prompt 0048)
 *
 * Checks prerequisites for building `apps/android` (`compileSdk 34`, AGP 8.2.2)
 * and running `:app:testDebugUnitTest` + `:app:assembleDebug`:
 * 1. JDK 17+ (`java` on PATH or `JAVA_HOME/bin/java`).
 * 2. Android SDK Platform 34 (`ANDROID_HOME` or `ANDROID_SDK_ROOT`, or `apps/android/local.properties`).
 * 3. Executable Gradle wrapper (`apps/android/gradlew` or `gradlew.bat`).
 *
 * Never simulates an Android Gradle build or converts missing prerequisites into a pass.
 * Exits with code 2 (BLOCKED) when prerequisites are absent.
 */

import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

const BLOCKED_EXIT_CODE = 2;
const isWindows = process.platform === 'win32';
const androidDir = path.resolve(process.cwd(), 'apps', 'android');

function detectJavaMajorVersion() {
  const javaHome = process.env.JAVA_HOME?.trim();
  const javaBin = javaHome
    ? path.join(javaHome, 'bin', isWindows ? 'java.exe' : 'java')
    : 'java';
  const res = spawnSync(javaBin, ['-version'], { encoding: 'utf8' });
  const combined = `${res.stdout ?? ''}\n${res.stderr ?? ''}`;
  if (res.status !== 0 && !combined.includes('version')) {
    return null;
  }
  const match = combined.match(/version\s+"(\d+)(?:\.(\d+))?/i);
  if (!match) return 0;
  const first = Number.parseInt(match[1], 10);
  if (first === 1 && match[2]) {
    return Number.parseInt(match[2], 10);
  }
  return first;
}

function detectAndroidSdkRoot() {
  const envSdk =
    process.env.ANDROID_HOME?.trim() || process.env.ANDROID_SDK_ROOT?.trim();
  if (envSdk && fs.existsSync(envSdk)) {
    return envSdk;
  }
  const localPropsPath = path.join(androidDir, 'local.properties');
  if (fs.existsSync(localPropsPath)) {
    const content = fs.readFileSync(localPropsPath, 'utf8');
    const sdkLine = content
      .split(/\r?\n/)
      .find((line) => line.trim().startsWith('sdk.dir='));
    if (sdkLine) {
      const candidate = sdkLine.slice(sdkLine.indexOf('=') + 1).trim();
      if (candidate && fs.existsSync(candidate)) {
        return candidate;
      }
    }
  }
  return null;
}

const missing = [];
const javaMajor = detectJavaMajorVersion();
if (javaMajor === null) {
  missing.push('JDK 17+ (java not found on PATH and JAVA_HOME is not set)');
} else if (javaMajor > 0 && javaMajor < 17) {
  missing.push(`JDK 17+ required by Android Gradle Plugin 8.2 (detected Java ${javaMajor})`);
}

const sdkRoot = detectAndroidSdkRoot();
if (!sdkRoot) {
  missing.push('Android SDK Platform 34 (ANDROID_HOME / ANDROID_SDK_ROOT / local.properties not configured)');
} else {
  const platform34 = path.join(sdkRoot, 'platforms', 'android-34');
  if (!fs.existsSync(platform34)) {
    missing.push(`Android SDK Platform 34 missing at ${platform34}`);
  }
}

const wrapperPath = path.join(androidDir, isWindows ? 'gradlew.bat' : 'gradlew');
if (!fs.existsSync(wrapperPath)) {
  missing.push(`Gradle wrapper missing at ${wrapperPath}`);
}

if (missing.length > 0) {
  console.error(`BLOCKED [test:android-agent]: Missing prerequisite(s): ${missing.join('; ')}.`);
  console.error(
    'Real Android unit tests and APK build were NOT RUN. Set JAVA_HOME (JDK 17) and ANDROID_HOME (SDK 34), then re-run npm run test:android-agent.'
  );
  process.exit(BLOCKED_EXIT_CODE);
}

console.log(`[test:android-agent] Running Gradle verification in ${androidDir}...`);
const res = spawnSync(
  wrapperPath,
  [':app:testDebugUnitTest', ':app:assembleDebug', '--no-daemon'],
  {
    cwd: androidDir,
    stdio: 'inherit',
  }
);
if (res.status !== 0) {
  process.exit(res.status ?? 1);
}
