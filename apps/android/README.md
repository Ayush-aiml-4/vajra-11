# VAJRA Android Companion (`apps/android`)

**Status:** Foundation implementation (Prompt 0015)  
**Language:** Kotlin  
**minSdk:** 29 (Android 10) · **targetSdk / compileSdk:** 34  
**AGP:** 8.2.2 · **Kotlin:** 1.9.22

Native companion that enrolls an Android phone with the existing VAJRA backend using **ECDSA P-256** in **Android Keystore**, signs Plane-2 requests with the same transcripts as the Windows agent / `packages/security`, and supports WorkManager heartbeats, command polling, and a visible device ring.

## Build requirements

- Android Studio Hedgehog+ or command-line Android SDK 34
- JDK 17
- `ANDROID_HOME` set

```bash
cd apps/android
./gradlew :app:assembleDebug   # after generating the Gradle wrapper on a dev machine
./gradlew :app:testDebugUnitTest
```

If the Gradle wrapper is not present:

```bash
gradle wrapper --gradle-version 8.2
```

## Configure server URL

Debug default: `http://10.0.2.2:3000` (emulator → host).  
Change in **Settings** (stored in app SharedPreferences). Production must use **HTTPS** with normal certificate validation (no custom TrustManager).

## Enrollment

1. Web console: open **Connect Device**, choose **Android**, and tap **Copy Pairing Bundle** (or copy `Device ID`, `One-Time Pairing Code`, and `Verification Challenge` individually).
2. App → **Enroll device** → tap **Paste Pairing Bundle from Clipboard** (auto-fills Server URL, Enrollment Token, Device ID, and Challenge Nonce) → **Submit enrollment**.
3. Console: **Approve Device** (`TRUSTED`).
4. App schedules WorkManager heartbeat / command poll (min ~15 min period); the first signed heartbeat transitions the server record to `ACTIVE` / `ONLINE`.

Local state remains `ENROLLMENT_PENDING` until the server accepts heartbeats after confirmation. From the monorepo root, run `npm run test:android-agent` to check JDK 17 + Android SDK 34 readiness and execute `:app:testDebugUnitTest` + `:app:assembleDebug` (exits `2` with `BLOCKED` if prerequisites are absent).

## Commands

| Action | Behavior |
| :--- | :--- |
| `REQUEST_DEVICE_STATUS` | Completed — OS/agent metadata |
| `RING_DEVICE` | Completed — high-priority notification + alarm ringtone |
| `REQUEST_LOCATION` | Failed — deferred (no continuous location in this phase) |
| Lost mode / recovery UI | Failed — not claimed |
| Shell / arbitrary code | Never |

## Permissions

- `INTERNET`
- `POST_NOTIFICATIONS` (ring UX)

**Not requested:** microphone, camera, SMS, contacts, storage, accessibility, background location.

## Privacy

See in-app **Privacy disclosure**. Disconnect clears Keystore key and cancels workers.

## Limitations

- Not built in environments without Android SDK (this CI sandbox has no `ANDROID_HOME`).
- WorkManager intervals are OS-limited (≥15 minutes).
- Continuous location and full-screen recovery UI deferred.
- Live end-to-end enrollment requires a real device/emulator + running API.

## Protocol alignment (Prompt 0016)

- Body SHA-256 uses **canonical JSON** (sorted keys) matching server `canonicalJsonSerialize`.
- ECDSA `SHA256withECDSA` produces **DER** signatures (Node-compatible).
- See `docs/architecture/device-protocol-matrix.md`.


## Build & test (Prompt 0023)

Requirements:
- JDK **17** (full JDK with `jlink`; Android Gradle Plugin 8.2)
- Android SDK platform **34** + build-tools 34
- Gradle wrapper (committed under `gradle/wrapper/`)

```bash
export JAVA_HOME=$(/usr/libexec/java_home -v 17 2>/dev/null || echo /usr/lib/jvm/java-17-openjdk-amd64)
export ANDROID_HOME=/path/to/Android/Sdk
echo "sdk.dir=$ANDROID_HOME" > local.properties   # gitignored locally
./gradlew testDebugUnitTest
./gradlew assembleDebug
# APK: app/build/outputs/apk/debug/app-debug.apk
```

Verified in CI sandbox: **5/5** unit tests PASS; `assembleDebug` PASS.
