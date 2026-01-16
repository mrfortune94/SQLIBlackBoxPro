# GitHub Actions Workflows Guide

This repository includes automated GitHub Actions workflows to build both debug and production-ready APKs.

## Available Workflows

### 1. Build Debug APK (`build-debug.yml`)

**Triggers:**
- Push to `main` or `develop` branches
- Pull requests to `main` or `develop` branches
- Manual trigger via GitHub Actions UI

**What it does:**
- Builds a debug APK of the application
- Uploads the APK as an artifact (available for 30 days)

**How to download:**
1. Go to the Actions tab in GitHub
2. Click on the latest workflow run
3. Scroll down to "Artifacts"
4. Download `app-debug`

### 2. Build Release APK (`build-release.yml`)

**Triggers:**
- Push of version tags (e.g., `v1.0.0`, `v2.1.0`)
- Manual trigger via GitHub Actions UI

**What it does:**
- Builds a production-ready release APK
- Signs the APK if keystore secrets are configured
- Uploads the APK as an artifact (available for 90 days)
- Creates a GitHub Release with the APK attached (when triggered by a tag)

**How to download:**
1. For tagged releases: Check the Releases section
2. For manual runs: Go to Actions tab, find the workflow run, download from Artifacts

## Setting Up Release Signing

To build signed release APKs, you need to configure signing secrets in your GitHub repository.

### Step 1: Create a Keystore

If you don't have a keystore, create one:

```bash
keytool -genkey -v -keystore release-keystore.jks -keyalg RSA -keysize 2048 -validity 10000 -alias sqliblackboxpro
```

Follow the prompts to set:
- Keystore password
- Key alias password
- Your name and organization details

**Important:** Keep your keystore file and passwords secure! Never commit them to the repository.

### Step 2: Encode Keystore to Base64

```bash
base64 -i release-keystore.jks | tr -d '\n' > keystore.base64.txt
```

### Step 3: Add Secrets to GitHub

1. Go to your repository on GitHub
2. Navigate to Settings → Secrets and variables → Actions
3. Click "New repository secret" and add these secrets:

| Secret Name | Description | Example |
|-------------|-------------|---------|
| `KEYSTORE_BASE64` | Base64-encoded keystore file | Contents of `keystore.base64.txt` |
| `KEYSTORE_PASSWORD` | Password for the keystore | The password you set when creating the keystore |
| `KEY_ALIAS` | Alias for the signing key | `sqliblackboxpro` (or the alias you used) |
| `KEY_PASSWORD` | Password for the key | The key password you set |

### Step 4: Test the Workflow

Create and push a tag to trigger a release build:

```bash
git tag -a v1.0.0 -m "Release version 1.0.0"
git push origin v1.0.0
```

## Manual Workflow Triggers

You can manually trigger workflows from the GitHub Actions UI:

1. Go to the Actions tab
2. Select the workflow you want to run
3. Click "Run workflow"
4. Select the branch
5. Click "Run workflow"

## Troubleshooting

### Debug APK Build Fails

- Check that all Kotlin source files compile without errors
- Ensure all dependencies in `app/build.gradle.kts` are valid
- Review the workflow logs in the Actions tab

### Release APK Build Fails with Signing Errors

- Verify all four secrets are correctly set in GitHub
- Ensure the `KEYSTORE_BASE64` secret contains the full base64-encoded keystore
- Check that passwords match the keystore you created
- Make sure the key alias matches

### APK Not Found After Build

- The APK will be in the Artifacts section of the workflow run
- For releases triggered by tags, check the Releases section
- Artifacts expire after their retention period (30 days for debug, 90 days for release)

## Building Locally

You can also build APKs locally:

### Debug APK
```bash
./gradlew assembleDebug
```
Output: `app/build/outputs/apk/debug/app-debug.apk`

### Release APK (unsigned)
```bash
./gradlew assembleRelease
```
Output: `app/build/outputs/apk/release/app-release-unsigned.apk`

### Release APK (signed)
1. Place your `release-keystore.jks` in the `app/` directory
2. Set environment variables:
```bash
export KEYSTORE_PASSWORD="your_keystore_password"
export KEY_ALIAS="your_key_alias"
export KEY_PASSWORD="your_key_password"
```
3. Build:
```bash
./gradlew assembleRelease
```
Output: `app/build/outputs/apk/release/app-release.apk` (signed)

## Security Best Practices

1. **Never commit keystore files** - They are already ignored in `.gitignore`
2. **Keep passwords secure** - Only store them in GitHub Secrets
3. **Rotate keys periodically** - Update your keystore and secrets regularly
4. **Use different keys** - Consider different keys for different release channels
5. **Backup your keystore** - Store it securely offline; losing it means you can't update your app

## Version Management

To create a new release:

1. Update version in `app/build.gradle.kts`:
   ```kotlin
   versionCode = 2  // Increment for each release
   versionName = "1.1"  // Semantic versioning
   ```

2. Commit the changes:
   ```bash
   git add app/build.gradle.kts
   git commit -m "Bump version to 1.1"
   git push
   ```

3. Create and push a tag:
   ```bash
   git tag -a v1.1.0 -m "Release version 1.1.0"
   git push origin v1.1.0
   ```

4. The workflow will automatically build and create a GitHub Release

## Workflow Customization

You can customize the workflows by editing the YAML files in `.github/workflows/`:

- Change trigger conditions (branches, tags, schedules)
- Add additional build variants
- Modify artifact retention periods
- Add automated testing before building
- Configure notifications for build status
