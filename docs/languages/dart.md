---
title: Dart/Flutter
layout: default
parent: Languages
nav_order: 6
description: "Dart and Flutter pubspec.yaml support"
---

# Dart/Flutter
{: .no_toc }

Support for Dart and Flutter projects using pubspec.yaml.
{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Supported Files

| File | Description |
|------|-------------|
| `pubspec.yaml` | Dart/Flutter manifest |

### Lockfile Resolution

Depsy reads `pubspec.lock` to show resolved versions and eliminate false-positive "update available" warnings.

## Registry

**pub.dev** - The official Dart package repository

- Base URL: `https://pub.dev/api`
- Rate limit: ~100 requests per minute
- Documentation: [pub.dev](https://pub.dev)

## Dependency Format

### Regular Dependencies

```yaml
dependencies:
  http: ^1.1.0
  provider: ^6.0.0
  dio: ^5.0.0
```

### Development Dependencies

```yaml
dev_dependencies:
  test: ^1.24.0
  build_runner: ^2.4.0
  json_serializable: ^6.7.0
```

### Dependency Overrides

```yaml
dependency_overrides:
  http: ^1.2.0
```

## Version Specification

Dart uses caret syntax similar to npm:

| Syntax | Meaning |
|--------|---------|
| `1.0.0` | Exactly 1.0.0 |
| `^1.0.0` | >=1.0.0, <2.0.0 |
| `">=1.0.0 <2.0.0"` | Range |
| `any` | Any version |

## Special Cases

### Flutter SDK

```yaml
dependencies:
  flutter:
    sdk: flutter
```

SDK dependencies show `→ SDK` hint.

### Git Dependencies

```yaml
dependencies:
  my_package:
    git:
      url: https://github.com/user/repo.git
      ref: main
```

Git dependencies show `→ Git` hint.

### Path Dependencies

```yaml
dependencies:
  my_local_package:
    path: ../my_local_package
```

Path dependencies show `→ Local` hint.

### Hosted Dependencies

```yaml
dependencies:
  my_package:
    hosted:
      name: my_package
      url: https://my-package-server.com
    version: ^1.0.0
```

Custom hosted packages are resolved from their specified URL.

### Retracted Versions

Retracted versions on pub.dev show `⊘ Retracted` hint. Update immediately.

### Discontinued Packages

Discontinued packages show `⚠ Discontinued` hint. Find an alternative.

## SDK Constraints

```yaml
environment:
  sdk: ">=3.0.0 <4.0.0"
  flutter: ">=3.10.0"
```

SDK constraints are shown but don't trigger version hints.

## Vulnerability Database

Dart vulnerabilities are sourced from:
- GitHub Security Advisories
- OSV.dev Dart database

## Example pubspec.yaml

```yaml
name: my_app
description: A Flutter application
version: 1.0.0

environment:
  sdk: ">=3.0.0 <4.0.0"
  flutter: ">=3.10.0"

dependencies:
  flutter:
    sdk: flutter
  http: ^1.1.0                    # ✓
  provider: ^6.0.0                # -> 6.1.0
  dio: ^5.0.0                     # ✓
  riverpod: ^2.4.0                # ✓

dev_dependencies:
  flutter_test:
    sdk: flutter
  test: ^1.24.0                   # ✓
  build_runner: ^2.4.0            # -> 2.4.6
  json_serializable: ^6.7.0       # ✓
```

## Tooling Integration

After updating `pubspec.yaml` with Depsy:

```bash
# Dart
dart pub get
dart pub upgrade

# Flutter
flutter pub get
flutter pub upgrade

# Check outdated
dart pub outdated
flutter pub outdated
```

## Troubleshooting

### Package Not Found

1. Verify package name spelling
2. Check if package exists on pub.dev
3. Ensure network access to pub.dev

### Version Resolution Failures

1. Check SDK constraints compatibility
2. Review transitive dependency conflicts
3. Try `dart pub upgrade --major-versions`

### Flutter vs Dart Packages

Some packages are Flutter-specific:
1. Flutter packages require Flutter SDK
2. Pure Dart packages work in both
3. Check package description on pub.dev

### Retracted Version Warning

If using a retracted version:
1. Check the package's changelog for issues
2. Update to a newer version immediately
3. The retraction reason may be in the package's README
