---
title: Troubleshooting
layout: default
nav_order: 8
description: "Common issues and solutions"
---

# Troubleshooting
{: .no_toc }

Solutions for common issues with Depsy.
{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## LSP Server Not Starting

**Symptoms:**
- No inlay hints or diagnostics appear
- No completions for dependency versions
- Extension seems inactive

**Solutions:**

1. Check Zed's extension panel to verify Depsy is installed and enabled
2. View Zed logs for errors:
   ```bash
   zed --foreground
   ```
3. Reinstall the extension from Zed Extensions marketplace
4. Check if firewall/proxy is blocking network requests to package registries

## LSP Server Crashes or Freezes

**Symptoms:**
- Editor becomes unresponsive when opening dependency files
- LSP process repeatedly restarts
- High memory usage

**Solutions:**

1. Clear the cache directory and restart Zed:
   ```bash
   # Linux
   rm -rf ~/.cache/depsy/

   # macOS
   rm -rf ~/Library/Caches/depsy/

   # Windows
   rmdir /s %LOCALAPPDATA%\depsy
   ```
2. Update to the latest Depsy version
3. Check if the issue occurs with a specific dependency file
4. File a bug report with reproduction steps

## Outdated Cache Data

**Symptoms:**
- Recently published packages not showing as latest
- Old version information displayed
- Known updates not appearing

**Solutions:**

1. Cache automatically refreshes after 1 hour (default TTL)
2. Clear cache manually to force refresh:
   ```bash
   rm -rf ~/.cache/depsy/
   ```
3. Restart Zed after clearing cache
4. Verify the registry is accessible (try visiting crates.io, npmjs.com, etc.)

## Registry Rate Limiting

**Symptoms:**
- Intermittent failures fetching package info
- `? Unknown` hints appearing temporarily
- Slow responses when opening files

**Solutions:**

1. Wait a few minutes for rate limits to reset
2. The cache reduces API calls - avoid clearing cache unnecessarily
3. For npm, consider setting up authentication
4. Large monorepos may trigger rate limits - be patient on first load

## Network/Proxy Issues

**Symptoms:**
- All package lookups failing
- Timeout errors in logs
- Works on some networks but not others

**Solutions:**

1. Configure system proxy settings (Depsy uses system proxy)
2. Ensure registry URLs are allowed through corporate firewall:
   - `https://crates.io`
   - `https://registry.npmjs.org`
   - `https://pypi.org`
   - `https://proxy.golang.org`
   - `https://packagist.org`
   - `https://pub.dev`
   - `https://api.nuget.org`
   - `https://rubygems.org`
   - `https://api.osv.dev` (vulnerability scanning)
3. Check DNS resolution for registry domains
4. Try temporarily disabling VPN if using one

## Configuration Not Applying

**Symptoms:**
- Custom settings in `settings.json` are ignored
- Default behavior despite configuration changes

**Solutions:**

1. Verify JSON syntax is valid in `settings.json`
2. Ensure settings are under the correct path:
   ```json
   {
     "lsp": {
       "depsy": {
         "initialization_options": {
           // your settings here
         }
       }
     }
   }
   ```
3. Restart Zed after configuration changes
4. Check for typos in setting names

## "Unknown" Packages

**Symptoms:**
- `? Unknown` hint for packages that should exist
- Some packages work, others don't

**Solutions:**

1. Check package name spelling
2. Verify the package exists on its registry
3. For scoped npm packages, ensure `@scope/name` format
4. Network issues may cause temporary failures
5. Check if package was recently unpublished/yanked

## Vulnerability Scan Issues

**Symptoms:**
- No vulnerability warnings appearing
- Known vulnerabilities not showing

**Solutions:**

1. Check `security.enabled` is `true` in settings
2. Verify `min_severity` isn't filtering results
3. Ensure network access to `https://api.osv.dev`
4. Vulnerability data is cached for 6 hours
5. Not all packages have vulnerability data

## Performance Issues

**Symptoms:**
- Slow editor startup
- Lag when opening dependency files
- High CPU usage

**Solutions:**

1. Large dependency files take longer on first load
2. Cache improves performance over time
3. Consider increasing cache TTL
4. Check network latency to registries
5. Close other resource-intensive applications

## Debug Logging

For detailed troubleshooting, enable debug logging:

```bash
RUST_LOG=debug zed --foreground
```

This shows:
- Registry requests and responses
- Cache hits/misses
- Configuration loading
- Error details

## Reporting Bugs

If you can't resolve an issue:

1. Check [existing issues](https://github.com/mpiton/zed-depsy/issues)
2. Open a new issue with:
   - Depsy version
   - Zed version
   - Operating system
   - Steps to reproduce
   - Expected vs actual behavior
   - Relevant logs (`zed --foreground`)
