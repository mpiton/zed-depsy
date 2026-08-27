---
title: Ruby
layout: default
parent: Languages
nav_order: 8
description: "Ruby Gemfile support"
---

# Ruby
{: .no_toc }

Support for Ruby projects using Gemfile.
{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Supported Files

| File | Description |
|------|-------------|
| `Gemfile` | Bundler dependency file |

### Lockfile Resolution

Depsy reads `Gemfile.lock` to show resolved versions and eliminate false-positive "update available" warnings.

## Registry

**RubyGems.org** - The Ruby community's gem hosting service

- Base URL: `https://rubygems.org/api/v1`
- Rate limit: ~10 requests per second
- Documentation: [rubygems.org](https://rubygems.org)

## Dependency Format

### Basic Syntax

```ruby
source 'https://rubygems.org'

gem 'rails', '~> 7.0'
gem 'pg', '>= 1.0'
gem 'puma', '~> 6.0'
```

### With Groups

```ruby
group :development, :test do
  gem 'rspec-rails', '~> 6.0'
  gem 'rubocop', '~> 1.50'
end

group :development do
  gem 'web-console', '~> 4.0'
end
```

### With Options

```ruby
gem 'devise', '~> 4.9', require: false
gem 'sidekiq', '~> 7.0', group: :worker
```

## Version Specification

Ruby uses these version operators:

| Syntax | Meaning |
|--------|---------|
| `'1.0.0'` | Exactly 1.0.0 |
| `'~> 1.0'` | >=1.0, <2.0 (pessimistic) |
| `'~> 1.0.0'` | >=1.0.0, <1.1.0 |
| `'>= 1.0'` | 1.0 or higher |
| `'>= 1.0', '< 2.0'` | Range |

The `~>` (pessimistic) operator is unique to Ruby and very common.

## Special Cases

### Git Dependencies

```ruby
gem 'my_gem', git: 'https://github.com/user/repo.git'
gem 'my_gem', git: 'https://github.com/user/repo.git', branch: 'main'
gem 'my_gem', git: 'https://github.com/user/repo.git', tag: 'v1.0.0'
```

Git dependencies show `→ Git` hint.

### Path Dependencies

```ruby
gem 'my_local_gem', path: '../my_local_gem'
```

Path dependencies show `→ Local` hint.

### Platform-specific Gems

```ruby
gem 'wdm', '>= 0.1.0', platforms: [:mingw, :mswin, :x64_mingw]
gem 'tzinfo-data', platforms: [:mingw, :mswin, :x64_mingw, :jruby]
```

Platform gems may have different versions per platform.

### Prerelease Versions

```ruby
gem 'rails', '~> 7.1.0.beta1'
```

Ruby prereleases use `.pre.N` or `.beta.N` format (not `-pre.N`).

### Multiple Sources

```ruby
source 'https://rubygems.org'
source 'https://gems.company.com' do
  gem 'internal_gem'
end
```

Currently, Depsy queries rubygems.org only.

## Vulnerability Database

Ruby vulnerabilities are sourced from:
- [RubySec Advisory Database](https://rubysec.com/)
- GitHub Security Advisories

## Example Gemfile

```ruby
source 'https://rubygems.org'

ruby '3.2.0'

gem 'rails', '~> 7.0'                     # ✓
gem 'pg', '~> 1.5'                        # ✓
gem 'puma', '~> 6.0'                      # -> 6.4.0
gem 'redis', '~> 5.0'                     # ✓
gem 'sidekiq', '~> 7.0'                   # -> 7.2.0

group :development, :test do
  gem 'rspec-rails', '~> 6.0'             # ✓
  gem 'factory_bot_rails', '~> 6.2'       # -> 6.4.0
end

group :development do
  gem 'rubocop', '~> 1.50'                # -> 1.59.0
  gem 'web-console', '~> 4.0'             # ✓
end

group :test do
  gem 'capybara', '~> 3.39'               # ✓
  gem 'selenium-webdriver', '~> 4.0'      # -> 4.16.0
end
```

## Tooling Integration

After updating `Gemfile` with Depsy:

```bash
# Update lockfile
bundle install

# Update specific gem
bundle update rails

# Update all gems
bundle update

# Check outdated
bundle outdated

# Check vulnerabilities
bundle audit
```

## Troubleshooting

### Gem Not Found

1. Verify gem name spelling
2. Check if gem exists on rubygems.org
3. Ensure `source 'https://rubygems.org'` is present

### Platform Gems

Some gems have platform-specific versions (e.g., `-java`, `-x86_64-linux`). Depsy shows the Ruby platform version by default.

### Pessimistic Constraint Issues

The `~>` operator behavior depends on version specificity:
- `~> 1.0` allows 1.x (up to but not including 2.0)
- `~> 1.0.0` allows 1.0.x (up to but not including 1.1)

### Private Gem Servers

For private gem servers:
1. Configure source in Gemfile
2. Set up authentication via bundler config
3. Note: Depsy currently uses rubygems.org only

### Ruby Version Constraint

```ruby
ruby '~> 3.2.0'
```

Ruby version constraints are shown but don't trigger hints.
