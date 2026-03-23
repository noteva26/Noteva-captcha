# 🔒 Captcha - Noteva Plugin

Human verification for comments. Supports **Cloudflare Turnstile** and **hCaptcha**.

## Features

- 🛡️ Block spam bots from posting comments
- ⚡ Lazy-load captcha SDK (only when needed)
- 🌙 Auto dark mode support
- 🌐 i18n ready (zh-CN / en)
- 🔐 Backend token verification via WASM sandbox
- 📋 Explicit consent mode (GDPR-friendly)

## Setup

1. Install & enable the plugin in **Admin → Plugins**
2. Choose provider: `turnstile` or `hcaptcha`
3. Enter your **Site Key** and **Secret Key**
4. Done — captcha widget appears above the comment box

### Get API Keys

| Provider | Dashboard |
|----------|-----------|
| Cloudflare Turnstile | [dash.cloudflare.com](https://dash.cloudflare.com/?to=/:account/turnstile) |
| hCaptcha | [dashboard.hcaptcha.com](https://dashboard.hcaptcha.com) |

## Settings

| Key | Description | Default |
|-----|-------------|---------|
| `provider` | `turnstile` or `hcaptcha` | `none` |
| `site_key` | Public site key | — |
| `secret_key` | Secret key (hidden) | — |
| `lazy_load` | Load SDK only when visible | `true` |
| `explicit_consent` | Show consent button first | `true` |

## Requirements

- Noteva ≥ 0.2.0
- Permissions: `network`, `storage`

## License

MIT
