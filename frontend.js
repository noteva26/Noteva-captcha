/**
 * 人机验证插件
 * 支持 Cloudflare Turnstile 和 hCaptcha
 * 纯插件实现，不修改核心代码
 *
 * 关键时序：fetch 拦截必须在 settings 加载前就注册，
 * 否则在 loadEnabledPlugins 完成前提交的评论会绕过验证。
 * 初始化分两阶段：
 *   1. 立即注册 fetch 拦截（此时 captchaEnabled=false，等 settings 后更新）
 *   2. Noteva.ready() 后读取 settings，决定是否启用
 */
(function() {
  var PLUGIN_ID = 'captcha';
  var sdkLoaded = false;
  var sdkLoading = false;
  var captchaToken = '';
  var verified = false;
  var captchaEnabled = false; // settings 加载后才设为 true
  var widgetId = null;
  var widgetContainerId = null;
  var provider = 'none';
  var siteKey = '';
  var lazyLoad = true;
  var explicitConsent = true;
  var consentText = '提交评论需要进行人机验证，验证服务由第三方提供';

  var SDK_URLS = {
    turnstile: 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit',
    hcaptcha: 'https://js.hcaptcha.com/1/api.js?render=explicit'
  };

  // ========================================================
  // 阶段 1：立即注册 fetch 拦截（不依赖 settings）
  // ========================================================
  var _originalFetch = window.fetch;
  window.fetch = function(url, options) {
    if (captchaEnabled
        && typeof url === 'string'
        && url.indexOf('/comments') !== -1
        && options && options.method === 'POST'
        && url.indexOf('/comments/') === -1) {
      if (!verified) {
        console.log('[captcha] Comment blocked: not verified');
        var msg = (typeof Noteva !== 'undefined' && Noteva.i18n) ? Noteva.i18n.t('captcha.required') : '请先完成人机验证';
        var err = new Error(msg);
        err.data = { error: msg };
        return Promise.reject(err);
      }
      console.log('[captcha] Comment allowed, resetting after submit');
      var result = _originalFetch.apply(this, arguments);
      result.then(function() { resetWidget(); }).catch(function() {});
      return result;
    }
    return _originalFetch.apply(this, arguments);
  };

  // ========================================================
  // 阶段 2：等 SDK ready 后读取 settings 并初始化
  // ========================================================
  function initAfterReady() {
    var settings = Noteva.plugins.getSettings(PLUGIN_ID);
    provider = settings.provider || 'none';
    siteKey = settings.site_key || '';
    lazyLoad = settings.lazy_load !== false;
    explicitConsent = settings.explicit_consent !== false;
    consentText = settings.consent_text || Noteva.i18n.t('captcha.consent') || consentText;

    if (provider === 'none' || !siteKey) {
      console.log('[captcha] Disabled (provider=' + provider + ', siteKey=' + (siteKey ? 'set' : 'empty') + ')');
      return;
    }

    captchaEnabled = true;
    console.log('[captcha] Enabled, provider:', provider);

    // 注册 content_render 钩子
    Noteva.hooks.on('content_render', function() {
      setTimeout(injectCaptcha, 300);
    });

    // MutationObserver 兜底
    startObserver();

    // 立即尝试注入一次
    setTimeout(injectCaptcha, 200);
  }

  function loadProviderSdk(callback) {
    if (sdkLoaded) return callback();
    if (sdkLoading) {
      var check = setInterval(function() {
        if (sdkLoaded) { clearInterval(check); callback(); }
      }, 100);
      return;
    }
    sdkLoading = true;
    var s = document.createElement('script');
    s.src = SDK_URLS[provider];
    s.async = true;
    s.onload = function() { sdkLoaded = true; sdkLoading = false; callback(); };
    s.onerror = function() { sdkLoading = false; console.warn('[captcha] Provider SDK load failed'); };
    document.head.appendChild(s);
  }

  function onTokenReceived(token) {
    captchaToken = token;
    console.log('[captcha] Token received, verifying with backend...');
    verifyToken(token);
  }

  function onTokenExpired() {
    captchaToken = '';
    verified = false;
    updateStatus('');
  }

  function updateStatus(text, ok) {
    var el = document.querySelector('.noteva-captcha-status');
    if (el) {
      el.textContent = text;
      el.className = 'noteva-captcha-status' + (ok ? ' noteva-captcha-verified' : '');
    }
  }

  function verifyToken(token) {
    _originalFetch('/api/v1/plugins/captcha/api/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: token, provider: provider })
    })
    .then(function(r) { return r.json(); })
    .then(function(data) {
      if (data.success) {
        verified = true;
        updateStatus(Noteva.i18n.t('captcha.verified'), true);
        console.log('[captcha] Verified successfully');
      } else {
        verified = false;
        updateStatus(Noteva.i18n.t('captcha.failed') + (data.error ? ': ' + data.error : ''));
        console.log('[captcha] Verification failed:', data.error);
      }
    })
    .catch(function(e) {
      console.warn('[captcha] Verify request error:', e);
      updateStatus(Noteva.i18n.t('captcha.requestError'));
    });
  }

  function renderWidget(container) {
    widgetContainerId = 'noteva-captcha-widget-' + Date.now();
    var widgetDiv = document.createElement('div');
    widgetDiv.id = widgetContainerId;
    container.appendChild(widgetDiv);

    var statusDiv = document.createElement('div');
    statusDiv.className = 'noteva-captcha-status';
    container.appendChild(statusDiv);

    var opts = {
      sitekey: siteKey,
      callback: onTokenReceived,
      'expired-callback': onTokenExpired,
      'error-callback': onTokenExpired,
      theme: document.documentElement.classList.contains('dark') ? 'dark' : 'light'
    };

    setTimeout(function() {
      if (provider === 'turnstile' && typeof turnstile !== 'undefined') {
        widgetId = turnstile.render('#' + widgetContainerId, opts);
      } else if (provider === 'hcaptcha' && typeof hcaptcha !== 'undefined') {
        widgetId = hcaptcha.render(widgetContainerId, opts);
      }
    }, 100);
  }

  function resetWidget() {
    verified = false;
    captchaToken = '';
    updateStatus('');
    setTimeout(function() {
      try {
        if (provider === 'turnstile' && typeof turnstile !== 'undefined' && widgetId != null) {
          turnstile.reset(widgetId);
        } else if (provider === 'hcaptcha' && typeof hcaptcha !== 'undefined' && widgetId != null) {
          hcaptcha.reset(widgetId);
        }
      } catch(e) {}
    }, 500);
  }

  function injectCaptcha() {
    var slot = document.querySelector('[data-noteva-slot="comment_form_before"]');
    if (!slot || slot.querySelector('.noteva-captcha-container')) return;

    var container = document.createElement('div');
    container.className = 'noteva-captcha-container';

    if (explicitConsent && lazyLoad) {
      var loadBtnText = (typeof Noteva !== 'undefined' && Noteva.i18n) ? Noteva.i18n.t('captcha.loadBtn') : '加载验证码';
      container.innerHTML =
        '<div class="noteva-captcha-consent">' +
          '<p class="noteva-captcha-consent-text">' + consentText + '</p>' +
          '<button type="button" class="noteva-captcha-load-btn">' + loadBtnText + '</button>' +
        '</div>';
      container.querySelector('.noteva-captcha-load-btn').addEventListener('click', function() {
        this.textContent = Noteva.i18n.t('captcha.loading');
        this.disabled = true;
        loadProviderSdk(function() {
          var consent = container.querySelector('.noteva-captcha-consent');
          if (consent) consent.remove();
          renderWidget(container);
        });
      });
    } else if (lazyLoad) {
      var obs = new IntersectionObserver(function(entries) {
        if (entries[0].isIntersecting) {
          obs.disconnect();
          loadProviderSdk(function() { renderWidget(container); });
        }
      });
      obs.observe(container);
      container.style.minHeight = '65px';
    } else {
      loadProviderSdk(function() { renderWidget(container); });
    }

    slot.appendChild(container);
    console.log('[captcha] Widget injected into slot');
  }

  function startObserver() {
    if (!document.body) { setTimeout(startObserver, 100); return; }
    new MutationObserver(function() {
      if (!captchaEnabled) return;
      var slot = document.querySelector('[data-noteva-slot="comment_form_before"]');
      if (slot && !slot.querySelector('.noteva-captcha-container')) {
        setTimeout(injectCaptcha, 200);
      }
    }).observe(document.body, { childList: true, subtree: true });
  }

  // 等待 Noteva SDK ready（此时 loadEnabledPlugins 已完成）
  function waitAndInit() {
    if (typeof Noteva !== 'undefined' && Noteva.ready) {
      Noteva.ready(initAfterReady);
    } else {
      setTimeout(waitAndInit, 100);
    }
  }
  waitAndInit();

})();
