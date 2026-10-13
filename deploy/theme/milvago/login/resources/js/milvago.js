// Milvago identity pages. A classic script run in <head>, so the theme chosen in the
// console is applied before the first paint; the rest waits for the document. Every page
// works without it: these are conveniences on top of plain forms.
(() => {
  const root = document.documentElement;
  // Same choice, cookie and storage key as the console. Dark is the brand's default
  // rendering: the system setting is not consulted, only an explicit choice.
  const saved = () => {
    const cookie = document.cookie.split('; ').find((value) => /^milvago_theme=(light|dark)$/.test(value));
    if (cookie) return cookie.split('=')[1];
    try { return localStorage.getItem('milvago.theme'); } catch { return null; }
  };
  let theme = saved() === 'light' ? 'light' : 'dark';
  const applyTheme = () => {
    if (theme === 'light') root.dataset.theme = 'light';
    else delete root.dataset.theme;
  };
  applyTheme();
  root.classList.add('has-script');

  const themeToggle = (button) => {
    const label = () => button.setAttribute('aria-label', theme === 'light' ? button.dataset.labelDark : button.dataset.labelLight);
    label();
    button.addEventListener('click', () => {
      theme = theme === 'light' ? 'dark' : 'light';
      applyTheme();
      label();
      document.cookie = 'milvago_theme=' + theme + '; Path=/; SameSite=Lax' + (location.protocol === 'https:' ? '; Secure' : '');
      try { localStorage.setItem('milvago.theme', theme); } catch { /* private window: the cookie still carries it */ }
    });
  };

  const reveal = (button) => {
    const input = document.getElementById(button.dataset.reveal);
    if (!input) return;
    button.setAttribute('aria-pressed', 'false');
    button.addEventListener('click', () => {
      const shown = input.type === 'password';
      input.type = shown ? 'text' : 'password';
      button.setAttribute('aria-pressed', String(shown));
      button.setAttribute('aria-label', shown ? button.dataset.labelHide : button.dataset.labelShow);
      button.querySelector('.reveal-show').hidden = shown;
      button.querySelector('.reveal-hide').hidden = !shown;
    });
  };

  const capsLock = (warning) => {
    const input = document.getElementById(warning.dataset.capsFor);
    if (!input) return;
    const check = (event) => { if (event.getModifierState) warning.hidden = !event.getModifierState('CapsLock'); };
    input.addEventListener('keydown', check);
    input.addEventListener('keyup', check);
    input.addEventListener('blur', () => { warning.hidden = true; });
  };

  // A six-digit code is sent as soon as it is complete, once.
  const autoSubmit = (input) => {
    let sent = false;
    input.addEventListener('input', () => {
      input.value = input.value.replace(/\D/g, '').slice(0, 6);
      if (input.value.length === 6 && !sent && input.form) {
        sent = true;
        input.form.requestSubmit();
      }
    });
  };

  const copy = (button) => {
    const source = document.getElementById(button.dataset.copy);
    const text = button.querySelector('span');
    if (!source || !text || !navigator.clipboard) return;
    const idle = text.textContent;
    button.addEventListener('click', () => {
      navigator.clipboard.writeText(source.textContent.replace(/\s+/g, '')).then(() => {
        text.textContent = button.dataset.labelDone;
        setTimeout(() => { text.textContent = idle; }, 2000);
      }, () => { /* the key stays on screen to be typed */ });
    });
  };

  // Ticks the realm's rules as they are met; the server still decides.
  const count = (value, pattern) => (value.match(pattern) || []).length;
  const rules = (list) => {
    const input = document.getElementById(list.dataset.rulesFor);
    if (!input) return;
    const met = {
      length: (v) => [...v].length,
      upperCase: (v) => count(v, /\p{Lu}/gu),
      lowerCase: (v) => count(v, /\p{Ll}/gu),
      digits: (v) => count(v, /\p{Nd}/gu),
      specialChars: (v) => count(v, /[^\p{L}\p{Nd}]/gu),
    };
    input.addEventListener('input', () => {
      for (const rule of list.querySelectorAll('li[data-rule]')) {
        const measure = met[rule.dataset.rule];
        rule.classList.toggle('ok', !!measure && measure(input.value) >= Number(rule.dataset.min));
      }
    });
  };

  // An identity-provider link is followed once: a second click would start a second sign-in.
  const onceLinks = () => document.addEventListener('click', (event) => {
    const link = event.target.closest('a[data-once-link]');
    if (!link) return;
    if (link.getAttribute('aria-disabled') === 'true') {
      event.preventDefault();
      return;
    }
    link.classList.add('is-disabled');
    link.setAttribute('aria-disabled', 'true');
  });

  // Keycloak's own watcher: when the same sign-in completes in another tab, this one follows.
  const sessionWatch = () => {
    const { resources, ssoPoll, authSession } = document.body.dataset;
    if (!resources || !ssoPoll) return;
    import(resources + '/js/authChecker.js').then((checker) => {
      checker.startSessionPolling(ssoPoll);
      if (authSession) checker.checkAuthSession(authSession);
    }, () => { /* without it, the page simply stays where it is */ });
  };

  const ready = () => {
    document.querySelectorAll('[data-theme-toggle]').forEach(themeToggle);
    document.querySelectorAll('[data-reveal]').forEach(reveal);
    document.querySelectorAll('[data-caps-for]').forEach(capsLock);
    document.querySelectorAll('[data-auto-submit]').forEach(autoSubmit);
    document.querySelectorAll('[data-copy]').forEach(copy);
    document.querySelectorAll('[data-rules-for]').forEach(rules);
    onceLinks();
    sessionWatch();
  };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', ready);
  else ready();
})();
