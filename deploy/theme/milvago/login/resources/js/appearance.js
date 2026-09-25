(() => {
 const apply = mode => { document.documentElement.dataset.appearance = mode; };
 let mode;
 const savedCookie = document.cookie.split('; ').find(v=>v.startsWith('milvago_theme='))?.split('=')[1];
 try { mode = savedCookie || localStorage.getItem('milvago.theme'); } catch {}
 // Dark is the brand's default rendering (charte graphique v2.0): the system
 // setting is not consulted, only an explicit choice by this reader.
 if (mode !== 'light' && mode !== 'dark') mode = 'dark';
 apply(mode);

 // Localized labels. A Keycloak locale switch reloads the page, so reading the
 // document language at build time keeps the appearance label in sync with the
 // chosen language.
 const strings = {
  fr: { dark: 'Mode sombre', light: 'Mode clair', darkAria: 'Activer le thème sombre', lightAria: 'Activer le thème clair', lang: 'Langue' },
  en: { dark: 'Dark mode', light: 'Light mode', darkAria: 'Switch to the dark theme', lightAria: 'Switch to the light theme', lang: 'Language' },
  es: { dark: 'Modo oscuro', light: 'Modo claro', darkAria: 'Activar el tema oscuro', lightAria: 'Activar el tema claro', lang: 'Idioma' },
  pt: { dark: 'Modo escuro', light: 'Modo claro', darkAria: 'Ativar o tema escuro', lightAria: 'Ativar o tema claro', lang: 'Idioma' },
 };
 // Keyed on the full locale: pt-BR must not read as PT, which is a different
 // language to a Brazilian reader.
 const codes = { fr: 'FR', en: 'EN', es: 'ES', 'pt-br': 'BR' };

 addEventListener('DOMContentLoaded', () => {
  const locale = (document.documentElement.lang || 'fr').toLowerCase();
  const t = strings[locale.slice(0, 2)] || strings.fr;

  const controls = document.createElement('div');
  controls.className = 'mv-controls';

  // Appearance toggle (label follows the current language).
  const button = document.createElement('button');
  button.type = 'button';
  button.className = 'mv-appearance';
  const paint = () => {
   button.textContent = mode === 'dark' ? t.light : t.dark;
   button.setAttribute('aria-label', mode === 'dark' ? t.lightAria : t.darkAria);
  };
  button.addEventListener('click', () => {
   mode = mode === 'dark' ? 'light' : 'dark';
   apply(mode);
   paint();
   document.cookie = 'milvago_theme=' + mode + '; Path=/; SameSite=Lax' + (location.protocol === 'https:' ? '; Secure' : '');
   try { localStorage.setItem('milvago.theme', mode); } catch {}
  });
  paint();
  controls.append(button);

  // Language: replace Keycloak's native <select> with a compact segmented
  // toggle built from its own options (keeps the kc_locale navigation).
  const select = document.getElementById('login-select-toggle');
  if (select && select.options.length > 1) {
   const group = document.createElement('div');
   group.className = 'mv-lang';
   group.setAttribute('role', 'group');
   group.setAttribute('aria-label', t.lang);
   for (const option of select.options) {
    const match = /[?&]kc_locale=([a-zA-Z-]+)/.exec(option.value);
    const loc = (match ? match[1] : '').toLowerCase();
    const current = option.selected || (loc && loc === locale);
    const item = document.createElement(current ? 'span' : 'a');
    item.className = 'mv-lang-item';
    item.textContent = codes[loc] || (loc ? loc.slice(0, 2).toUpperCase() : option.text.trim().slice(0, 2).toUpperCase());
    item.title = option.text.trim();
    if (current) item.setAttribute('aria-current', 'true');
    else item.href = option.value;
    group.append(item);
   }
   controls.append(group);
   document.documentElement.classList.add('mv-enhanced');
  }

  document.body.append(controls);
 });
})();
