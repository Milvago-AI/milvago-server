// Blocking head script: the React bundle must never be needed for the first paint.
(() => {
  let choice;
  try {
    const cookie = document.cookie.split(';').map(value => value.trim()).find(value => /^milvago_theme=(light|dark)$/.test(value));
    choice = cookie?.split('=')[1];
  } catch { /* Preferences are optional. */ }
  if (!choice) {
    try { choice = localStorage.getItem('milvago.theme'); } catch { /* Use the system. */ }
  }
  const theme = choice === 'light' || choice === 'dark' ? choice :
    typeof matchMedia === 'function' && matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
  document.documentElement.dataset.theme = theme;
  document.querySelector('meta[name="theme-color"]')?.setAttribute('content', theme === 'light' ? '#F3F6FA' : '#111722');
})();
