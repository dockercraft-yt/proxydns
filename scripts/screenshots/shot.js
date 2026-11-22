// Screenshot helper: pre-fills the "new entry" form with example values.
(function () {
  if (!location.hash.startsWith('#/new')) return;
  const iv = setInterval(() => {
    const form = document.querySelector('#app form');
    if (!form) return;
    clearInterval(iv);
    const inputs = form.querySelectorAll('input[type=text], input[type=number]');
    const selects = form.querySelectorAll('select');
    const set = (el, v, ev) => { el.value = v; el.dispatchEvent(new Event(ev, { bubbles: true })); };
    set(inputs[0], 'git.home.example.org', 'input');
    set(inputs[1], '192.168.10.25', 'input');
    set(inputs[2], '3000', 'input');
    // selects: scheme, access list, certificate
    for (const s of selects) {
      if ([...s.options].some((o) => o.text === 'LAN only')) set(s, '1', 'change');
      if ([...s.options].some((o) => o.text.startsWith('*.home'))) set(s, '1', 'change');
    }
  }, 50);
})();
