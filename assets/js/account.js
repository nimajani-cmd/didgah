// Account lookup. Each student's record is encrypted with a key derived from class + birthdate,
// so the data file is not a readable list; the browser derives the key from what is entered.
(() => {
  const CLASSES = { r1: 'دهم ریاضی یک', r2: 'دهم ریاضی دو', t1: 'دهم تجربی یک' };
  const form = document.getElementById('acc-form');
  const err = document.getElementById('acc-error');
  const submit = document.getElementById('acc-submit');
  const result = document.getElementById('acc-result');
  const copyBtn = document.getElementById('acc-copy');
  let data;
  const b64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
  const hex = a => Array.from(a, x => x.toString(16).padStart(2, '0')).join('');
  const showError = msg => { err.textContent = msg; err.hidden = false; };

  async function lookup(cid, bd) {
    if (!data) {
      const r = await fetch('assets/data/accounts.json', { cache: 'no-cache' });
      if (!r.ok) throw new Error('load');
      data = await r.json();
    }
    const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(cid + '|' + bd), 'PBKDF2', false, ['deriveBits']);
    const bits = new Uint8Array(await crypto.subtle.deriveBits(
      { name: 'PBKDF2', hash: 'SHA-256', salt: b64(data.salt), iterations: data.iter }, base, 384));
    const entry = data.entries.find(e => e.id === hex(bits.slice(0, 16)));
    if (!entry) return null;
    const key = await crypto.subtle.importKey('raw', bits.slice(16), 'AES-GCM', false, ['decrypt']);
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64(entry.iv) }, key, b64(entry.ct));
    return JSON.parse(new TextDecoder().decode(plain));
  }

  form.addEventListener('submit', async e => {
    e.preventDefault();
    err.hidden = true;
    const cid = (form.querySelector('input[name="acc-class"]:checked') || {}).value;
    const d = document.getElementById('acc-d').value, m = document.getElementById('acc-m').value, y = document.getElementById('acc-y').value;
    if (!cid) return showError('اول کلاست را انتخاب کن.');
    if (!d || !m) return showError('روز و ماه تولدت را انتخاب کن.');
    if (!window.crypto || !crypto.subtle) return showError('مرورگرت این بخش را پشتیبانی نمی‌کند. صفحه را با Chrome یا Safari باز کن.');
    const label = submit.querySelector('span');
    submit.disabled = true; label.textContent = 'در حال جستجو...';
    try {
      const rec = await lookup(cid, `${y}/${m.padStart(2, '0')}/${d.padStart(2, '0')}`);
      if (!rec) return showError('با این کلاس و تاریخ تولد کسی پیدا نشد. کلاس و تاریخ را دوباره بررسی کن؛ اگر درست بود، به استاد بگو.');
      document.getElementById('acc-r-class').textContent = CLASSES[cid];
      document.getElementById('acc-r-name').textContent = rec.n;
      document.getElementById('acc-r-user').textContent = rec.u;
      copyBtn.querySelector('span').textContent = 'کپی';
      form.hidden = true; result.hidden = false;
      result.scrollIntoView({ block: 'nearest' });
    } catch (_) {
      showError('اتصال برقرار نشد. اینترنتت را بررسی کن و دوباره امتحان کن.');
    } finally {
      submit.disabled = false; label.textContent = 'نمایش نام کاربری';
    }
  });

  copyBtn.addEventListener('click', async () => {
    const text = document.getElementById('acc-r-user').textContent;
    try { await navigator.clipboard.writeText(text); }
    catch (_) {
      const r = document.createRange(); r.selectNodeContents(document.getElementById('acc-r-user'));
      const sel = getSelection(); sel.removeAllRanges(); sel.addRange(r); document.execCommand('copy');
    }
    copyBtn.querySelector('span').textContent = 'کپی شد';
  });

  document.getElementById('acc-again').addEventListener('click', () => {
    result.hidden = true; form.hidden = false;
    ['acc-r-class', 'acc-r-name', 'acc-r-user'].forEach(id => { document.getElementById(id).textContent = ''; });
  });
})();

