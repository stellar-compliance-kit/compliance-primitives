(() => {
  const input = document.querySelector('[data-search]');
  const items = [...document.querySelectorAll('[data-search-item]')];
  if (!input || items.length === 0) return;
  input.addEventListener('input', () => {
    const query = input.value.trim().toLowerCase();
    let visible = 0;
    items.forEach((item) => {
      const match = !query || item.textContent.toLowerCase().includes(query);
      item.hidden = !match;
      if (match) visible += 1;
    });
    const empty = document.querySelector('[data-search-empty]');
    if (empty) empty.hidden = visible !== 0;
  });
})();
