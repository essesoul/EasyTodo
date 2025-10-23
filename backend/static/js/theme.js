// Theme management: light, dark, system
// Icons:
// - dark: <i class="fa-solid fa-moon"></i>
// - light: <i class="fa-solid fa-lightbulb"></i>
// - system: <i class="fa-solid fa-circle-half-stroke"></i>
(function(){
  const STORAGE_KEY = 'theme';
  const MQL = (function(){
    try{ return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)'); }
    catch(_){ return null; }
  })();

  function applyThemeColor(mode){
    try{
      const dark = (mode === 'dark') || (mode !== 'light' && !!(MQL && MQL.matches));
      const color = dark ? '#0b0e11' : '#f7f8fa';
      let meta = document.querySelector('meta[name="theme-color"]');
      if(!meta){
        meta = document.createElement('meta');
        meta.setAttribute('name','theme-color');
        document.head.appendChild(meta);
      }
      meta.setAttribute('content', color);
    }catch(_){/* no-op */}
  }

  function getMode(){
    const v = localStorage.getItem(STORAGE_KEY);
    return (v === 'light' || v === 'dark' || v === 'system') ? v : 'system';
  }

  function apply(mode){
    if(mode === 'light' || mode === 'dark'){
      document.documentElement.setAttribute('data-theme', mode);
    }else{ // system
      document.documentElement.removeAttribute('data-theme');
    }
    localStorage.setItem(STORAGE_KEY, mode);
    applyThemeColor(mode);
  }

  function updateIcon(btn){
    if(!btn) return;
    const mode = getMode();
    let cls = 'fa-circle-half-stroke';
    if(mode === 'dark') cls = 'fa-moon';
    else if(mode === 'light') cls = 'fa-lightbulb';
    btn.innerHTML = `<i class="fa-solid ${cls}"></i>`;
    const titleMap = { light: '当前：浅色（点击切换）', dark: '当前：深色（点击切换）', system: '当前：跟随系统（点击切换）' };
    btn.title = '切换明暗 · ' + (titleMap[mode]||'');
    btn.setAttribute('aria-label', btn.title);
  }

  function nextMode(curr){
    if(curr === 'light') return 'dark';
    if(curr === 'dark') return 'system';
    return 'light'; // system -> light
  }

  function init(){
    // Apply from storage (head also sets early to avoid FOUC)
    const mode = getMode();
    apply(mode);
    const btn = document.getElementById('themeBtn');
    updateIcon(btn);
    if(btn){
      btn.onclick = function(){
        const m = nextMode(getMode());
        apply(m);
        updateIcon(btn);
      };
    }

    // If following system, no attribute is set; CSS @media handles palette.
    // Optionally, react to changes to keep consistent if needed.
    try{
      if(MQL && typeof MQL.addEventListener === 'function'){
        MQL.addEventListener('change', ()=>{
          if(getMode()==='system'){
            // Update icon and theme-color when system scheme changes
            updateIcon(document.getElementById('themeBtn'));
            applyThemeColor('system');
          }
        });
      }
    }catch(_){/* no-op */}
  }

  if(document.readyState === 'loading'){
    document.addEventListener('DOMContentLoaded', init);
  }else{
    init();
  }
})();
