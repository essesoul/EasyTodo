// Register the service worker and listen for updates
(function(){
  if (!('serviceWorker' in navigator)) return;
  window.addEventListener('load', function(){
    // Register at root scope so we can control all pages
    navigator.serviceWorker.register('/sw.js').then(function(reg){
      // Optional: update flow
      if (reg.waiting) {
        // A new SW is waiting; could prompt user to refresh
        // For simplicity, let it take control on next load
      }
      reg.addEventListener('updatefound', function(){
        const nw = reg.installing;
        if (!nw) return;
        nw.addEventListener('statechange', function(){
          // Could notify about updates
        });
      });
    }).catch(function(err){
      console.warn('SW registration failed:', err);
    });
  });
})();

