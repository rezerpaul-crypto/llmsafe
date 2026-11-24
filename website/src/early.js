/* Runs before first paint: flags that scripting works and restores an explicit theme choice.
   Without a stored choice nothing is set, so the page follows the system theme through CSS. */
(function () {
  var d = document.documentElement;
  d.classList.add('js');
  try {
    var t = localStorage.getItem('pfos-theme');
    if (t === 'dark' || t === 'light') d.dataset.theme = t;
  } catch (e) { /* storage blocked: follow the system theme */ }
})();
