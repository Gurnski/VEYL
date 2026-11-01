// Design preview only: popup.html#locked shows the "locked" screen, and so on.
// When the popup is wired up, this is replaced by code that asks VEYL for the real state.
if (location.hash.length > 1) document.body.dataset.show = location.hash.slice(1);
