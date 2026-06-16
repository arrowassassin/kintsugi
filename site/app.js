// Dark/light theme toggle — persisted, defaults to the OS preference.
(function () {
  const root = document.documentElement;
  const saved = localStorage.getItem("kintsugi-theme");
  const prefersLight = window.matchMedia("(prefers-color-scheme: light)").matches;
  const initial = saved || (prefersLight ? "light" : "dark");
  if (initial === "light") root.setAttribute("data-theme", "light");
  const btn = document.getElementById("theme");
  if (btn) {
    const sync = () => {
      btn.textContent = root.getAttribute("data-theme") === "light" ? "☾ dark" : "☀ light";
    };
    sync();
    btn.addEventListener("click", () => {
      const light = root.getAttribute("data-theme") === "light";
      if (light) root.removeAttribute("data-theme");
      else root.setAttribute("data-theme", "light");
      localStorage.setItem("kintsugi-theme", light ? "dark" : "light");
      sync();
    });
  }
})();

// Mobile hamburger: only kicks in <=640px (where the CSS hides the nav).
// At wider widths the nav is always visible and the button is display:none, so
// the attribute we set here is harmless.
(function () {
  const toggle = document.getElementById("navtoggle");
  const header = document.querySelector("header.nav");
  if (!toggle || !header) return;
  const close = () => {
    header.removeAttribute("data-nav");
    toggle.setAttribute("aria-expanded", "false");
    toggle.setAttribute("aria-label", "open menu");
  };
  toggle.addEventListener("click", () => {
    const open = header.getAttribute("data-nav") === "open";
    if (open) return close();
    header.setAttribute("data-nav", "open");
    toggle.setAttribute("aria-expanded", "true");
    toggle.setAttribute("aria-label", "close menu");
  });
  // Tapping a link inside the open menu should close it; otherwise the menu
  // covers the scroll target the user just chose.
  header.querySelectorAll("nav a").forEach((a) => a.addEventListener("click", close));
  // If the viewport grows past the mobile breakpoint while the menu is open,
  // collapse it so the desktop layout doesn't inherit the open state.
  window.matchMedia("(min-width: 641px)").addEventListener("change", (e) => {
    if (e.matches) close();
  });
})();

// Tiny progressive enhancement: copy-to-clipboard on command blocks.
document.querySelectorAll(".cmd .copy").forEach((btn) => {
  btn.addEventListener("click", () => {
    const pre = btn.parentElement.querySelector("pre");
    const text = pre ? pre.innerText : "";
    navigator.clipboard.writeText(text).then(
      () => {
        const old = btn.textContent;
        btn.textContent = "ok!";
        btn.classList.add("ok");
        setTimeout(() => {
          btn.textContent = old;
          btn.classList.remove("ok");
        }, 1200);
      },
      () => {
        btn.textContent = "err";
      }
    );
  });
});
