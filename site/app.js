// Dark/light theme toggle — persisted, defaults to the OS preference.
(function () {
  const root = document.documentElement;
  const saved = localStorage.getItem("aegis-theme");
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
      localStorage.setItem("aegis-theme", light ? "dark" : "light");
      sync();
    });
  }
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
