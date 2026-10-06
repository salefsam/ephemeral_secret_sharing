(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const views = ["create-view", "link-view", "reveal-view", "secret-view", "gone-view"];
  const show = (id) => views.forEach((v) => ($(v).hidden = v !== id));

  const b64 = {
    enc(buf) {
      let s = "";
      new Uint8Array(buf).forEach((b) => (s += String.fromCharCode(b)));
      return btoa(s);
    },
    dec(str) {
      const bin = atob(str);
      const out = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
      return out;
    },
    encUrl(buf) {
      return b64.enc(buf).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    },
    decUrl(str) {
      str = str.replace(/-/g, "+").replace(/_/g, "/");
      while (str.length % 4) str += "=";
      return b64.dec(str);
    },
  };

  async function encrypt(text) {
    const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt"]);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(text));
    const rawKey = await crypto.subtle.exportKey("raw", key);
    return { ciphertext: b64.enc(ct), iv: b64.enc(iv), key: b64.encUrl(rawKey) };
  }

  async function decrypt(ciphertext, iv, keyStr) {
    const key = await crypto.subtle.importKey("raw", b64.decUrl(keyStr), "AES-GCM", false, ["decrypt"]);
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64.dec(iv) }, key, b64.dec(ciphertext));
    return new TextDecoder().decode(pt);
  }

  async function copy(text, btn) {
    const old = btn.textContent;
    try {
      await navigator.clipboard.writeText(text);
      btn.textContent = "Copied!";
    } catch {
      btn.textContent = "Copy failed";
    }
    setTimeout(() => (btn.textContent = old), 1500);
  }

  // --- Create flow ---
  $("create-btn").addEventListener("click", async () => {
    const text = $("secret").value;
    const err = $("create-error");
    err.hidden = true;
    if (!text.trim()) {
      err.textContent = "Enter a secret first.";
      err.hidden = false;
      return;
    }
    const btn = $("create-btn");
    btn.disabled = true;
    try {
      const { ciphertext, iv, key } = await encrypt(text);
      const views = parseInt($("views").value, 10);
      const res = await fetch("/api/secrets", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ciphertext, iv, ttl: $("ttl").value, views }),
      });
      if (res.status === 413) throw new Error("Secret is too large.");
      if (!res.ok) throw new Error("Could not create the secret.");
      const { id } = await res.json();
      $("secret").value = "";
      $("link").value = `${location.origin}/s/${id}#${key}`;
      $("views-count").textContent = views === 1 ? "once" : `up to ${views} times`;
      show("link-view");
    } catch (e) {
      err.textContent = e.message || "Something went wrong.";
      err.hidden = false;
    } finally {
      btn.disabled = false;
    }
  });

  $("copy-btn").addEventListener("click", () => copy($("link").value, $("copy-btn")));
  $("link").addEventListener("focus", (e) => e.target.select());
  $("another-btn").addEventListener("click", () => show("create-view"));

  // --- Reveal flow ---
  const match = location.pathname.match(/^\/s\/([\w-]+)$/);
  if (match) {
    const id = match[1];
    const keyStr = location.hash.slice(1);
    if (!keyStr) {
      show("gone-view");
    } else {
      show("reveal-view");
      $("reveal-btn").addEventListener("click", async () => {
        const btn = $("reveal-btn");
        btn.disabled = true;
        try {
          const res = await fetch(`/api/secrets/${encodeURIComponent(id)}/reveal`, { method: "POST" });
          if (!res.ok) return show("gone-view");
          const { ciphertext, iv, remaining } = await res.json();
          const text = await decrypt(ciphertext, iv, keyStr);
          $("remaining-note").textContent =
            remaining > 0
              ? `This link can be opened ${remaining} more time${remaining === 1 ? "" : "s"}. Copy the secret now.`
              : "That was the last view. The secret has been deleted from the server. Copy it now.";
          if (remaining === 0) history.replaceState(null, "", "/s/" + id); // drop key from the address bar
          $("secret-out").textContent = text;
          show("secret-view");
        } catch {
          // Secret was already consumed server-side; a bad/missing key can't recover it.
          show("gone-view");
        }
      });
      $("copy-secret-btn").addEventListener("click", () => copy($("secret-out").textContent, $("copy-secret-btn")));
    }
  } else {
    show("create-view");
  }
})();
