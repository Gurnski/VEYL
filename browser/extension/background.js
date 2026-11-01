// VEYL Passwords: background service worker.
//
// The only part of the extension that talks to VEYL. Messages go through Chrome's native
// messaging to Veyl.BrowserHost.exe, which hands them to the running VEYL app. VEYL decides
// which logins match a site; this file only tells it which site is asking.
//
// The site always comes from the browser, never from the page: sender.origin for a content
// script (the frame's real origin, which page scripts can't change), or the active tab's
// URL for the toolbar popup. A frame from another site gets that site's logins, not yours.

const HOST = "com.veyl.vault";
const SAVE_TTL_MS = 2 * 60 * 1000; // how long a "save this login?" offer waits for an answer

// ------------------------------------------------------------------ talking to VEYL
function native(message) {
  return new Promise((resolve) => {
    chrome.runtime.sendNativeMessage(HOST, { v: 1, ...message }, (reply) => {
      if (chrome.runtime.lastError) {
        const text = chrome.runtime.lastError.message || "";
        // "Specified native messaging host not found" means VEYL isn't installed (or is too old).
        resolve({ ok: false, error: /not found/i.test(text) ? "no-host" : "host-failed", detail: text });
        return;
      }
      resolve(reply || { ok: false, error: "host-failed" });
    });
  });
}

async function token() {
  const { veylToken } = await chrome.storage.local.get("veylToken");
  return veylToken || "";
}

// Sends a request that needs the pairing token. A "not-paired" answer means VEYL no
// longer knows this browser (pairing removed in VEYL), so forget the stale token.
async function call(message) {
  const t = await token();
  if (!t) return { ok: false, error: "not-paired" };
  const reply = await native({ ...message, token: t });
  if (reply.error === "not-paired") await chrome.storage.local.remove("veylToken");
  return reply;
}

async function pair() {
  const reply = await native({ type: "pair" });
  if (reply.ok && reply.token) await chrome.storage.local.set({ veylToken: reply.token });
  return reply;
}

// ------------------------------------------------------------------ where a request comes from
function webOrigin(url) {
  try {
    const u = new URL(url);
    return u.protocol === "https:" || u.protocol === "http:" ? u.origin : null;
  } catch {
    return null;
  }
}

function senderOrigin(sender) {
  return webOrigin(sender.origin || sender.url || "");
}

async function tabOrigin(tabId) {
  try {
    const tab = await chrome.tabs.get(tabId);
    return webOrigin(tab.url || "");
  } catch {
    return null;
  }
}

// ------------------------------------------------------------------ pending "save this login?"
async function pendingFor(tabId) {
  const key = "save:" + tabId;
  const got = await chrome.storage.session.get(key);
  const p = got[key];
  if (!p) return null;
  if (Date.now() - p.at > SAVE_TTL_MS) {
    await chrome.storage.session.remove(key);
    return null;
  }
  return p;
}

const clearPending = (tabId) => chrome.storage.session.remove("save:" + tabId);

const hostOf = (origin) => new URL(origin).hostname.replace(/^www\./, "");

// Same site, allowing for the login page and the page after it being on sibling hosts
// (login.example.com, then www.example.com).
function sameSite(a, b) {
  const x = hostOf(a), y = hostOf(b);
  return x === y || x.endsWith("." + y) || y.endsWith("." + x);
}

// ------------------------------------------------------------------ requests from the extension
async function handle(msg, sender) {
  const tabId = sender.tab ? sender.tab.id : msg.tabId;
  const fromContent = !!sender.tab;
  const origin = fromContent ? senderOrigin(sender) : await tabOrigin(msg.tabId);

  switch (msg.cmd) {
    case "status":
      // Without a token VEYL answers "not-paired" (or the host reports "not-running"/"no-host").
      return (await token()) ? call({ type: "status" }) : native({ type: "status" });

    case "pair":
      return pair();

    case "open":
      return native({ type: "open" });

    case "list":
      if (!origin) return { ok: false, error: "not-a-website" };
      return call({ type: "list", origin });

    case "fill": {
      // From the in-page menu: the answer goes back to the same frame that asked.
      if (!origin) return { ok: false, error: "not-a-website" };
      return call({ type: "fill", origin, id: msg.id });
    }

    case "fillTab": {
      // From the popup: fill the tab's top frame, and only if it's still on the same site.
      if (!origin) return { ok: false, error: "not-a-website" };
      const reply = await call({ type: "fill", origin, id: msg.id });
      if (!reply.ok) return reply;
      const done = await chrome.tabs
        .sendMessage(msg.tabId, { cmd: "doFill", origin, username: reply.username, password: reply.password }, { frameId: 0 })
        .catch(() => null);
      return done && done.ok ? { ok: true } : { ok: false, error: "no-login-form" };
    }

    case "offerSave": {
      // A login form was submitted. Ask VEYL whether it's new or a changed password, and keep
      // the details (in memory only) for the save bar to offer on this page or the next.
      if (!origin || !msg.password) return { ok: false };
      const reply = await call({ type: "check", origin, username: msg.username || "", password: msg.password });
      if (reply.ok && reply.status === "same") return { ok: true, offer: null };
      if (!reply.ok && reply.error !== "locked") return reply;
      const offer = {
        origin,
        username: msg.username || "",
        password: msg.password,
        status: reply.ok ? reply.status : "locked",
        at: Date.now(),
      };
      await chrome.storage.session.set({ ["save:" + tabId]: offer });
      return { ok: true, offer: publicOffer(offer) };
    }

    case "pendingSave": {
      const p = await pendingFor(tabId);
      if (!p || !origin || !sameSite(p.origin, origin)) return { ok: true, offer: null };
      return { ok: true, offer: publicOffer(p) };
    }

    case "save": {
      const p = await pendingFor(tabId);
      if (!p) return { ok: false, error: "expired" };
      const reply = await call({ type: "save", origin: p.origin, username: p.username, password: p.password });
      if (reply.ok) await clearPending(tabId);
      return reply;
    }

    case "dismissSave":
      await clearPending(tabId);
      return { ok: true };

    default:
      return { ok: false, error: "unknown" };
  }
}

// The save bar needs to say what it's saving, but never gets the password back.
function publicOffer(p) {
  return { host: hostOf(p.origin), username: p.username, status: p.status };
}

chrome.runtime.onMessage.addListener((msg, sender, respond) => {
  // Only our own pages and content scripts can reach this listener; still, ignore other extensions.
  if (sender.id !== chrome.runtime.id) return false;
  handle(msg, sender).then(respond, (e) => respond({ ok: false, error: "failed", detail: String(e) }));
  return true; // answer asynchronously
});

chrome.tabs.onRemoved.addListener((tabId) => clearPending(tabId));
