// The one script of the HTML pages. It only enhances them; every page works without it.
//
// - Theme switch without a reload; dates in the browser's time zone.
// - Menus (<details>) close when another one opens, on Escape and on clicks outside.
// - Folder pages: selection count, drag and drop of files and folders, folder upload, and an
//   upload queue with progress. Small files are sent with one PUT; large ones in chunks
//   (chunked upload v2 of the server), each retried after network errors, so that an
//   interrupted connection resumes where it stopped.
//
// Requests carry the session's CSRF token in X-Gono-CSRF. The DOM is built with
// createElement and textContent only: file names never become markup.
(() => {
  "use strict";

  const SMALL_FILE = 16 * 1024 * 1024;
  const CHUNK = 10 * 1024 * 1024;
  const RETRIES = 6;

  const textNode = document.getElementById("gono-text");
  const T = textNode ? JSON.parse(textNode.textContent) : {};
  const csrfMeta = document.querySelector('meta[name="gono-csrf"]');
  const CSRF = csrfMeta ? csrfMeta.content : "";
  const LANG = document.documentElement.lang || "en";

  /** Fills the {} placeholders of a translated string in order. */
  function fill(template, ...values) {
    let index = 0;
    return String(template || "").replace(/\{\}/g, () => String(values[index++] ?? ""));
  }

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function formatBytes(bytes) {
    const units = ["B", "KB", "MB", "GB", "TB"];
    let unit = 0;
    let value = bytes;
    while (value >= 1024 && unit < units.length - 1) {
      value /= 1024;
      unit += 1;
    }
    return unit === 0 ? `${bytes} B` : `${value.toFixed(1)} ${units[unit]}`;
  }

  // ------------------------------------------------------------------------------------------
  // Theme
  // ------------------------------------------------------------------------------------------

  function setupTheme() {
    for (const form of document.querySelectorAll("form[data-theme-form]")) {
      form.addEventListener("submit", async (event) => {
        event.preventDefault();
        try {
          const response = await fetch(form.action, {
            method: "POST",
            body: new URLSearchParams(new FormData(form)),
            headers: { Accept: "application/json" },
            credentials: "same-origin",
          });
          if (!response.ok) throw new Error(String(response.status));
          const { theme } = await response.json();
          const root = document.documentElement;
          if (theme === "light" || theme === "dark") root.dataset.theme = theme;
          else delete root.dataset.theme;
          const label = { light: T.themeLight, dark: T.themeDark }[theme] || T.themeSystem;
          const button = form.querySelector("button");
          if (button && label) button.setAttribute("aria-label", label);
        } catch {
          form.submit();
        }
      });
    }
  }

  // ------------------------------------------------------------------------------------------
  // Dates in the browser's time zone
  // ------------------------------------------------------------------------------------------

  function setupTimes() {
    const now = new Date();
    const dayStart = (date) => new Date(date.getFullYear(), date.getMonth(), date.getDate());
    const today = dayStart(now).getTime();
    let time;
    let monthDay;
    let full;
    try {
      time = new Intl.DateTimeFormat(LANG, { hour: "2-digit", minute: "2-digit", hourCycle: "h23" });
      monthDay = new Intl.DateTimeFormat(LANG, { month: "short", day: "numeric" });
      full = new Intl.DateTimeFormat(LANG, { year: "numeric", month: "short", day: "numeric" });
    } catch {
      return;
    }
    const zh = LANG.startsWith("zh");
    for (const node of document.querySelectorAll("time[datetime]")) {
      const date = new Date(node.getAttribute("datetime"));
      if (Number.isNaN(date.getTime())) continue;
      node.title = date.toLocaleString(LANG);
      const days = Math.round((today - dayStart(date).getTime()) / 86400000);
      const clock = time.format(date);
      let label;
      if (days === 0) label = zh ? `${T.today} ${clock}` : `${T.today}, ${clock}`;
      else if (days === 1) label = zh ? `${T.yesterday} ${clock}` : `${T.yesterday}, ${clock}`;
      else if (date.getFullYear() === now.getFullYear()) {
        label = zh ? `${monthDay.format(date)} ${clock}` : `${monthDay.format(date)}, ${clock}`;
      } else label = full.format(date);
      node.textContent = label;
    }
  }

  // ------------------------------------------------------------------------------------------
  // Menus
  // ------------------------------------------------------------------------------------------

  function setupMenus() {
    const menus = () => document.querySelectorAll("details.menu[open], details.mobile-nav[open]");
    document.addEventListener("toggle", (event) => {
      const opened = event.target;
      if (!(opened instanceof HTMLDetailsElement) || !opened.open) return;
      for (const other of menus()) if (other !== opened) other.open = false;
    }, true);
    document.addEventListener("click", (event) => {
      for (const menu of menus()) if (!menu.contains(event.target)) menu.open = false;
    });
    document.addEventListener("keydown", (event) => {
      if (event.key !== "Escape") return;
      for (const menu of menus()) {
        menu.open = false;
        menu.querySelector("summary")?.focus();
      }
    });
  }

  // ------------------------------------------------------------------------------------------
  // Selection
  // ------------------------------------------------------------------------------------------

  function setupSelection() {
    const bulk = document.querySelector("[data-bulk]");
    if (!bulk) return;
    const boxes = [...document.querySelectorAll(".file-row__check")];
    const all = bulk.querySelector("[data-select-all]");
    const allBox = all?.querySelector("input");
    const count = bulk.querySelector("[data-selected]");
    const buttons = [...bulk.querySelectorAll("button")];
    const update = () => {
      const selected = boxes.filter((box) => box.checked).length;
      count.textContent = fill(T.selected, selected);
      for (const button of buttons) button.disabled = selected === 0;
      if (allBox) {
        allBox.checked = selected > 0 && selected === boxes.length;
        allBox.indeterminate = selected > 0 && selected < boxes.length;
      }
    };
    if (all) all.hidden = false;
    allBox?.addEventListener("change", () => {
      for (const box of boxes) box.checked = allBox.checked;
      update();
    });
    for (const box of boxes) box.addEventListener("change", update);
    update();
  }

  // ------------------------------------------------------------------------------------------
  // Uploads
  // ------------------------------------------------------------------------------------------

  function encodePath(path) {
    return path.split("/").filter(Boolean).map(encodeURIComponent).join("/");
  }

  /** One XMLHttpRequest, for upload progress. Resolves with the status; 0 = network error. */
  function send(method, url, body, headers, onProgress, track) {
    return new Promise((resolve) => {
      const request = new XMLHttpRequest();
      request.open(method, url);
      request.setRequestHeader("X-Gono-CSRF", CSRF);
      for (const [name, value] of Object.entries(headers || {})) request.setRequestHeader(name, value);
      if (onProgress) request.upload.onprogress = (event) => onProgress(event.loaded);
      request.onload = () => resolve(request.status);
      request.onerror = () => resolve(0);
      request.onabort = () => resolve(-1);
      if (track) track(request);
      request.send(body ?? null);
    });
  }

  const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

  function randomId() {
    const bytes = new Uint8Array(12);
    crypto.getRandomValues(bytes);
    return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
  }

  class Queue {
    constructor(root, folderUrl, folderName) {
      this.root = root;
      this.folderUrl = folderUrl.endsWith("/") ? folderUrl : `${folderUrl}/`;
      this.folderName = folderName;
      this.items = [];
      this.running = false;
      this.cancelled = false;
      this.madeFolders = new Set();
      this.current = null;
      this.done = 0;
      this.failed = 0;
      window.addEventListener("beforeunload", (event) => {
        if (!this.running) return;
        event.preventDefault();
        event.returnValue = T.leave;
      });
    }

    view() {
      if (this.pane) return;
      this.pane = el("section", "pane uploads");
      this.pane.setAttribute("aria-live", "polite");
      const head = el("div", "uploads__head");
      head.append(el("h2", "", T.uploads));
      this.action = el("button", "btn sm", T.cancelAll);
      this.action.type = "button";
      this.action.addEventListener("click", () => {
        if (this.running) this.cancel();
        else location.reload();
      });
      head.append(this.action);
      this.list = el("div");
      this.pane.append(head, this.list);
      this.root.append(this.pane);
    }

    /** Adds files; `path` is the file's path below the folder ("a/b.txt"). */
    add(entries, replace) {
      this.view();
      for (const { file, path } of entries) {
        const row = el("div", "upload");
        const name = el("span", "upload__name", path);
        const state = el("span", "upload__state", T.waiting);
        const bar = el("progress");
        bar.max = Math.max(file.size, 1);
        bar.value = 0;
        row.append(name, state, bar);
        this.list.append(row);
        this.items.push({ file, path, replace, row, state, bar });
      }
      if (!this.running) this.run();
    }

    cancel() {
      this.cancelled = true;
      this.current?.abort();
    }

    async run() {
      this.running = true;
      this.cancelled = false;
      while (this.items.length > 0) {
        const item = this.items.shift();
        if (this.cancelled) {
          this.finish(item, "failed", T.cancelled);
          continue;
        }
        try {
          await this.upload(item);
        } catch {
          this.finish(item, "failed", T.failed);
        }
      }
      this.running = false;
      this.action.textContent = T.close;
      if (this.failed === 0 && this.done > 0) {
        location.href = `${this.folderUrl}?done=uploaded&n=${this.done}`;
      }
    }

    finish(item, kind, text) {
      item.row.classList.add(kind === "done" ? "upload--done" : "upload--failed");
      item.state.textContent = text;
      if (kind === "done") {
        item.bar.value = item.bar.max;
        this.done += 1;
      } else this.failed += 1;
    }

    progress(item, sent) {
      item.bar.value = sent;
      item.state.textContent = fill(T.uploading, formatBytes(sent), formatBytes(item.file.size));
    }

    async folders(path) {
      const parts = path.split("/").slice(0, -1);
      let current = "";
      for (const part of parts) {
        current = current ? `${current}/${part}` : part;
        if (this.madeFolders.has(current)) continue;
        const status = await send("MKCOL", `${this.folderUrl}${encodePath(current)}/`);
        if (status >= 400 || status === 0) throw new Error(`MKCOL ${status}`);
        this.madeFolders.add(current);
      }
    }

    /** Asks whether to replace an existing file. */
    confirmReplace(item) {
      return window.confirm(fill(T.conflict, item.path));
    }

    async upload(item) {
      await this.folders(item.path);
      const url = `${this.folderUrl}${encodePath(item.path)}`;
      const mtime = String(Math.floor((item.file.lastModified || Date.now()) / 1000));
      const done = (status, replaced) => {
        if (status >= 200 && status < 300) {
          this.finish(item, "done", replaced ? T.replaced : T.done);
          return true;
        }
        return false;
      };
      if (item.file.size <= SMALL_FILE) {
        let replace = item.replace;
        for (let attempt = 0; attempt <= RETRIES; attempt += 1) {
          const headers = { "X-OC-MTime": mtime };
          if (!replace) headers["If-None-Match"] = "*";
          const status = await send("PUT", url, item.file, headers, (sent) => this.progress(item, sent),
            (request) => { this.current = request; });
          if (done(status, replace && !item.replace)) return;
          if (status === -1) return this.finish(item, "failed", T.cancelled);
          if (status === 412 && !replace) {
            if (!this.confirmReplace(item)) return this.finish(item, "failed", T.skipped);
            replace = true;
            attempt -= 1;
            continue;
          }
          if (status !== 0 && status < 500) return this.finish(item, "failed", `${T.failed} (${status})`);
          item.state.textContent = T.retrying;
          await sleep(1000 * 2 ** attempt);
        }
        return this.finish(item, "failed", T.failed);
      }
      return this.chunked(item, url, mtime);
    }

    async chunked(item, url, mtime) {
      const id = randomId();
      const total = item.file.size;
      const query = (step, extra = "") => `${url}?chunked=${step}&id=${id}&total=${total}${extra}`;
      const start = await send("POST", query("start"));
      if (start < 200 || start >= 300) return this.finish(item, "failed", `${T.failed} (${start})`);
      let offset = 0;
      while (offset < total) {
        const end = Math.min(offset + CHUNK, total);
        const chunk = item.file.slice(offset, end);
        let ok = false;
        for (let attempt = 0; attempt <= RETRIES && !ok; attempt += 1) {
          const status = await send("PUT", query("part", `&start=${offset}&end=${end - 1}`), chunk, {},
            (sent) => this.progress(item, offset + sent), (request) => { this.current = request; });
          if (status >= 200 && status < 300) ok = true;
          else if (status === -1) {
            await send("DELETE", query("cancel"));
            return this.finish(item, "failed", T.cancelled);
          } else if (status !== 0 && status < 500) {
            await send("DELETE", query("cancel"));
            return this.finish(item, "failed", `${T.failed} (${status})`);
          } else {
            item.state.textContent = T.retrying;
            await sleep(1000 * 2 ** attempt);
          }
        }
        if (!ok) {
          await send("DELETE", query("cancel"));
          return this.finish(item, "failed", T.failed);
        }
        offset = end;
      }
      item.state.textContent = T.finishing;
      let replace = item.replace;
      for (let attempt = 0; attempt <= RETRIES; attempt += 1) {
        const headers = { "X-OC-MTime": mtime };
        if (!replace) headers["If-None-Match"] = "*";
        const status = await send("POST", query("finish"), null, headers);
        if (status >= 200 && status < 300) {
          return this.finish(item, "done", replace && !item.replace ? T.replaced : T.done);
        }
        if (status === 412 && !replace) {
          if (!this.confirmReplace(item)) {
            await send("DELETE", query("cancel"));
            return this.finish(item, "failed", T.skipped);
          }
          replace = true;
          attempt -= 1;
          continue;
        }
        if (status !== 0 && status < 500) break;
        await sleep(1000 * 2 ** attempt);
      }
      await send("DELETE", query("cancel"));
      return this.finish(item, "failed", T.failed);
    }
  }

  /** Every file below dropped entries, with its path relative to the drop. */
  async function walk(entry, prefix, out) {
    if (entry.isFile) {
      const file = await new Promise((resolve, reject) => entry.file(resolve, reject));
      out.push({ file, path: `${prefix}${entry.name}` });
    } else if (entry.isDirectory) {
      const reader = entry.createReader();
      // readEntries returns the entries in batches until an empty one.
      for (;;) {
        const batch = await new Promise((resolve, reject) => reader.readEntries(resolve, reject));
        if (batch.length === 0) break;
        for (const child of batch) await walk(child, `${prefix}${entry.name}/`, out);
      }
    }
  }

  function setupUploads() {
    const layout = document.querySelector("[data-folder]");
    const root = document.querySelector("[data-uploads]");
    if (!layout || !root || !CSRF || !window.fetch) return;
    const queue = new Queue(root, layout.dataset.folder, layout.dataset.folderName || "");
    const form = document.querySelector("form[data-upload-form]");
    const replaceBox = form?.querySelector('input[name="replace"]');
    const replace = () => Boolean(replaceBox?.checked);

    const picker = (directory) => {
      const input = document.createElement("input");
      input.type = "file";
      input.multiple = true;
      if (directory) input.webkitdirectory = true;
      input.addEventListener("change", () => {
        const entries = [...input.files].map((file) => ({
          file,
          path: directory && file.webkitRelativePath ? file.webkitRelativePath : file.name,
        }));
        if (entries.length) queue.add(entries, replace());
      });
      input.click();
    };

    if (form) {
      form.addEventListener("submit", (event) => {
        const input = form.querySelector('input[type="file"]');
        if (!input || input.files.length === 0) return;
        event.preventDefault();
        queue.add([...input.files].map((file) => ({ file, path: file.name })), replace());
        input.value = "";
      });
      const folderButton = form.querySelector("[data-upload-folder]");
      if (folderButton && "webkitdirectory" in document.createElement("input")) {
        folderButton.hidden = false;
        folderButton.addEventListener("click", () => picker(true));
      }
      const hint = form.querySelector("[data-drop-hint]");
      if (hint) hint.hidden = false;
    }
    document.querySelector("[data-upload-button]")?.addEventListener("click", (event) => {
      event.preventDefault();
      picker(false);
    });

    // Drag and drop anywhere on the page.
    let overlay = null;
    let depth = 0;
    const hasFiles = (event) => [...(event.dataTransfer?.types || [])].includes("Files");
    const hide = () => {
      depth = 0;
      overlay?.remove();
      overlay = null;
    };
    document.addEventListener("dragenter", (event) => {
      if (!hasFiles(event)) return;
      event.preventDefault();
      depth += 1;
      if (!overlay) {
        overlay = el("div", "dropzone");
        overlay.append(el("div", "dropzone__box", fill(T.dropHere, queue.folderName)));
        document.body.append(overlay);
      }
    });
    document.addEventListener("dragleave", (event) => {
      if (!hasFiles(event)) return;
      depth -= 1;
      if (depth <= 0) hide();
    });
    document.addEventListener("dragover", (event) => {
      if (!hasFiles(event)) return;
      event.preventDefault();
      event.dataTransfer.dropEffect = "copy";
    });
    document.addEventListener("drop", async (event) => {
      if (!hasFiles(event)) return;
      event.preventDefault();
      hide();
      const items = [...event.dataTransfer.items];
      const entries = items.map((item) => item.webkitGetAsEntry?.()).filter(Boolean);
      const out = [];
      if (entries.length) {
        for (const entry of entries) await walk(entry, "", out);
      } else {
        for (const file of event.dataTransfer.files) out.push({ file, path: file.name });
      }
      if (out.length) queue.add(out, replace());
    });
  }

  function start() {
    setupTheme();
    setupTimes();
    setupMenus();
    setupSelection();
    setupUploads();
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start);
  else start();
})();
