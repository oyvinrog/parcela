const invoke =
  window.__TAURI__?.core?.invoke ||
  window.__TAURI__?.tauri?.invoke;

const state = {
  vaultPath: "",
  vaultPassword: "",
  vault: { version: 1, files: [] },
  selectedFileId: null,
};

const shareIndexRegex = /^(.*)\.share([1-3])$/;

const statusEl = document.getElementById("status-msg");
const loginScreen = document.getElementById("login-screen");
const vaultScreen = document.getElementById("vault-screen");

const vaultPasswordEl = document.getElementById("vault-password");
const vaultPathEl = document.getElementById("vault-path");
const vaultSavePathEl = document.getElementById("vault-save-path");
const vaultCurrentPathEl = document.getElementById("vault-current-path");
const vaultNameEl = document.getElementById("vault-name");

const fileListEl = document.getElementById("file-list");
const detailEmptyEl = document.getElementById("detail-empty");
const detailPanelEl = document.getElementById("detail-panel");
const detailTitleEl = document.getElementById("detail-title");
const detailLightsEl = document.getElementById("detail-lights");
const detailCountEl = document.getElementById("detail-count");
const shareListEl = document.getElementById("share-list");
const detailResultEl = document.getElementById("detail-result");
const recoverBtn = document.getElementById("recover-file");

let pendingOpenPath = "";
let pendingSavePath = "";

function setStatus(message, kind = "") {
  statusEl.textContent = message;
  statusEl.className = "status";
  if (kind) statusEl.classList.add(kind);
}

function showVaultScreen() {
  loginScreen.classList.add("hidden");
  vaultScreen.classList.remove("hidden");
  vaultCurrentPathEl.textContent = state.vaultPath || "";
  vaultNameEl.textContent = state.vaultPath
    ? getFileName(state.vaultPath)
    : "Vault";
}

function showLoginScreen() {
  loginScreen.classList.remove("hidden");
  vaultScreen.classList.add("hidden");
}

function getFileName(path) {
  const parts = path.split(/[/\\]/);
  return parts[parts.length - 1] || path;
}

function getShareInfo(path) {
  const filename = getFileName(path);
  const match = filename.match(shareIndexRegex);
  if (!match) return null;
  return {
    baseName: match[1],
    index: Number(match[2]),
  };
}

function ensureAvailability(file) {
  if (!file.available) {
    file.available = [false, false, false];
  }
}

async function refreshAvailability(file) {
  ensureAvailability(file);
  const paths = file.shares.map((p) => p || "");
  const availability = await invoke("check_paths", { paths });
  file.available = availability;
}

async function refreshAllAvailability() {
  for (const file of state.vault.files) {
    await refreshAvailability(file);
  }
}

function renderFileList() {
  fileListEl.innerHTML = "";

  if (state.vault.files.length === 0) {
    const empty = document.createElement("div");
    empty.className = "path";
    empty.textContent = "No files in this vault yet.";
    fileListEl.appendChild(empty);
    return;
  }

  for (const file of state.vault.files) {
    ensureAvailability(file);
    const item = document.createElement("button");
    item.className = "file-item";
    if (file.id === state.selectedFileId) {
      item.classList.add("active");
    }
    item.type = "button";

    const title = document.createElement("div");
    title.className = "file-title";
    title.textContent = file.name;

    const meta = document.createElement("div");
    meta.className = "file-meta";

    const lights = document.createElement("div");
    lights.className = "lights-inline";

    file.available.forEach((available) => {
      const dot = document.createElement("span");
      dot.className = "light";
      dot.classList.add(available ? "available" : "missing");
      lights.appendChild(dot);
    });

    const count = document.createElement("span");
    const availableCount = file.available.filter(Boolean).length;
    count.textContent = `${availableCount}/3`;

    meta.appendChild(lights);
    meta.appendChild(count);

    item.appendChild(title);
    item.appendChild(meta);

    item.addEventListener("click", () => {
      state.selectedFileId = file.id;
      renderDetail();
      renderFileList();
    });

    fileListEl.appendChild(item);
  }
}

function renderDetail() {
  const file = state.vault.files.find((entry) => entry.id === state.selectedFileId);
  if (!file) {
    detailEmptyEl.classList.remove("hidden");
    detailPanelEl.classList.add("hidden");
    return;
  }

  ensureAvailability(file);
  detailEmptyEl.classList.add("hidden");
  detailPanelEl.classList.remove("hidden");
  detailTitleEl.textContent = file.name;

  const availableCount = file.available.filter(Boolean).length;
  detailCountEl.textContent = `${availableCount} of 3 available`;

  detailLightsEl.querySelectorAll(".light").forEach((el, idx) => {
    el.classList.remove("available", "missing");
    el.classList.add(file.available[idx] ? "available" : "missing");
  });

  shareListEl.innerHTML = "";
  for (let i = 0; i < 3; i += 1) {
    const card = document.createElement("div");
    card.className = "share-card";

    const label = document.createElement("div");
    label.className = "label";
    label.innerHTML = `<span>Share ${i + 1}</span>`;

    const status = document.createElement("span");
    status.textContent = file.available[i] ? "Available" : "Missing";
    status.style.color = file.available[i] ? "#1d6b44" : "#8b6f5a";
    label.appendChild(status);

    const path = document.createElement("div");
    path.className = "path";
    path.textContent = file.shares[i] || "No location stored";

    card.appendChild(label);
    card.appendChild(path);
    shareListEl.appendChild(card);
  }

  recoverBtn.disabled = availableCount < 2;
}

async function saveVault() {
  await invoke("save_vault", {
    path: state.vaultPath,
    password: state.vaultPassword,
    vault: state.vault,
  });
}

function addOrUpdateFileEntry({ name, shares }) {
  let existing = state.vault.files.find((entry) => entry.name === name);
  if (!existing) {
    existing = {
      id: `${Date.now()}-${Math.random().toString(16).slice(2)}`,
      name,
      shares: [null, null, null],
    };
    state.vault.files.push(existing);
  }

  shares.forEach((path, idx) => {
    if (path) existing.shares[idx] = path;
  });

  state.vault.files.sort((a, b) => a.name.localeCompare(b.name));
  return existing;
}

async function handleOpenVault() {
  const password = vaultPasswordEl.value.trim();
  if (!pendingOpenPath || !password) {
    setStatus("Select a vault and enter the password.", "error");
    return;
  }

  try {
    setStatus("Opening vault...");
    const vault = await invoke("open_vault", {
      path: pendingOpenPath,
      password,
    });
    state.vaultPath = pendingOpenPath;
    state.vaultPassword = password;
    state.vault = vault;
    await refreshAllAvailability();
    state.selectedFileId = state.vault.files[0]?.id || null;
    renderFileList();
    renderDetail();
    showVaultScreen();
    setStatus("Vault open.", "success");
  } catch (err) {
    setStatus(`Error: ${err}`, "error");
  }
}

async function handleCreateVault() {
  const password = vaultPasswordEl.value.trim();
  if (!pendingSavePath || !password) {
    setStatus("Choose a vault destination and enter a password.", "error");
    return;
  }

  try {
    setStatus("Creating vault...");
    const vault = await invoke("create_vault", {
      path: pendingSavePath,
      password,
    });
    state.vaultPath = pendingSavePath;
    state.vaultPassword = password;
    state.vault = vault;
    state.selectedFileId = null;
    renderFileList();
    renderDetail();
    showVaultScreen();
    setStatus("Vault created.", "success");
  } catch (err) {
    setStatus(`Error: ${err}`, "error");
  }
}

async function handleAddFile() {
  detailResultEl.textContent = "";
  try {
    const inputPath = await invoke("pick_input_file");
    if (!inputPath) return;
    const outDir = await invoke("pick_output_dir");
    if (!outDir) return;

    setStatus("Encrypting and splitting...");
    const sharePaths = await invoke("split_file", {
      inputPath,
      outDir,
      password: state.vaultPassword,
    });

    const name = getFileName(inputPath);
    const shares = [null, null, null];
    sharePaths.forEach((path) => {
      const info = getShareInfo(path);
      if (info) shares[info.index - 1] = path;
    });

    const entry = addOrUpdateFileEntry({ name, shares });
    await refreshAvailability(entry);
    await saveVault();
    state.selectedFileId = entry.id;
    renderFileList();
    renderDetail();
    setStatus("File added to vault.", "success");
  } catch (err) {
    setStatus(`Error: ${err}`, "error");
  }
}

async function handleImportShares() {
  detailResultEl.textContent = "";
  try {
    const sharePaths = await invoke("pick_share_files");
    if (!sharePaths || sharePaths.length === 0) return;

    const infos = sharePaths.map(getShareInfo).filter(Boolean);
    if (infos.length === 0) {
      setStatus("Selected files are not valid share files.", "error");
      return;
    }

    const baseName = infos[0].baseName;
    if (!infos.every((info) => info.baseName === baseName)) {
      setStatus("Selected shares are from different files.", "error");
      return;
    }

    const shares = [null, null, null];
    sharePaths.forEach((path) => {
      const info = getShareInfo(path);
      if (info) shares[info.index - 1] = path;
    });

    const entry = addOrUpdateFileEntry({ name: baseName, shares });
    await refreshAvailability(entry);
    await saveVault();
    state.selectedFileId = entry.id;
    renderFileList();
    renderDetail();
    setStatus("Shares imported to vault.", "success");
  } catch (err) {
    setStatus(`Error: ${err}`, "error");
  }
}

async function handleRecoverFile() {
  detailResultEl.textContent = "";
  const file = state.vault.files.find((entry) => entry.id === state.selectedFileId);
  if (!file) return;

  const availablePaths = file.shares.filter((path, idx) => path && file.available[idx]);
  if (availablePaths.length < 2) {
    detailResultEl.textContent = "Need at least two available shares to recover.";
    return;
  }

  try {
    const outputPath = await invoke("pick_output_file");
    if (!outputPath) return;

    setStatus("Recovering file...");
    const recovered = await invoke("combine_shares", {
      sharePaths: availablePaths.slice(0, 2),
      outputPath,
      password: state.vaultPassword,
    });
    detailResultEl.textContent = `Recovered file saved to:\n${recovered}`;
    setStatus("File recovered.", "success");
  } catch (err) {
    detailResultEl.textContent = `Error: ${err}`;
    setStatus("Recovery failed.", "error");
  }
}

async function handleRefreshStatus() {
  try {
    setStatus("Refreshing share status...");
    await refreshAllAvailability();
    renderFileList();
    renderDetail();
    setStatus("Status refreshed.", "success");
  } catch (err) {
    setStatus(`Error: ${err}`, "error");
  }
}

document.getElementById("pick-vault").addEventListener("click", async () => {
  const path = await invoke("pick_vault_file");
  if (!path) return;
  pendingOpenPath = path;
  vaultPathEl.textContent = path;
});

document.getElementById("pick-vault-save").addEventListener("click", async () => {
  const path = await invoke("pick_vault_save");
  if (!path) return;
  pendingSavePath = path;
  vaultSavePathEl.textContent = path;
});

document.getElementById("open-vault").addEventListener("click", handleOpenVault);
document.getElementById("create-vault").addEventListener("click", handleCreateVault);

document.getElementById("add-file").addEventListener("click", handleAddFile);
document.getElementById("import-shares").addEventListener("click", handleImportShares);
document.getElementById("refresh-status").addEventListener("click", handleRefreshStatus);
recoverBtn.addEventListener("click", handleRecoverFile);

showLoginScreen();
renderFileList();
renderDetail();
