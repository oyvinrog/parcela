const invoke =
  window.__TAURI__?.core?.invoke ||
  window.__TAURI__?.tauri?.invoke;

const state = {
  vaultPath: "",
  vaultPassword: "",
  vault: { version: 1, files: [], virtual_drives: [] },
  selectedFileId: null,
  selectedFileIds: new Set(),
  selectedType: "file", // "file" or "drive"
  unlockedDrives: new Map(), // drive_id -> { mount_path }
  isMemoryMode: false, // true on Windows where virtual drives are memory-only
  // File browser state
  fileBrowser: {
    currentPath: "",
    selectedEntry: null, // { name, isDir }
    entries: [],
  },
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
const selectAllEl = document.getElementById("select-all-files");
const recoverSelectedBtn = document.getElementById("recover-selected");

const fileListEl = document.getElementById("file-list");
const detailEmptyEl = document.getElementById("detail-empty");
const detailPanelEl = document.getElementById("detail-panel");
const detailTitleEl = document.getElementById("detail-title");
const detailLightsEl = document.getElementById("detail-lights");
const detailCountEl = document.getElementById("detail-count");
const shareListEl = document.getElementById("share-list");
const detailResultEl = document.getElementById("detail-result");
const recoverBtn = document.getElementById("recover-file");
const fileActionsEl = document.getElementById("file-actions");
const driveActionsEl = document.getElementById("drive-actions");
const driveStatusEl = document.getElementById("drive-status");
const driveMountPathEl = document.getElementById("drive-mount-path");
const unlockDriveBtn = document.getElementById("unlock-drive");
const lockDriveBtn = document.getElementById("lock-drive");
const openDriveBtn = document.getElementById("open-drive");

// File browser elements
const fileBrowserEl = document.getElementById("file-browser");
const fbBreadcrumbEl = document.getElementById("fb-breadcrumb");
const fbListEl = document.getElementById("fb-list");
const fbSelectionEl = document.getElementById("fb-selection");
const fbSelectedNameEl = document.getElementById("fb-selected-name");
const fbUploadBtn = document.getElementById("fb-upload");
const fbNewFolderBtn = document.getElementById("fb-new-folder");
const fbDownloadBtn = document.getElementById("fb-download");
const fbDeleteBtn = document.getElementById("fb-delete");

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

function getDirName(path) {
  const parts = path.split(/[/\\]/);
  if (parts.length <= 1) return "";
  parts.pop();
  return parts.join(path.includes("\\") ? "\\" : "/");
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

function getMissingCount(file) {
  ensureAvailability(file);
  return file.available.filter((available) => !available).length;
}

function getAvailabilityClass(file) {
  const missingCount = getMissingCount(file);
  if (missingCount === 0) return "ok";
  if (missingCount === 1) return "warn";
  return "fail";
}

function joinPath(dir, name) {
  if (!dir) return name;
  if (dir.endsWith("/") || dir.endsWith("\\")) return `${dir}${name}`;
  if (dir.includes("\\")) return `${dir}\\${name}`;
  return `${dir}/${name}`;
}

function setResultText(message) {
  detailResultEl.textContent = message;
}

function showRecoveredResult(paths, errors) {
  detailResultEl.innerHTML = "";

  if (paths.length > 0) {
    const header = document.createElement("div");
    header.textContent =
      paths.length === 1 ? "Recovered file saved to:" : "Recovered files saved to:";
    detailResultEl.appendChild(header);

    for (const path of paths) {
      const row = document.createElement("div");
      row.className = "result-row";

      const pathEl = document.createElement("span");
      pathEl.className = "result-path";
      pathEl.textContent = path;

      const openBtn = document.createElement("button");
      openBtn.type = "button";
      openBtn.textContent = "Browse";
      openBtn.addEventListener("click", async () => {
        const dir = getDirName(path) || path;
        try {
          await invoke("open_path", { path: dir });
        } catch (err) {
          setStatus(`Error: ${err}`, "error");
        }
      });

      row.appendChild(pathEl);
      row.appendChild(openBtn);
      detailResultEl.appendChild(row);
    }
  }

  if (errors.length > 0) {
    const errorHeader = document.createElement("div");
    errorHeader.className = "result-errors";
    errorHeader.textContent = "Errors:";
    detailResultEl.appendChild(errorHeader);

    const errorList = document.createElement("div");
    errorList.textContent = errors.join("\n");
    detailResultEl.appendChild(errorList);
  }
}

function updateSelectionUI() {
  const total = state.vault.files.length;
  const selectedCount = state.selectedFileIds.size;
  const allSelected = total > 0 && selectedCount === total;

  selectAllEl.checked = allSelected;
  selectAllEl.indeterminate = selectedCount > 0 && selectedCount < total;
  selectAllEl.disabled = total === 0;
  recoverSelectedBtn.disabled = selectedCount === 0;
  recoverSelectedBtn.textContent = allSelected ? "Recover all" : "Recover selected";
}

function setSelectedFiles(ids) {
  state.selectedFileIds = new Set(ids);
  updateSelectionUI();
}

function toggleSelectedFile(fileId, isSelected) {
  if (isSelected) {
    state.selectedFileIds.add(fileId);
  } else {
    state.selectedFileIds.delete(fileId);
  }
  updateSelectionUI();
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
  for (const drive of state.vault.virtual_drives || []) {
    await refreshAvailability(drive);
  }
}

async function refreshUnlockedDrives() {
  try {
    const unlocked = await invoke("get_unlocked_drives");
    state.unlockedDrives.clear();
    for (const info of unlocked) {
      state.unlockedDrives.set(info.drive_id, {
        mount_path: info.mount_path,
        name: info.name,
      });
    }
  } catch (err) {
    console.error("Failed to refresh unlocked drives:", err);
  }
}

function isDriveUnlocked(driveId) {
  return state.unlockedDrives.has(driveId);
}

function getDriveMountPath(driveId) {
  const info = state.unlockedDrives.get(driveId);
  return info ? info.mount_path : null;
}

function renderFileList() {
  fileListEl.innerHTML = "";

  const allFiles = state.vault.files || [];
  const allDrives = state.vault.virtual_drives || [];

  if (allFiles.length === 0 && allDrives.length === 0) {
    const empty = document.createElement("div");
    empty.className = "path";
    empty.textContent = "No files in this vault yet.";
    fileListEl.appendChild(empty);
    return;
  }

  // Render virtual drives first
  for (const drive of allDrives) {
    ensureAvailability(drive);
    const item = document.createElement("button");
    item.className = "file-item drive-item";
    if (drive.id === state.selectedFileId && state.selectedType === "drive") {
      item.classList.add("active");
    }
    if (isDriveUnlocked(drive.id)) {
      item.classList.add("unlocked");
    }
    item.type = "button";

    const info = document.createElement("div");
    info.className = "file-info";

    const icon = document.createElement("span");
    icon.className = "drive-icon";
    icon.textContent = isDriveUnlocked(drive.id) ? "🔓" : "💾";

    const title = document.createElement("div");
    title.className = "file-title";
    title.textContent = drive.name;

    const sizeTag = document.createElement("span");
    sizeTag.className = "size-tag";
    sizeTag.textContent = `${drive.size_mb}MB`;

    info.appendChild(icon);
    info.appendChild(title);
    info.appendChild(sizeTag);

    const meta = document.createElement("div");
    meta.className = "file-meta";

    const lights = document.createElement("div");
    lights.className = "lights-inline";

    const statusClass = getAvailabilityClass(drive);
    drive.available.forEach(() => {
      const dot = document.createElement("span");
      dot.className = "light";
      dot.classList.add(statusClass);
      lights.appendChild(dot);
    });

    const count = document.createElement("span");
    const availableCount = drive.available.filter(Boolean).length;
    count.textContent = `${availableCount}/3`;

    meta.appendChild(lights);
    meta.appendChild(count);

    item.appendChild(info);
    item.appendChild(meta);

    item.addEventListener("click", () => {
      // Reset file browser when switching drives
      if (state.selectedFileId !== drive.id) {
        state.fileBrowser.currentPath = "";
        state.fileBrowser.selectedEntry = null;
      }
      state.selectedFileId = drive.id;
      state.selectedType = "drive";
      renderDetail();
      renderFileList();
    });

    fileListEl.appendChild(item);
  }

  // Render regular files
  for (const file of allFiles) {
    ensureAvailability(file);
    const item = document.createElement("button");
    item.className = "file-item";
    if (file.id === state.selectedFileId && state.selectedType === "file") {
      item.classList.add("active");
    }
    item.type = "button";

    const info = document.createElement("div");
    info.className = "file-info";

    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.className = "file-select";
    checkbox.checked = state.selectedFileIds.has(file.id);
    checkbox.addEventListener("click", (event) => event.stopPropagation());
    checkbox.addEventListener("change", () => {
      toggleSelectedFile(file.id, checkbox.checked);
    });

    const title = document.createElement("div");
    title.className = "file-title";
    title.textContent = file.name;

    info.appendChild(checkbox);
    info.appendChild(title);

    const meta = document.createElement("div");
    meta.className = "file-meta";

    const lights = document.createElement("div");
    lights.className = "lights-inline";

    const statusClass = getAvailabilityClass(file);
    file.available.forEach(() => {
      const dot = document.createElement("span");
      dot.className = "light";
      dot.classList.add(statusClass);
      lights.appendChild(dot);
    });

    const count = document.createElement("span");
    const availableCount = file.available.filter(Boolean).length;
    count.textContent = `${availableCount}/3`;

    meta.appendChild(lights);
    meta.appendChild(count);

    item.appendChild(info);
    item.appendChild(meta);

    item.addEventListener("click", () => {
      state.selectedFileId = file.id;
      state.selectedType = "file";
      renderDetail();
      renderFileList();
    });

    fileListEl.appendChild(item);
  }

  updateSelectionUI();
}

function renderDetail() {
  // Check if we're showing a virtual drive or a file
  let entry = null;
  let isDrive = false;

  if (state.selectedType === "drive") {
    entry = (state.vault.virtual_drives || []).find((d) => d.id === state.selectedFileId);
    isDrive = true;
  } else {
    entry = (state.vault.files || []).find((f) => f.id === state.selectedFileId);
    isDrive = false;
  }

  if (!entry) {
    detailEmptyEl.classList.remove("hidden");
    detailPanelEl.classList.add("hidden");
    return;
  }

  ensureAvailability(entry);
  detailEmptyEl.classList.add("hidden");
  detailPanelEl.classList.remove("hidden");
  
  if (isDrive) {
    detailTitleEl.textContent = `${entry.name} (Virtual Drive)`;
  } else {
    detailTitleEl.textContent = entry.name;
  }

  const availableCount = entry.available.filter(Boolean).length;
  detailCountEl.textContent = `${availableCount} of 3 available`;

  const statusClass = getAvailabilityClass(entry);
  detailLightsEl.querySelectorAll(".light").forEach((el) => {
    el.classList.remove("ok", "warn", "fail");
    el.classList.add(statusClass);
  });

  shareListEl.innerHTML = "";
  for (let i = 0; i < 3; i += 1) {
    const card = document.createElement("div");
    card.className = "share-card";

    const label = document.createElement("div");
    label.className = "label";
    label.innerHTML = `<span>Share ${i + 1}</span>`;

    const status = document.createElement("span");
    status.textContent = entry.available[i] ? "Available" : "Missing";
    status.style.color = entry.available[i] ? "#1d6b44" : "#8b6f5a";
    label.appendChild(status);

    const actions = document.createElement("div");
    actions.className = "share-actions";

    const changeBtn = document.createElement("button");
    changeBtn.type = "button";
    changeBtn.textContent = "Change";
    changeBtn.addEventListener("click", () => handleChangeShare(i, isDrive));
    actions.appendChild(changeBtn);

    const browseBtn = document.createElement("button");
    browseBtn.type = "button";
    browseBtn.textContent = "Browse";
    browseBtn.disabled = !entry.shares[i] || !entry.available[i];
    browseBtn.addEventListener("click", async () => {
      const sharePath = entry.shares[i];
      if (!sharePath) return;
      const dir = getDirName(sharePath) || sharePath;
      try {
        await invoke("open_path", { path: dir });
      } catch (err) {
        setStatus(`Error: ${err}`, "error");
      }
    });
    actions.appendChild(browseBtn);

    const path = document.createElement("div");
    path.className = "path";
    path.textContent = entry.shares[i] || "No location stored";

    card.appendChild(label);
    card.appendChild(actions);
    card.appendChild(path);
    shareListEl.appendChild(card);
  }

  // Show/hide appropriate action buttons
  if (isDrive) {
    fileActionsEl.classList.add("hidden");
    driveActionsEl.classList.remove("hidden");

    const isUnlocked = isDriveUnlocked(entry.id);
    unlockDriveBtn.disabled = isUnlocked || availableCount < 2;
    lockDriveBtn.disabled = !isUnlocked;
    openDriveBtn.disabled = !isUnlocked;

    if (isUnlocked) {
      driveStatusEl.classList.remove("hidden");
      driveMountPathEl.textContent = getDriveMountPath(entry.id) || "Unknown";
      // Show file browser for unlocked drives
      loadFileBrowser(entry.id, state.fileBrowser.currentPath || "");
    } else {
      driveStatusEl.classList.add("hidden");
      hideFileBrowser();
    }
  } else {
    fileActionsEl.classList.remove("hidden");
    driveActionsEl.classList.add("hidden");
    driveStatusEl.classList.add("hidden");
    hideFileBrowser();
    recoverBtn.disabled = availableCount < 2;
  }
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
    // Ensure virtual_drives array exists
    if (!state.vault.virtual_drives) {
      state.vault.virtual_drives = [];
    }
    await refreshAllAvailability();
    await refreshUnlockedDrives();
    
    // Select first item (drive or file)
    const drives = state.vault.virtual_drives || [];
    const files = state.vault.files || [];
    if (drives.length > 0) {
      state.selectedFileId = drives[0].id;
      state.selectedType = "drive";
    } else if (files.length > 0) {
      state.selectedFileId = files[0].id;
      state.selectedType = "file";
    } else {
      state.selectedFileId = null;
      state.selectedType = "file";
    }
    setSelectedFiles(state.selectedFileId && state.selectedType === "file" ? [state.selectedFileId] : []);
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
    setSelectedFiles([]);
    renderFileList();
    renderDetail();
    showVaultScreen();
    setStatus("Vault created.", "success");
  } catch (err) {
    setStatus(`Error: ${err}`, "error");
  }
}

async function handleAddFile() {
  setResultText("");
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
    setSelectedFiles([entry.id]);
    renderFileList();
    renderDetail();
    setStatus("File added to vault.", "success");
  } catch (err) {
    setStatus(`Error: ${err}`, "error");
  }
}

async function handleImportShares() {
  setResultText("");
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
  setResultText("");
  const file = state.vault.files.find((entry) => entry.id === state.selectedFileId);
  if (!file) return;

  const availablePaths = file.shares.filter((path, idx) => path && file.available[idx]);
  if (availablePaths.length < 2) {
    setResultText("Need at least two available shares to recover.");
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
    showRecoveredResult([recovered], []);
    setStatus("File recovered.", "success");
  } catch (err) {
    setResultText(`Error: ${err}`);
    setStatus("Recovery failed.", "error");
  }
}

async function handleChangeShare(index, isDrive = false) {
  setResultText("");
  let entry;
  if (isDrive) {
    entry = (state.vault.virtual_drives || []).find((d) => d.id === state.selectedFileId);
  } else {
    entry = state.vault.files.find((f) => f.id === state.selectedFileId);
  }
  if (!entry) return;

  const sharePath = await invoke("pick_input_file");
  if (!sharePath) return;

  entry.shares[index] = sharePath;
  await refreshAvailability(entry);
  await saveVault();
  renderFileList();
  renderDetail();
  setStatus("Share location updated.", "success");
}

async function handleCreateVirtualDrive() {
  setResultText("");
  try {
    const name = prompt("Enter a name for the virtual drive:", "My Secure Drive");
    if (!name || name.trim() === "") return;

    const sizeStr = prompt("Enter size in MB (default: 64):", "64");
    if (sizeStr === null) return;
    const sizeMb = parseInt(sizeStr, 10) || 64;

    const outDir = await invoke("pick_output_dir");
    if (!outDir) return;

    setStatus("Creating virtual drive...");
    const driveInfo = await invoke("create_virtual_drive", {
      name: name.trim(),
      sizeMb,
      outDir,
      password: state.vaultPassword,
    });

    // Add to vault
    if (!state.vault.virtual_drives) {
      state.vault.virtual_drives = [];
    }
    state.vault.virtual_drives.push(driveInfo);
    await saveVault();

    // Refresh and select the new drive
    await refreshAvailability(driveInfo);
    state.selectedFileId = driveInfo.id;
    state.selectedType = "drive";
    renderFileList();
    renderDetail();
    setStatus("Virtual drive created.", "success");
  } catch (err) {
    setStatus(`Error: ${err}`, "error");
  }
}

async function handleUnlockDrive() {
  setResultText("");
  const drive = (state.vault.virtual_drives || []).find(
    (d) => d.id === state.selectedFileId
  );
  if (!drive) return;

  ensureAvailability(drive);
  const availablePaths = drive.shares.filter((path, idx) => path && drive.available[idx]);
  if (availablePaths.length < 2) {
    setResultText("Need at least two available shares to unlock.");
    return;
  }

  try {
    setStatus("Unlocking drive...");
    const unlockInfo = await invoke("unlock_virtual_drive", {
      sharePaths: availablePaths.slice(0, 2),
      password: state.vaultPassword,
    });

    state.unlockedDrives.set(unlockInfo.drive_id, {
      mount_path: unlockInfo.mount_path,
      name: unlockInfo.name,
    });

    renderFileList();
    renderDetail();
    setResultText(`Drive unlocked at: ${unlockInfo.mount_path}`);
    setStatus("Drive unlocked.", "success");
  } catch (err) {
    setResultText(`Error: ${err}`);
    setStatus("Unlock failed.", "error");
  }
}

async function handleLockDrive() {
  setResultText("");
  const drive = (state.vault.virtual_drives || []).find(
    (d) => d.id === state.selectedFileId
  );
  if (!drive) return;

  try {
    setStatus("Locking drive...");
    await invoke("lock_virtual_drive", {
      driveId: drive.id,
      sharePaths: drive.shares,
      password: state.vaultPassword,
    });

    state.unlockedDrives.delete(drive.id);
    renderFileList();
    renderDetail();
    setResultText("Drive locked and content saved.");
    setStatus("Drive locked.", "success");
  } catch (err) {
    setResultText(`Error: ${err}`);
    setStatus("Lock failed.", "error");
  }
}

async function handleOpenDrive() {
  const drive = (state.vault.virtual_drives || []).find(
    (d) => d.id === state.selectedFileId
  );
  if (!drive) return;

  const mountPath = getDriveMountPath(drive.id);
  if (!mountPath) {
    setStatus("Drive is not unlocked.", "error");
    return;
  }

  try {
    await invoke("open_path", { path: mountPath });
  } catch (err) {
    setStatus(`Error: ${err}`, "error");
  }
}

// =============================================================================
// File Browser Functions (for virtual drives)
// =============================================================================

function getSelectedDriveId() {
  if (state.selectedType !== "drive") return null;
  return state.selectedFileId;
}

function showFileBrowser() {
  fileBrowserEl.classList.remove("hidden");
}

function hideFileBrowser() {
  fileBrowserEl.classList.add("hidden");
  state.fileBrowser.currentPath = "";
  state.fileBrowser.selectedEntry = null;
  state.fileBrowser.entries = [];
}

async function loadFileBrowser(driveId, path = "") {
  state.fileBrowser.currentPath = path;
  state.fileBrowser.selectedEntry = null;
  
  try {
    const entries = await invoke("vdrive_list_files", { driveId, path });
    state.fileBrowser.entries = entries;
    renderFileBrowser();
  } catch (err) {
    console.error("Failed to load file browser:", err);
    state.fileBrowser.entries = [];
    renderFileBrowser();
  }
}

function renderFileBrowser() {
  const driveId = getSelectedDriveId();
  if (!driveId || !isDriveUnlocked(driveId)) {
    hideFileBrowser();
    return;
  }

  showFileBrowser();
  renderBreadcrumb();
  renderFileList_FB();
  renderSelection();
}

function renderBreadcrumb() {
  fbBreadcrumbEl.innerHTML = "";
  
  const parts = state.fileBrowser.currentPath
    ? state.fileBrowser.currentPath.split("/").filter(Boolean)
    : [];
  
  // Root button
  const rootBtn = document.createElement("button");
  rootBtn.className = "breadcrumb-item" + (parts.length === 0 ? " active" : "");
  rootBtn.textContent = "🏠 Root";
  rootBtn.dataset.path = "";
  rootBtn.addEventListener("click", () => navigateTo(""));
  fbBreadcrumbEl.appendChild(rootBtn);
  
  // Path segments
  let accumulated = "";
  for (let i = 0; i < parts.length; i++) {
    const sep = document.createElement("span");
    sep.className = "breadcrumb-sep";
    sep.textContent = "›";
    fbBreadcrumbEl.appendChild(sep);
    
    accumulated += (accumulated ? "/" : "") + parts[i];
    const btn = document.createElement("button");
    btn.className = "breadcrumb-item" + (i === parts.length - 1 ? " active" : "");
    btn.textContent = parts[i];
    btn.dataset.path = accumulated;
    const pathCopy = accumulated;
    btn.addEventListener("click", () => navigateTo(pathCopy));
    fbBreadcrumbEl.appendChild(btn);
  }
}

function renderFileList_FB() {
  fbListEl.innerHTML = "";
  
  const entries = state.fileBrowser.entries || [];
  
  if (entries.length === 0) {
    const empty = document.createElement("div");
    empty.className = "fb-empty";
    empty.textContent = "This folder is empty. Import files to get started.";
    fbListEl.appendChild(empty);
    return;
  }
  
  // Sort: folders first, then files, alphabetically
  const sorted = [...entries].sort((a, b) => {
    if (a.is_dir !== b.is_dir) return a.is_dir ? -1 : 1;
    return a.name.localeCompare(b.name);
  });
  
  for (const entry of sorted) {
    const el = document.createElement("div");
    el.className = "fb-entry" + (entry.is_dir ? " folder" : "");
    
    if (
      state.fileBrowser.selectedEntry &&
      state.fileBrowser.selectedEntry.name === entry.name
    ) {
      el.classList.add("selected");
    }
    
    const icon = document.createElement("span");
    icon.className = "fb-entry-icon";
    icon.textContent = entry.is_dir ? "📁" : getFileIcon(entry.name);
    
    const name = document.createElement("span");
    name.className = "fb-entry-name";
    name.textContent = entry.name;
    
    el.appendChild(icon);
    el.appendChild(name);
    
    el.addEventListener("click", () => handleEntryClick(entry));
    el.addEventListener("dblclick", () => handleEntryDoubleClick(entry));
    
    fbListEl.appendChild(el);
  }
}

function getFileIcon(filename) {
  const ext = filename.split(".").pop()?.toLowerCase() || "";
  const iconMap = {
    txt: "📄",
    md: "📝",
    pdf: "📕",
    doc: "📘",
    docx: "📘",
    xls: "📗",
    xlsx: "📗",
    png: "🖼️",
    jpg: "🖼️",
    jpeg: "🖼️",
    gif: "🖼️",
    svg: "🖼️",
    mp3: "🎵",
    wav: "🎵",
    mp4: "🎬",
    mov: "🎬",
    zip: "📦",
    rar: "📦",
    "7z": "📦",
    json: "📋",
    xml: "📋",
    html: "🌐",
    css: "🎨",
    js: "⚡",
    ts: "⚡",
    py: "🐍",
    rs: "🦀",
    key: "🔑",
    pem: "🔐",
  };
  return iconMap[ext] || "📄";
}

function renderSelection() {
  const sel = state.fileBrowser.selectedEntry;
  if (!sel || sel.is_dir) {
    fbSelectionEl.classList.add("hidden");
    return;
  }
  
  fbSelectionEl.classList.remove("hidden");
  fbSelectedNameEl.textContent = sel.name;
}

function handleEntryClick(entry) {
  state.fileBrowser.selectedEntry = entry;
  renderFileList_FB();
  renderSelection();
}

function handleEntryDoubleClick(entry) {
  if (entry.is_dir) {
    navigateTo(joinPath(state.fileBrowser.currentPath, entry.name));
  }
}

function navigateTo(path) {
  const driveId = getSelectedDriveId();
  if (!driveId) return;
  loadFileBrowser(driveId, path);
}

async function handleFBUpload() {
  const driveId = getSelectedDriveId();
  if (!driveId) return;
  
  try {
    setStatus("Importing file...");
    const importedPath = await invoke("vdrive_import_file", {
      driveId,
      destPath: state.fileBrowser.currentPath,
    });
    await loadFileBrowser(driveId, state.fileBrowser.currentPath);
    setStatus(`Imported: ${importedPath}`, "success");
  } catch (err) {
    if (err !== "No file selected") {
      setStatus(`Error: ${err}`, "error");
    }
  }
}

async function handleFBNewFolder() {
  const driveId = getSelectedDriveId();
  if (!driveId) return;
  
  const name = prompt("Enter folder name:");
  if (!name || name.trim() === "") return;
  
  const folderPath = joinPath(state.fileBrowser.currentPath, name.trim());
  
  try {
    setStatus("Creating folder...");
    await invoke("vdrive_create_dir", { driveId, path: folderPath });
    await loadFileBrowser(driveId, state.fileBrowser.currentPath);
    setStatus(`Created folder: ${name}`, "success");
  } catch (err) {
    setStatus(`Error: ${err}`, "error");
  }
}

async function handleFBDownload() {
  const driveId = getSelectedDriveId();
  const sel = state.fileBrowser.selectedEntry;
  if (!driveId || !sel || sel.is_dir) return;
  
  const filePath = joinPath(state.fileBrowser.currentPath, sel.name);
  
  try {
    setStatus("Exporting file...");
    const savedPath = await invoke("vdrive_export_file", { driveId, path: filePath });
    setStatus(`Exported to: ${savedPath}`, "success");
  } catch (err) {
    if (err !== "No save location selected") {
      setStatus(`Error: ${err}`, "error");
    }
  }
}

async function handleFBDelete() {
  const driveId = getSelectedDriveId();
  const sel = state.fileBrowser.selectedEntry;
  if (!driveId || !sel) return;
  
  const filePath = joinPath(state.fileBrowser.currentPath, sel.name);
  const typeLabel = sel.is_dir ? "folder" : "file";
  
  if (!confirm(`Delete ${typeLabel} "${sel.name}"?`)) return;
  
  try {
    setStatus(`Deleting ${typeLabel}...`);
    await invoke("vdrive_delete_file", { driveId, path: filePath });
    state.fileBrowser.selectedEntry = null;
    await loadFileBrowser(driveId, state.fileBrowser.currentPath);
    setStatus(`Deleted: ${sel.name}`, "success");
  } catch (err) {
    setStatus(`Error: ${err}`, "error");
  }
}

async function handleRecoverSelected() {
  setResultText("");
  const selectedFiles = state.vault.files.filter((entry) =>
    state.selectedFileIds.has(entry.id)
  );
  if (selectedFiles.length === 0) return;

  const outputDir = await invoke("pick_output_dir");
  if (!outputDir) return;

  setStatus("Recovering selected files...");
  const recoveredPaths = [];
  const errors = [];

  for (const file of selectedFiles) {
    ensureAvailability(file);
    const availablePaths = file.shares.filter((path, idx) => path && file.available[idx]);
    if (availablePaths.length < 2) {
      errors.push(`${file.name}: need at least two available shares`);
      continue;
    }

    const outputPath = joinPath(outputDir, file.name);
    try {
      await invoke("combine_shares", {
        sharePaths: availablePaths.slice(0, 2),
        outputPath,
        password: state.vaultPassword,
      });
      recoveredPaths.push(outputPath);
    } catch (err) {
      errors.push(`${file.name}: ${err}`);
    }
  }

  showRecoveredResult(recoveredPaths, errors);

  if (recoveredPaths.length > 0) {
    setStatus(`Recovered ${recoveredPaths.length} file(s).`, "success");
  } else {
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
document.getElementById("add-virtual-drive").addEventListener("click", handleCreateVirtualDrive);
document.getElementById("refresh-status").addEventListener("click", handleRefreshStatus);
selectAllEl.addEventListener("change", () => {
  if (selectAllEl.checked) {
    setSelectedFiles(state.vault.files.map((file) => file.id));
  } else {
    setSelectedFiles([]);
  }
  renderFileList();
});
recoverSelectedBtn.addEventListener("click", handleRecoverSelected);
recoverBtn.addEventListener("click", handleRecoverFile);
unlockDriveBtn.addEventListener("click", handleUnlockDrive);
lockDriveBtn.addEventListener("click", handleLockDrive);
openDriveBtn.addEventListener("click", handleOpenDrive);

// File browser event listeners
fbUploadBtn.addEventListener("click", handleFBUpload);
fbNewFolderBtn.addEventListener("click", handleFBNewFolder);
fbDownloadBtn.addEventListener("click", handleFBDownload);
fbDeleteBtn.addEventListener("click", handleFBDelete);

// Check if we're on a platform that uses memory-only mode (Windows)
// and hide the "Open in Browser" button if so
(async function initPlatformSettings() {
  try {
    state.isMemoryMode = await invoke("uses_memory_mode");
    if (state.isMemoryMode) {
      // On Windows, virtual drives are memory-only; there's no directory to open
      openDriveBtn.style.display = "none";
    }
  } catch (err) {
    console.warn("Failed to check memory mode:", err);
  }
})();

showLoginScreen();
renderFileList();
renderDetail();
