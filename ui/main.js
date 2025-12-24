const invoke =
  window.__TAURI__?.core?.invoke ||
  window.__TAURI__?.tauri?.invoke;

const state = {
  inputPath: "",
  outDir: "",
  sharePaths: [],
  outputPath: "",
};

const inputPathEl = document.getElementById("input-path");
const outDirEl = document.getElementById("out-dir");
const sharesPathEl = document.getElementById("shares-path");
const outputPathEl = document.getElementById("output-path");
const splitResultEl = document.getElementById("split-result");
const combineResultEl = document.getElementById("combine-result");
const splitPasswordEl = document.getElementById("split-password");
const combinePasswordEl = document.getElementById("combine-password");
const shareLights = [
  document.getElementById("share-1"),
  document.getElementById("share-2"),
  document.getElementById("share-3"),
];
const sharesCountEl = document.getElementById("shares-count");

const shareIndexRegex = /\.share([1-3])$/;

function updateShareLights() {
  const selected = new Set();
  for (const path of state.sharePaths) {
    const match = path.match(shareIndexRegex);
    if (match) {
      selected.add(Number(match[1]));
    }
  }
  shareLights.forEach((el, idx) => {
    if (selected.has(idx + 1)) {
      el.classList.add("active");
    } else {
      el.classList.remove("active");
    }
  });
  sharesCountEl.textContent = `${state.sharePaths.length} of 3 selected`;
}

document.getElementById("pick-input").addEventListener("click", async () => {
  const path = await invoke("pick_input_file");
  if (!path) return;
  state.inputPath = path;
  inputPathEl.textContent = path;
});

document.getElementById("pick-out-dir").addEventListener("click", async () => {
  const path = await invoke("pick_output_dir");
  if (!path) return;
  state.outDir = path;
  outDirEl.textContent = path;
});

document.getElementById("pick-shares").addEventListener("click", async () => {
  const paths = await invoke("pick_share_files");
  if (!paths || paths.length === 0) return;
  state.sharePaths = paths;
  sharesPathEl.textContent = paths.join(", ");
  updateShareLights();
});

document.getElementById("pick-output").addEventListener("click", async () => {
  const path = await invoke("pick_output_file");
  if (!path) return;
  state.outputPath = path;
  outputPathEl.textContent = path;
});

document.getElementById("split-action").addEventListener("click", async () => {
  splitResultEl.textContent = "";
  const password = splitPasswordEl.value.trim();
  if (!state.inputPath || !state.outDir || !password) {
    splitResultEl.textContent = "Please select input, output folder, and password.";
    return;
  }

  splitResultEl.textContent = "Working...";
  try {
    const paths = await invoke("split_file", {
      inputPath: state.inputPath,
      outDir: state.outDir,
      password,
    });
    splitResultEl.textContent = `Shares created:\n${paths.join("\n")}`;
  } catch (err) {
    splitResultEl.textContent = `Error: ${err}`;
  }
});

document.getElementById("combine-action").addEventListener("click", async () => {
  combineResultEl.textContent = "";
  const password = combinePasswordEl.value.trim();
  if (state.sharePaths.length < 2 || !state.outputPath || !password) {
    combineResultEl.textContent = "Please select at least two shares, output file, and password.";
    return;
  }

  combineResultEl.textContent = "Working...";
  try {
    const path = await invoke("combine_shares", {
      sharePaths: state.sharePaths,
      outputPath: state.outputPath,
      password,
    });
    combineResultEl.textContent = `Recovered file saved to:\n${path}`;
  } catch (err) {
    combineResultEl.textContent = `Error: ${err}`;
  }
});

updateShareLights();
