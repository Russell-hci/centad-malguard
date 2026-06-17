const ASSET_ROOT = "./assets";
const SAMPLE_ROOT = `${ASSET_ROOT}/samples`;
const META_ROOT = `${ASSET_ROOT}/metadata`;
const DEFAULT_SAMPLE_ID = "05_allaple_a_pgd";
const DEFAULT_ATTACK = "pgd";

const STAGE_COPY = {
  1: {
    title: "Standard detector scans a malware image.",
    copy:
      "The sample begins as a grayscale malware image from the finalized duplicate-aware test split.",
    next: "Launch attack",
  },
  2: {
    title: "An evasion attack is launched.",
    copy:
      "The attack changes the image just enough to target the detector while preserving the same malware sample.",
    next: "Show detector failure",
  },
  3: {
    title: "The standard detector is fooled.",
    copy:
      "The standard detector now predicts the wrong malware family, showing that clean accuracy is not the same as security.",
    next: "Activate MalGuard",
  },
  4: {
    title: "MalGuard switches to the robust detector.",
    copy:
      "The visual demo uses a curated robust-detector checkpoint, while the final MalGuard-X metrics are shown in the evidence section.",
    next: "Check recovery",
  },
  5: {
    title: "MalGuard checks whether the correct family is recovered.",
    copy:
      "The central product question is whether the robust model restores the correct malware-family prediction after attack.",
    next: "Explain evidence",
  },
  6: {
    title: "Attention stability explains why MalGuard is different.",
    copy:
      "Grad-CAM evidence suggests attacks can change what the detector focuses on, while adversarial training makes attention more stable on the curated examples.",
    next: "Restart demo",
  },
};

const state = {
  samples: [],
  predictions: [],
  attentionMetrics: [],
  evidenceRows: [],
  selectedSampleId: DEFAULT_SAMPLE_ID,
  attack: DEFAULT_ATTACK,
  activeStage: 1,
};

const elements = {
  heroDemoButton: document.getElementById("heroDemoButton"),
  sampleSelect: document.getElementById("sampleSelect"),
  sampleTags: document.getElementById("sampleTags"),
  fgsmButton: document.getElementById("fgsmButton"),
  pgdButton: document.getElementById("pgdButton"),
  presentationButton: document.getElementById("presentationButton"),
  prevStageButton: document.getElementById("prevStageButton"),
  nextStageButton: document.getElementById("nextStageButton"),
  scenarioTitle: document.getElementById("scenarioTitle"),
  scenarioCopy: document.getElementById("scenarioCopy"),
  cleanImage: document.getElementById("cleanImage"),
  trueFamily: document.getElementById("trueFamily"),
  baselineCleanPred: document.getElementById("baselineCleanPred"),
  baselineCleanConfidence: document.getElementById("baselineCleanConfidence"),
  attackImage: document.getElementById("attackImage"),
  perturbationImage: document.getElementById("perturbationImage"),
  attackImageLabel: document.getElementById("attackImageLabel"),
  baselineAttackPred: document.getElementById("baselineAttackPred"),
  attackStatus: document.getElementById("attackStatus"),
  defenseAttackPred: document.getElementById("defenseAttackPred"),
  defenseAttackBar: document.getElementById("defenseAttackBar"),
  defenseStatus: document.getElementById("defenseStatus"),
  comparisonPanel: document.getElementById("comparisonPanel"),
  attentionMetricRows: document.getElementById("attentionMetricRows"),
  attentionFinding: document.getElementById("attentionFinding"),
  evidenceRows: document.getElementById("evidenceRows"),
  stageTabs: Array.from(document.querySelectorAll(".stage-tab")),
  stageCards: Array.from(document.querySelectorAll(".stage-card")),
};

function parseCsv(text) {
  const rows = [];
  let row = [];
  let field = "";
  let inQuotes = false;

  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];
    const next = text[index + 1];

    if (char === '"' && inQuotes && next === '"') {
      field += '"';
      index += 1;
    } else if (char === '"') {
      inQuotes = !inQuotes;
    } else if (char === "," && !inQuotes) {
      row.push(field);
      field = "";
    } else if ((char === "\n" || char === "\r") && !inQuotes) {
      if (field.length || row.length) {
        row.push(field);
        rows.push(row);
        row = [];
        field = "";
      }
      if (char === "\r" && next === "\n") {
        index += 1;
      }
    } else {
      field += char;
    }
  }

  if (field.length || row.length) {
    row.push(field);
    rows.push(row);
  }

  const headers = rows.shift() || [];
  return rows.map((values) => {
    const item = {};
    headers.forEach((header, index) => {
      item[header] = values[index] ?? "";
    });
    return item;
  });
}

async function loadCsv(path) {
  const response = await fetch(path);
  if (!response.ok) {
    throw new Error(`Unable to load ${path}`);
  }
  return parseCsv(await response.text());
}

function asPercent(value) {
  const number = Number(value);
  if (!Number.isFinite(number)) return "-";
  return `${(number * 100).toFixed(2)}%`;
}

function formatNumber(value) {
  const number = Number(value);
  if (!Number.isFinite(number)) return value || "-";
  if (Math.abs(number) >= 10) return number.toFixed(2);
  return number.toFixed(4);
}

function formatMetric(value, metricName) {
  const number = Number(value);
  if (!Number.isFinite(number)) return value || "-";
  const lower = metricName.toLowerCase();
  if (
    lower.includes("accuracy") ||
    lower.includes("macro f1") ||
    lower.includes("asr")
  ) {
    return `${(number * 100).toFixed(2)}%`;
  }
  if (lower.includes("parameters")) return number.toLocaleString();
  if (lower.includes("size")) return `${number.toFixed(3)} MB`;
  if (lower.includes("latency")) return `${number.toFixed(3)} ms`;
  if (lower.includes("throughput")) return `${number.toFixed(1)} samples/s`;
  return formatNumber(value);
}

function currentSample() {
  return state.samples.find((sample) => sample.sample_id === state.selectedSampleId);
}

function predictionFor(sampleId, model, variant) {
  return state.predictions.find(
    (row) =>
      row.sample_id === sampleId &&
      row.model === model &&
      row.image_variant === variant,
  );
}

function metricRowsFor(sampleId, attack) {
  return state.attentionMetrics.filter(
    (row) => row.sample_id === sampleId && row.attack === attack,
  );
}

function imagePath(sampleId, variant) {
  if (variant === "clean") return `${SAMPLE_ROOT}/${sampleId}/images/clean.png`;
  if (variant === "fgsm") return `${SAMPLE_ROOT}/${sampleId}/images/fgsm_eps_0_03.png`;
  return `${SAMPLE_ROOT}/${sampleId}/images/pgd_eps_0_03_steps_20.png`;
}

function perturbationPath(sampleId, attack) {
  return `${SAMPLE_ROOT}/${sampleId}/images/perturbation_${attack}.png`;
}

function comparisonPanelPath(sampleId) {
  return `${SAMPLE_ROOT}/${sampleId}/comparison_panel.png`;
}

function resetToDefault() {
  loadSample(DEFAULT_SAMPLE_ID, DEFAULT_ATTACK, 1);
}

function setAttack(attack) {
  state.attack = attack;
  elements.fgsmButton.classList.toggle("active", attack === "fgsm");
  elements.pgdButton.classList.toggle("active", attack === "pgd");
  elements.fgsmButton.setAttribute("aria-checked", String(attack === "fgsm"));
  elements.pgdButton.setAttribute("aria-checked", String(attack === "pgd"));
  render();
}

function loadSample(sampleId, attack = state.attack, stage = state.activeStage) {
  state.selectedSampleId = sampleId;
  state.attack = attack;
  state.activeStage = stage;
  elements.sampleSelect.value = sampleId;
  elements.fgsmButton.classList.toggle("active", attack === "fgsm");
  elements.pgdButton.classList.toggle("active", attack === "pgd");
  elements.fgsmButton.setAttribute("aria-checked", String(attack === "fgsm"));
  elements.pgdButton.setAttribute("aria-checked", String(attack === "pgd"));
  render();
}

function setStage(stage) {
  state.activeStage = Math.min(6, Math.max(1, stage));
  renderStage();
}

function renderSampleOptions() {
  elements.sampleSelect.innerHTML = "";
  state.samples.forEach((sample) => {
    const option = document.createElement("option");
    option.value = sample.sample_id;
    option.textContent = `${sample.family} | ${sample.primary_category.replaceAll("_", " ")}`;
    elements.sampleSelect.append(option);
  });
}

function renderTags(sample) {
  const tags = sample.category_tags.split(";").filter(Boolean);
  elements.sampleTags.innerHTML = "";
  tags.forEach((tag) => {
    const node = document.createElement("span");
    node.textContent = tag.replaceAll("_", " ");
    elements.sampleTags.append(node);
  });
}

function renderEvidenceTable() {
  const priority = [
    "Clean Accuracy",
    "Clean Macro F1",
    "FGSM Accuracy (0.03)",
    "FGSM Macro F1 (0.03)",
    "FGSM ASR (0.03)",
    "PGD-20 Accuracy",
    "PGD-20 Macro F1",
    "PGD-50 Accuracy",
    "PGD-50 Macro F1",
    "PGD-20 ASR",
    "Parameters",
    "Model Size MB",
    "Latency ms",
    "Throughput samples/s",
  ];
  const rows = priority
    .map((metric) => state.evidenceRows.find((row) => row.metric === metric))
    .filter(Boolean);
  elements.evidenceRows.innerHTML = rows
    .map(
      (row) => `
        <tr>
          <td>${row.metric}</td>
          <td>${formatMetric(row.baseline_mobilenet_v3, row.metric)}</td>
          <td>${formatMetric(row.adversarially_trained_mobilenet_v3, row.metric)}</td>
          <td>${formatMetric(row.absolute_change, row.metric)}</td>
        </tr>
      `,
    )
    .join("");
}

function renderAttention(sample) {
  const rows = metricRowsFor(sample.sample_id, state.attack);
  elements.attentionMetricRows.innerHTML = rows
    .map(
      (row) => `
        <tr>
          <td>${row.model === "defense" ? "MalGuard" : "Standard"}</td>
          <td>${formatNumber(row.top20_iou)}</td>
          <td>${formatNumber(row.center_of_mass_shift)}</td>
        </tr>
      `,
    )
    .join("");

  const baseline = rows.find((row) => row.model === "baseline");
  const defense = rows.find((row) => row.model === "defense");
  if (baseline && defense) {
    const iouDelta = Number(defense.top20_iou) - Number(baseline.top20_iou);
    const shiftDelta =
      Number(baseline.center_of_mass_shift) - Number(defense.center_of_mass_shift);
    elements.attentionFinding.textContent =
      iouDelta > 0 && shiftDelta > 0
        ? "For this sample, MalGuard shows higher heatmap overlap and lower attention shift."
        : "This sample shows mixed attention behavior; use it as supporting evidence, not proof by itself.";
  }
}

function renderStage() {
  const active = state.activeStage;
  const copy = STAGE_COPY[active];
  elements.scenarioTitle.textContent = copy.title;
  elements.scenarioCopy.textContent = copy.copy;
  elements.prevStageButton.disabled = active === 1;
  elements.nextStageButton.textContent = copy.next;

  elements.stageTabs.forEach((tab) => {
    const stage = Number(tab.dataset.stage);
    tab.classList.toggle("active", stage === active);
    tab.classList.toggle("completed", stage < active);
    tab.setAttribute("aria-selected", String(stage === active));
    if (stage === active) {
      tab.setAttribute("aria-current", "step");
    } else {
      tab.removeAttribute("aria-current");
    }
  });

  elements.stageCards.forEach((card) => {
    const stage = Number(card.dataset.stageCard);
    card.classList.toggle("active", stage === active);
    card.classList.toggle("completed", stage < active);
  });
}

function renderVerdict(attackSuccess, defenseRecovers, family) {
  if (attackSuccess && defenseRecovers) {
    elements.defenseStatus.className = "verdict-line verdict-ok";
    elements.defenseStatus.textContent =
      `Recovered: MalGuard returns the prediction to ${family} after the attack.`;
    return;
  }
  if (attackSuccess && !defenseRecovers) {
    elements.defenseStatus.className = "verdict-line verdict-bad";
    elements.defenseStatus.textContent =
      "Defense limitation: the attack fools the standard detector and MalGuard does not recover this case.";
    return;
  }
  elements.defenseStatus.className = "verdict-line";
  elements.defenseStatus.textContent =
    "Detector resisted: this selected attack does not flip the standard detector on this sample.";
}

function render() {
  const sample = currentSample();
  if (!sample) return;

  const attack = state.attack;
  const baselineClean = predictionFor(sample.sample_id, "baseline", "clean");
  const baselineAttack = predictionFor(sample.sample_id, "baseline", attack);
  const defenseAttack = predictionFor(sample.sample_id, "defense", attack);
  const attackSuccess = sample[`${attack}_attack_success`] === "True";
  const defenseRecovers = sample[`${attack}_defense_recovers`] === "True";

  renderTags(sample);

  elements.cleanImage.src = imagePath(sample.sample_id, "clean");
  elements.trueFamily.textContent = sample.family;
  elements.baselineCleanPred.textContent =
    baselineClean?.prediction || sample.baseline_clean_pred;
  elements.baselineCleanConfidence.textContent = asPercent(
    baselineClean?.confidence || sample.baseline_clean_confidence,
  );

  elements.attackImage.src = imagePath(sample.sample_id, attack);
  elements.perturbationImage.src = perturbationPath(sample.sample_id, attack);
  elements.attackImageLabel.textContent =
    attack === "fgsm" ? "FGSM attacked image" : "PGD attacked image";

  elements.baselineAttackPred.textContent =
    baselineAttack?.prediction || sample[`baseline_${attack}_pred`];
  elements.attackStatus.className = `status-line ${attackSuccess ? "status-bad" : "status-ok"}`;
  elements.attackStatus.textContent = attackSuccess
    ? `Detector fooled: the standard detector changes to the wrong family with ${asPercent(
        baselineAttack?.confidence || sample[`baseline_${attack}_confidence`],
      )} confidence.`
    : `Detector resisted: this attack does not change the standard detector prediction. Confidence ${asPercent(
        baselineAttack?.confidence || sample[`baseline_${attack}_confidence`],
      )}.`;

  elements.defenseAttackPred.textContent =
    defenseAttack?.prediction || sample[`defense_${attack}_pred`];
  elements.defenseAttackBar.style.width = asPercent(
    defenseAttack?.confidence || sample[`defense_${attack}_confidence`],
  );
  renderVerdict(attackSuccess, defenseRecovers, sample.family);

  elements.comparisonPanel.src = comparisonPanelPath(sample.sample_id);
  renderAttention(sample);
  renderEvidenceTable();
  renderStage();
}

async function init() {
  const [samples, predictions, attentionMetrics, evidenceRows] = await Promise.all([
    loadCsv(`${META_ROOT}/selected_samples.csv`),
    loadCsv(`${META_ROOT}/predictions.csv`),
    loadCsv(`${META_ROOT}/attention_stability_metrics.csv`),
    loadCsv(`${META_ROOT}/adversarial_training_comparison.csv`),
  ]);

  state.samples = samples;
  state.predictions = predictions;
  state.attentionMetrics = attentionMetrics;
  state.evidenceRows = evidenceRows;

  renderSampleOptions();
  loadSample(DEFAULT_SAMPLE_ID, DEFAULT_ATTACK, 1);
}

elements.heroDemoButton.addEventListener("click", () => {
  resetToDefault();
  document.querySelector("#guidedDemo").scrollIntoView({ behavior: "smooth", block: "start" });
});

elements.presentationButton.addEventListener("click", () => {
  resetToDefault();
  document.querySelector("#guidedDemo").scrollIntoView({ behavior: "smooth", block: "start" });
});

elements.prevStageButton.addEventListener("click", () => setStage(state.activeStage - 1));
elements.nextStageButton.addEventListener("click", () => {
  if (state.activeStage === 6) {
    setStage(1);
  } else {
    setStage(state.activeStage + 1);
  }
});

elements.stageTabs.forEach((tab) => {
  tab.addEventListener("click", () => setStage(Number(tab.dataset.stage)));
});

elements.sampleSelect.addEventListener("change", (event) => {
  loadSample(event.target.value, state.attack, 1);
});

elements.fgsmButton.addEventListener("click", () => setAttack("fgsm"));
elements.pgdButton.addEventListener("click", () => setAttack("pgd"));

document.querySelectorAll(".sequence-list button").forEach((button) => {
  button.addEventListener("click", () => {
    loadSample(button.dataset.sample, button.dataset.attack || DEFAULT_ATTACK, 1);
  });
});

init().catch((error) => {
  document.body.innerHTML = `<main class="load-error">
    <h1>MalGuard-X failed to load</h1>
    <p>${error.message}</p>
    <p>Run the app from the repository root with <code>python3 -m http.server 8765</code>.</p>
  </main>`;
});
