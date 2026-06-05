(function () {
  const DEFAULT_FILES = [
    "../../results/pool-cache-element-cache.csv",
    "../../results/pool-cache-perf-all.csv",
    "../../results/pool-cache-perf-0w.csv",
    "../../results/pool-cache-perf-2w.csv",
    "../../results/pool-cache-perf-8w.csv",
  ];
  const RESULTS_DIR = "../../results/";
  const KNOWN_SPLIT_FILES = new Set([
    "pool-cache-perf-0w.csv",
    "pool-cache-perf-2w.csv",
    "pool-cache-perf-8w.csv",
  ]);

  const MODE_ORDER = ["local", "refill", "contended", "growth"];
  const MODE_COLORS = {
    local: "#1f7a8c",
    refill: "#3266b1",
    contended: "#b7791f",
    growth: "#b44343",
    unknown: "#697386",
  };
  const PARAMETER_FIELDS = [
    { field: "rounds", label: "Rounds", short: "r" },
    { field: "batch_size", label: "Batch", short: "b" },
    { field: "cache_batch_size", label: "Cache batch", short: "cb" },
    { field: "warmup_rounds", label: "Warmup", short: "wup" },
    { field: "samples", label: "Samples/run", short: "n" },
    { field: "log2_subpool_size", label: "log2 subpool", short: "s2" },
  ];

  const state = {
    datasets: [],
    metric: "cycles_per_op",
    groupBy: "mode",
    scale: "log",
    aggregateParams: new Set(),
    parameterValues: new Map(),
    parameterKnownValues: new Map(),
    modes: new Set(MODE_ORDER),
    workers: new Set(),
  };

  const el = {
    summary: document.getElementById("dataset-summary"),
    fileCount: document.getElementById("file-count"),
    datasetList: document.getElementById("dataset-list"),
    modeFilters: document.getElementById("mode-filters"),
    workerFilters: document.getElementById("worker-filters"),
    aggregateCount: document.getElementById("aggregate-count"),
    parameterGrouping: document.getElementById("parameter-grouping"),
    parameterValueCount: document.getElementById("parameter-value-count"),
    parameterValueFilters: document.getElementById("parameter-value-filters"),
    parameterSplit: document.getElementById("parameter-split"),
    parameterList: document.getElementById("parameter-list"),
    chartTitle: document.getElementById("chart-title"),
    chartSubtitle: document.getElementById("chart-subtitle"),
    chartHost: document.getElementById("chart-host"),
    legend: document.getElementById("legend"),
    tableSummary: document.getElementById("table-summary"),
    summaryBody: document.getElementById("summary-body"),
    tooltip: document.getElementById("tooltip"),
    fileInput: document.getElementById("file-input"),
    resetButton: document.getElementById("reset-button"),
    downloadButton: document.getElementById("download-button"),
    dropZone: document.getElementById("drop-zone"),
  };

  document.querySelectorAll("[data-metric]").forEach((button) => {
    button.addEventListener("click", () => {
      state.metric = button.dataset.metric;
      setActive("[data-metric]", button);
      render();
    });
  });

  document.querySelectorAll("[data-group]").forEach((button) => {
    button.addEventListener("click", () => {
      state.groupBy = button.dataset.group;
      setActive("[data-group]", button);
      render();
    });
  });

  document.querySelectorAll("[data-scale]").forEach((button) => {
    button.addEventListener("click", () => {
      state.scale = button.dataset.scale;
      setActive("[data-scale]", button);
      render();
    });
  });

  el.fileInput.addEventListener("change", (event) => {
    loadFiles(Array.from(event.target.files));
    el.fileInput.value = "";
  });

  el.resetButton.addEventListener("click", () => loadDefaultFiles());
  el.downloadButton.addEventListener("click", () => downloadSummary());

  ["dragenter", "dragover"].forEach((eventName) => {
    el.dropZone.addEventListener(eventName, (event) => {
      event.preventDefault();
      el.dropZone.classList.add("is-dragging");
    });
  });

  ["dragleave", "drop"].forEach((eventName) => {
    el.dropZone.addEventListener(eventName, (event) => {
      event.preventDefault();
      el.dropZone.classList.remove("is-dragging");
    });
  });

  el.dropZone.addEventListener("drop", (event) => {
    const files = Array.from(event.dataTransfer.files).filter((file) => file.name.endsWith(".csv"));
    loadFiles(files);
  });

  loadDefaultFiles();

  async function loadDefaultFiles() {
    state.datasets = [];
    el.summary.textContent = "Scanning results directory...";
    const loaded = [];
    const discovered = await discoverCsvFiles();
    const hasAggregate = discovered.some((path) => basename(path) === "pool-cache-perf-all.csv");

    for (const path of discovered) {
      try {
        const response = await fetch(path, { cache: "no-store" });
        if (!response.ok) continue;
        const text = await response.text();
        const name = basename(path);
        loaded.push(datasetFromCsv(text, name, path, defaultActiveForFile(name, hasAggregate)));
      } catch (error) {
        // The upload/drop path still works when the page is opened from file://.
      }
    }

    state.datasets = loaded.filter(Boolean);
    refreshFilters();
    render();
  }

  async function discoverCsvFiles() {
    try {
      const response = await fetch(RESULTS_DIR, { cache: "no-store" });
      if (!response.ok) return DEFAULT_FILES;
      const html = await response.text();
      const document = new DOMParser().parseFromString(html, "text/html");
      const paths = Array.from(document.querySelectorAll("a[href]"))
        .map((link) => new URL(link.getAttribute("href"), new URL(RESULTS_DIR, window.location.href)).href)
        .filter((href) => href.toLowerCase().endsWith(".csv"))
        .map((href) => relativeToCurrentPage(href))
        .filter(Boolean);
      return unique(paths).sort(filePathSort);
    } catch (error) {
      return DEFAULT_FILES;
    }
  }

  function defaultActiveForFile(name, hasAggregate) {
    if (name === "pool-cache-perf-all.csv") return true;
    if (hasAggregate && KNOWN_SPLIT_FILES.has(name)) return false;
    return true;
  }

  async function loadFiles(files) {
    if (!files.length) return;
    const loaded = await Promise.all(
      files.map(async (file) => datasetFromCsv(await file.text(), file.name, "upload", true)),
    );
    state.datasets = [...state.datasets, ...loaded.filter(Boolean)];
    refreshFilters();
    render();
  }

  function datasetFromCsv(text, name, source, active) {
    const rows = parseCsv(text);
    if (!rows.length) return null;
    const normalized = rows
      .map((row) => ({
        source,
        dataset: name,
        run_id: row.run_id,
        pid: row.pid,
        mode: row.mode || "unknown",
        workers: numberOrNull(row.workers),
        rounds: numberOrNull(row.rounds),
        batch_size: numberOrNull(row.batch_size),
        cache_batch_size: numberOrNull(row.cache_batch_size),
        warmup_rounds: numberOrNull(row.warmup_rounds),
        samples: numberOrNull(row.samples),
        log2_subpool_size: numberOrNull(row.log2_subpool_size),
        sample: numberOrNull(row.sample),
        cpu_hz: numberOrNull(row.cpu_hz),
        total_ticks: numberOrNull(row.total_ticks),
        max_ticks: numberOrNull(row.max_ticks),
        total_ops: numberOrNull(row.total_ops),
        cycles_per_op: numberOrNull(row.cycles_per_op),
        mops: numberOrNull(row.mops),
      }))
      .filter((row) => row.mode && Number.isFinite(row.workers) && Number.isFinite(row.cycles_per_op));

    return normalized.length
      ? {
          id: `${name}-${Date.now()}-${Math.random().toString(16).slice(2)}`,
          name,
          source,
          active,
          rows: normalized,
        }
      : null;
  }

  function parseCsv(text) {
    const lines = text.trim().split(/\r?\n/).filter(Boolean);
    if (lines.length < 2) return [];
    const headers = splitCsvLine(lines[0]);
    return lines.slice(1).map((line) => {
      const values = splitCsvLine(line);
      return Object.fromEntries(headers.map((header, index) => [header, values[index] ?? ""]));
    });
  }

  function splitCsvLine(line) {
    const values = [];
    let value = "";
    let quoted = false;
    for (let index = 0; index < line.length; index += 1) {
      const char = line[index];
      if (char === '"' && line[index + 1] === '"') {
        value += '"';
        index += 1;
      } else if (char === '"') {
        quoted = !quoted;
      } else if (char === "," && !quoted) {
        values.push(value);
        value = "";
      } else {
        value += char;
      }
    }
    values.push(value);
    return values;
  }

  function refreshFilters() {
    const allRows = state.datasets.flatMap((dataset) => dataset.rows);
    const modes = unique(allRows.map((row) => row.mode)).sort(modeSort);
    const workers = unique(allRows.map((row) => row.workers)).sort(numberSort);

    if (!state.modes.size) modes.forEach((mode) => state.modes.add(mode));
    workers.forEach((worker) => state.workers.add(String(worker)));
    PARAMETER_FIELDS.forEach(({ field }) => {
      const values = parameterValuesForField(allRows, field);
      if (!state.parameterValues.has(field)) state.parameterValues.set(field, new Set());
      if (!state.parameterKnownValues.has(field)) state.parameterKnownValues.set(field, new Set());
      const selected = state.parameterValues.get(field);
      const known = state.parameterKnownValues.get(field);
      values.forEach((value) => {
        const key = String(value);
        if (!known.has(key)) selected.add(key);
        known.add(key);
      });
    });

    renderModeFilters(modes);
    renderWorkerFilters(workers);
  }

  function render() {
    renderDatasets();
    renderParameterGrouping();
    renderParameterValueFilters();
    const rows = selectedRows();
    const groups = buildGroups(rows);
    const stats = groups.map((group) => ({
      ...group,
      ...statsFor(group.values),
    }));

    renderSummaryText(rows, stats);
    renderParameters(rows);
    renderLegend();
    renderChart(stats);
    renderTable(stats);
  }

  function selectedRows() {
    return state.datasets
      .filter((dataset) => dataset.active)
      .flatMap((dataset) =>
        dataset.rows
          .filter((row) => state.modes.has(row.mode))
          .filter((row) => state.workers.has(String(row.workers)))
          .filter((row) => parameterValueSelected(row))
          .filter((row) => Number.isFinite(row[state.metric]))
          .map((row) => ({ ...row, dataset: dataset.name, dataset_id: dataset.id })),
      );
  }

  function buildGroups(rows) {
    const groups = new Map();
    const parameterFields = groupingParameterFields(rows);
    rows.forEach((row) => {
      const params = parameterObject(row);
      const key = [row.dataset_id, row.mode, row.workers, ...parameterFields.map(({ field }) => params[field])].join("||");
      if (!groups.has(key)) {
        groups.set(key, {
          key,
          dataset: row.dataset,
          dataset_id: row.dataset_id,
          mode: row.mode,
          workers: row.workers,
          params,
          parameterFields,
          values: [],
          rows: [],
        });
      }
      const group = groups.get(key);
      group.values.push(row[state.metric]);
      group.rows.push(row);
    });

    return Array.from(groups.values()).sort((a, b) => {
      const primary =
        state.groupBy === "mode"
          ? modeSort(a.mode, b.mode) || numberSort(a.workers, b.workers)
          : numberSort(a.workers, b.workers) || modeSort(a.mode, b.mode);
      return primary || compareParams(a.params, b.params) || a.dataset.localeCompare(b.dataset);
    });
  }

  function renderDatasets() {
    el.fileCount.textContent = `${state.datasets.length} file${state.datasets.length === 1 ? "" : "s"}`;
    el.datasetList.replaceChildren(
      ...state.datasets.map((dataset) => {
        const label = document.createElement("label");
        label.className = "dataset-item";
        const input = document.createElement("input");
        input.type = "checkbox";
        input.checked = dataset.active;
        input.addEventListener("change", () => {
          dataset.active = input.checked;
          render();
        });
        const text = document.createElement("span");
        text.textContent = dataset.name;
        const meta = document.createElement("span");
        meta.className = "dataset-meta";
        meta.textContent = `${dataset.rows.length} samples`;
        text.appendChild(meta);
        label.append(input, text);
        return label;
      }),
    );
  }

  function renderModeFilters(modes) {
    el.modeFilters.replaceChildren(
      ...modes.map((mode) => filterItem(mode, state.modes.has(mode), (checked) => {
        checked ? state.modes.add(mode) : state.modes.delete(mode);
        render();
      })),
    );
  }

  function renderWorkerFilters(workers) {
    el.workerFilters.replaceChildren(
      ...workers.map((worker) =>
        filterItem(`${worker}w`, state.workers.has(String(worker)), (checked) => {
          checked ? state.workers.add(String(worker)) : state.workers.delete(String(worker));
          render();
        }),
      ),
    );
  }

  function renderParameterValueFilters() {
    const allRows = state.datasets.flatMap((dataset) => dataset.rows);
    const groups = PARAMETER_FIELDS.map((parameter) => ({
      ...parameter,
      values: parameterValuesForField(allRows, parameter.field),
    })).filter((parameter) => parameter.values.length > 1);

    el.parameterValueCount.textContent = `${groups.length} filter${groups.length === 1 ? "" : "s"}`;
    if (!groups.length) {
      el.parameterValueFilters.innerHTML = '<p class="parameter-note">No parameter has multiple values in the loaded data.</p>';
      return;
    }

    el.parameterValueFilters.replaceChildren(
      ...groups.map((parameter) => {
        const group = document.createElement("div");
        group.className = "parameter-value-group";
        const heading = document.createElement("div");
        heading.className = "parameter-value-heading";
        const title = document.createElement("h3");
        title.textContent = parameter.label;
        const count = document.createElement("span");
        const selected = state.parameterValues.get(parameter.field) || new Set();
        count.textContent = `${parameter.values.filter((value) => selected.has(String(value))).length}/${parameter.values.length}`;
        heading.append(title, count);

        const list = document.createElement("div");
        list.className = "check-list compact";
        list.replaceChildren(
          ...parameter.values.map((value) =>
            filterItem(formatValue(value), selected.has(String(value)), (checked) => {
              checked ? selected.add(String(value)) : selected.delete(String(value));
              state.parameterValues.set(parameter.field, selected);
              render();
            }),
          ),
        );
        group.append(heading, list);
        return group;
      }),
    );
  }

  function renderParameterGrouping() {
    const selected = selectedParameterFields();
    el.aggregateCount.textContent = `${selected.length} param${selected.length === 1 ? "" : "s"}`;
    el.parameterGrouping.replaceChildren(
      ...PARAMETER_FIELDS.map(({ field, label }) =>
        filterItem(label, state.aggregateParams.has(field), (checked) => {
          checked ? state.aggregateParams.add(field) : state.aggregateParams.delete(field);
          render();
        }),
      ),
    );
  }

  function filterItem(labelText, checked, onChange) {
    const label = document.createElement("label");
    label.className = "check-item";
    const input = document.createElement("input");
    input.type = "checkbox";
    input.checked = checked;
    input.addEventListener("change", () => onChange(input.checked));
    const text = document.createElement("span");
    text.textContent = labelText;
    label.append(input, text);
    return label;
  }

  function renderSummaryText(rows, stats) {
    const activeFiles = state.datasets.filter((dataset) => dataset.active).length;
    const sampleText = `${formatCount(rows.length)} samples`;
    const groupText = `${formatCount(stats.length)} comparison groups`;
    el.summary.textContent = activeFiles
      ? `${sampleText} across ${groupText} from ${activeFiles} active file${activeFiles === 1 ? "" : "s"}`
      : "No active datasets.";
    el.chartTitle.textContent = `${metricLabel()} by ${state.groupBy === "mode" ? "mode and workers" : "workers and mode"}`;
    el.chartSubtitle.textContent =
      state.scale === "log"
        ? `Log10 y-axis; ${aggregationSentence(rows)}.`
        : `${aggregationSentence(rows)}; center line is median.`;
    el.tableSummary.textContent = stats.length ? `${stats.length} grouped distributions` : "No rows selected.";
  }

  function renderParameters(rows) {
    const params = [
      ...PARAMETER_FIELDS.map(({ field, label }) => [field, label]),
      ["cpu_hz", "CPU Hz"],
    ];
    const variedFields = varyingParameterFields(rows);
    const selectedFields = selectedParameterFields().filter(({ field }) =>
      variedFields.some((item) => item.field === field),
    );
    const splitFields = groupingParameterFields(rows);

    el.parameterSplit.textContent = selectedFields.length
      ? `Aggregating across ${selectedFields.map((item) => item.label.toLowerCase()).join(", ")}${splitFields.length ? `; splitting by ${splitFields.map((item) => item.label.toLowerCase()).join(", ")}` : ""}.`
      : splitFields.length
        ? `Splitting by ${splitFields.map((item) => item.label.toLowerCase()).join(", ")}. Select a field above to aggregate across it.`
      : "All selected rows share the same benchmark parameter tuple.";

    el.parameterList.replaceChildren(
      ...params.map(([field, label]) => {
        const item = document.createElement("div");
        const dt = document.createElement("dt");
        const dd = document.createElement("dd");
        const values = unique(rows.map((row) => row[field]).filter(Number.isFinite)).sort(numberSort);
        dt.textContent = label;
        dd.textContent = values.length ? compactValues(values) : "-";
        item.append(dt, dd);
        return item;
      }),
    );
  }

  function renderLegend() {
    const activeModes = MODE_ORDER.filter((mode) => state.modes.has(mode));
    el.legend.replaceChildren(
      ...activeModes.map((mode) => {
        const item = document.createElement("span");
        item.className = "legend-item";
        const swatch = document.createElement("span");
        swatch.className = "legend-swatch";
        swatch.style.background = colorForMode(mode);
        const text = document.createElement("span");
        text.textContent = mode;
        item.append(swatch, text);
        return item;
      }),
    );
  }

  function renderChart(stats) {
    if (!stats.length) {
      el.chartHost.innerHTML = '<div class="chart-empty">Select at least one dataset, mode, and worker count.</div>';
      return;
    }

    const width = Math.max(920, stats.length * 54 + 160);
    const height = 494;
    const margin = { top: 22, right: 24, bottom: 86, left: 76 };
    const plotWidth = width - margin.left - margin.right;
    const plotHeight = height - margin.top - margin.bottom;
    const min = Math.min(...stats.map((item) => item.min));
    const max = Math.max(...stats.map((item) => item.max));
    const scale = makeScale(min, max);
    const y = (value) => margin.top + plotHeight - scale.position(value) * plotHeight;
    const step = plotWidth / stats.length;
    const boxWidth = Math.min(34, Math.max(16, step * 0.42));
    const ticks = scale.ticks;
    const svg = svgEl("svg", {
      class: "boxplot-svg",
      style: `min-width: ${width}px`,
      viewBox: `0 0 ${width} ${height}`,
      role: "img",
      "aria-label": `${metricLabel()} boxplot`,
    });

    ticks.forEach((tick) => {
      svg.append(
        svgEl("line", {
          class: "grid-line",
          x1: margin.left,
          x2: width - margin.right,
          y1: y(tick),
          y2: y(tick),
        }),
        svgText(formatValue(tick), margin.left - 10, y(tick) + 4, "tick-label", "end"),
      );
    });

    svg.append(
      svgEl("line", {
        class: "axis-line",
        x1: margin.left,
        x2: margin.left,
        y1: margin.top,
        y2: margin.top + plotHeight,
      }),
      svgEl("line", {
        class: "axis-line",
        x1: margin.left,
        x2: width - margin.right,
        y1: margin.top + plotHeight,
        y2: margin.top + plotHeight,
      }),
      svgText(metricLabel(), 18, margin.top + plotHeight / 2, "axis-label", "middle", {
        transform: `rotate(-90 18 ${margin.top + plotHeight / 2})`,
      }),
    );

    stats.forEach((item, index) => {
      const cx = margin.left + step * index + step / 2;
      const color = colorForMode(item.mode);
      const boxTop = y(item.q3);
      const boxBottom = y(item.q1);
      const minY = y(item.min);
      const maxY = y(item.max);
      const medianY = y(item.median);
      const label = chartLabel(item);
      const params = parameterLabel(item.params, item.parameterFields);
      const details = `${item.dataset}<br>${params ? `${params}<br>` : ""}${metricLabel()}: median ${formatValue(item.median)}, p25 ${formatValue(item.q1)}, p75 ${formatValue(item.q3)}<br>min ${formatValue(item.min)}, max ${formatValue(item.max)}, n=${item.count}`;

      const group = svgEl("g", { tabindex: "0", "aria-label": `${label} median ${formatValue(item.median)}` });
      const whiskerAttrs = { class: "box-line", stroke: color };
      group.append(
        svgEl("line", { ...whiskerAttrs, x1: cx, x2: cx, y1: minY, y2: maxY }),
        svgEl("line", { ...whiskerAttrs, x1: cx - boxWidth / 3, x2: cx + boxWidth / 3, y1: minY, y2: minY }),
        svgEl("line", { ...whiskerAttrs, x1: cx - boxWidth / 3, x2: cx + boxWidth / 3, y1: maxY, y2: maxY }),
        svgEl("rect", {
          x: cx - boxWidth / 2,
          y: boxTop,
          width: boxWidth,
          height: Math.max(1, boxBottom - boxTop),
          fill: hexToRgba(color, 0.18),
          stroke: color,
          class: "box-line",
          rx: 2,
        }),
        svgEl("line", {
          class: "median-line",
          x1: cx - boxWidth / 2,
          x2: cx + boxWidth / 2,
          y1: medianY,
          y2: medianY,
        }),
      );

      item.values.slice(0, 34).forEach((value, sampleIndex) => {
        const jitter = ((sampleIndex * 17) % 21) - 10;
        group.append(
          svgEl("circle", {
            class: "sample-dot",
            cx: cx + jitter * 0.55,
            cy: y(value),
            r: 2,
            fill: color,
          }),
        );
      });

      group.addEventListener("mousemove", (event) => showTooltip(event, label, details));
      group.addEventListener("mouseleave", hideTooltip);
      group.addEventListener("focus", (event) => showTooltip(event, label, details));
      group.addEventListener("blur", hideTooltip);

      svg.append(group);
      svg.append(svgText(label, cx, margin.top + plotHeight + 22, "tick-label", "middle", {
        transform: `rotate(-42 ${cx} ${margin.top + plotHeight + 22})`,
      }));
    });

    addMajorGroupLabels(svg, stats, margin, plotWidth, step, height);
    el.chartHost.replaceChildren(svg);
  }

  function addMajorGroupLabels(svg, stats, margin, plotWidth, step, height) {
    let start = 0;
    const primaryValue = (item) => (state.groupBy === "mode" ? item.mode : `${item.workers}w`);
    for (let index = 1; index <= stats.length; index += 1) {
      if (index < stats.length && primaryValue(stats[index]) === primaryValue(stats[start])) continue;
      const x1 = margin.left + step * start;
      const x2 = margin.left + step * index;
      const cx = (x1 + x2) / 2;
      svg.append(
        svgEl("line", {
          class: "axis-line",
          x1,
          x2,
          y1: height - 26,
          y2: height - 26,
        }),
        svgText(primaryValue(stats[start]), cx, height - 10, "group-label", "middle"),
      );
      start = index;
    }
  }

  function renderTable(stats) {
    el.summaryBody.replaceChildren(
      ...stats.map((item) => {
        const row = document.createElement("tr");
        row.innerHTML = `
          <td>${escapeHtml(item.dataset)}</td>
          <td><span class="mode-pill" style="color:${colorForMode(item.mode)}">${escapeHtml(item.mode)}</span></td>
          <td>${item.workers}</td>
          <td>${escapeHtml(parameterLabel(item.params, item.parameterFields) || "-")}</td>
          <td>${item.count}</td>
          <td>${formatValue(item.min)}</td>
          <td>${formatValue(item.q1)}</td>
          <td>${formatValue(item.median)}</td>
          <td>${formatValue(item.q3)}</td>
          <td>${formatValue(item.max)}</td>
          <td>${formatValue(item.mean)}</td>
        `;
        return row;
      }),
    );
  }

  function statsFor(values) {
    const sorted = [...values].sort(numberSort);
    const sum = sorted.reduce((acc, value) => acc + value, 0);
    return {
      values: sorted,
      count: sorted.length,
      min: sorted[0],
      q1: quantile(sorted, 0.25),
      median: quantile(sorted, 0.5),
      q3: quantile(sorted, 0.75),
      max: sorted[sorted.length - 1],
      mean: sum / sorted.length,
    };
  }

  function quantile(sorted, q) {
    if (!sorted.length) return 0;
    const position = (sorted.length - 1) * q;
    const base = Math.floor(position);
    const rest = position - base;
    return sorted[base + 1] === undefined ? sorted[base] : sorted[base] + rest * (sorted[base + 1] - sorted[base]);
  }

  function downloadSummary() {
    const selected = selectedRows();
    const rows = buildGroups(selected).map((group) => ({ ...group, ...statsFor(group.values) }));
    const groupingFields = groupingParameterFields(selected);
    const headers = [
      "dataset",
      "mode",
      "workers",
      ...groupingFields.map(({ field }) => field),
      "samples",
      "min",
      "p25",
      "median",
      "p75",
      "max",
      "mean",
    ];
    const csv = [
      headers.join(","),
      ...rows.map((row) =>
        [
          row.dataset,
          row.mode,
          row.workers,
          ...groupingFields.map(({ field }) => row.params[field]),
          row.count,
          row.min,
          row.q1,
          row.median,
          row.q3,
          row.max,
          row.mean,
        ]
          .map(csvEscape)
          .join(","),
      ),
    ].join("\n");

    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `pool-cache-summary-${state.metric}.csv`;
    link.click();
    URL.revokeObjectURL(url);
  }

  function showTooltip(event, title, html) {
    el.tooltip.innerHTML = `<strong>${escapeHtml(title)}</strong>${html}`;
    el.tooltip.hidden = false;
    const x = "clientX" in event ? event.clientX : window.innerWidth / 2;
    const y = "clientY" in event ? event.clientY : window.innerHeight / 2;
    el.tooltip.style.left = `${Math.min(x + 14, window.innerWidth - 300)}px`;
    el.tooltip.style.top = `${Math.min(y + 14, window.innerHeight - 140)}px`;
  }

  function hideTooltip() {
    el.tooltip.hidden = true;
  }

  function parameterObject(row) {
    return Object.fromEntries(PARAMETER_FIELDS.map(({ field }) => [field, row[field]]));
  }

  function parameterValueSelected(row) {
    return PARAMETER_FIELDS.every(({ field }) => {
      const selected = state.parameterValues.get(field);
      return !selected || selected.has(String(row[field]));
    });
  }

  function parameterValuesForField(rows, field) {
    return unique(rows.map((row) => row[field]).filter(Number.isFinite)).sort(numberSort);
  }

  function varyingParameterFields(rows) {
    return PARAMETER_FIELDS.filter(({ field }) => {
      const values = parameterValuesForField(rows, field);
      return values.length > 1;
    });
  }

  function selectedParameterFields() {
    return PARAMETER_FIELDS.filter(({ field }) => state.aggregateParams.has(field));
  }

  function groupingParameterFields(rows) {
    return varyingParameterFields(rows).filter(({ field }) => !state.aggregateParams.has(field));
  }

  function aggregationSentence(rows) {
    const split = groupingParameterFields(rows);
    const selected = selectedParameterFields().filter(({ field }) =>
      varyingParameterFields(rows).some((item) => item.field === field),
    );
    if (selected.length && split.length)
      return `aggregating across ${selected.map((item) => item.label.toLowerCase()).join(", ")}; splitting by ${split.map((item) => item.label.toLowerCase()).join(", ")}`;
    if (selected.length) return `aggregating across ${selected.map((item) => item.label.toLowerCase()).join(", ")}`;
    if (split.length) return `splitting by ${split.map((item) => item.label.toLowerCase()).join(", ")}`;
    return "parameter values are shared";
  }

  function parameterLabel(params, fields = PARAMETER_FIELDS) {
    return fields
      .filter(({ field }) => Number.isFinite(params[field]))
      .map(({ field, short }) => `${short}=${formatValue(params[field])}`)
      .join(", ");
  }

  function chartLabel(item) {
    const params = parameterLabel(item.params, item.parameterFields);
    return params ? `${item.mode} / ${item.workers}w / ${params}` : `${item.mode} / ${item.workers}w`;
  }

  function compareParams(a, b) {
    for (const { field } of PARAMETER_FIELDS) {
      if (state.aggregateParams.has(field)) continue;
      const diff = numberSort(a[field], b[field]);
      if (diff) return diff;
    }
    return 0;
  }

  function metricLabel() {
    return state.metric === "mops" ? "Mops" : "Cycles/op";
  }

  function setActive(selector, activeButton) {
    document.querySelectorAll(selector).forEach((button) => button.classList.toggle("is-active", button === activeButton));
  }

  function niceTicks(min, max, count) {
    const span = max - min || 1;
    const step = niceNumber(span / Math.max(1, count - 1));
    const start = Math.ceil(min / step) * step;
    const ticks = [];
    for (let value = start; value <= max + step * 0.5; value += step) ticks.push(value);
    return ticks;
  }

  function makeScale(min, max) {
    if (state.scale === "log" && min > 0 && max > 0) {
      const minPow = Math.floor(Math.log10(min));
      const maxPow = Math.ceil(Math.log10(max));
      const domainMin = 10 ** minPow;
      const domainMax = 10 ** maxPow;
      const logMin = Math.log10(domainMin);
      const logMax = Math.log10(domainMax);
      const ticks = [];
      for (let power = minPow; power <= maxPow; power += 1) {
        [1, 2, 5].forEach((multiple) => {
          const tick = multiple * 10 ** power;
          if (tick >= domainMin && tick <= domainMax) ticks.push(tick);
        });
      }
      return {
        ticks,
        position: (value) => (Math.log10(Math.max(value, domainMin)) - logMin) / (logMax - logMin || 1),
      };
    }

    const padding = (max - min || max || 1) * 0.08;
    const yMin = Math.max(0, min - padding);
    const yMax = max + padding;
    return {
      ticks: niceTicks(yMin, yMax, 6),
      position: (value) => (value - yMin) / (yMax - yMin || 1),
    };
  }

  function niceNumber(value) {
    const exponent = Math.floor(Math.log10(value));
    const fraction = value / 10 ** exponent;
    const nice = fraction <= 1 ? 1 : fraction <= 2 ? 2 : fraction <= 5 ? 5 : 10;
    return nice * 10 ** exponent;
  }

  function compactValues(values) {
    if (!values.length) return "-";
    if (values.length <= 3) return values.map(formatValue).join(", ");
    return `${formatValue(values[0])}...${formatValue(values[values.length - 1])}`;
  }

  function formatValue(value) {
    if (!Number.isFinite(value)) return "-";
    if (Math.abs(value) >= 1000000) return value.toExponential(2);
    if (Math.abs(value) >= 1000) return trimNumber(value.toFixed(0));
    if (Math.abs(value) >= 100) return trimNumber(value.toFixed(1));
    return trimNumber(value.toFixed(3));
  }

  function formatCount(value) {
    return String(value);
  }

  function trimNumber(value) {
    return value.includes(".") ? value.replace(/0+$/, "").replace(/\.$/, "") : value;
  }

  function colorForMode(mode) {
    return MODE_COLORS[mode] || MODE_COLORS.unknown;
  }

  function hexToRgba(hex, alpha) {
    const value = hex.replace("#", "");
    const int = parseInt(value, 16);
    const r = (int >> 16) & 255;
    const g = (int >> 8) & 255;
    const b = int & 255;
    return `rgba(${r}, ${g}, ${b}, ${alpha})`;
  }

  function svgEl(tag, attrs = {}) {
    const node = document.createElementNS("http://www.w3.org/2000/svg", tag);
    Object.entries(attrs).forEach(([key, value]) => node.setAttribute(key, value));
    return node;
  }

  function svgText(text, x, y, className, anchor = "start", attrs = {}) {
    const node = svgEl("text", { x, y, class: className, "text-anchor": anchor, ...attrs });
    node.textContent = text;
    return node;
  }

  function numberOrNull(value) {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : null;
  }

  function unique(values) {
    return Array.from(new Set(values));
  }

  function numberSort(a, b) {
    return Number(a) - Number(b);
  }

  function modeSort(a, b) {
    const ia = MODE_ORDER.indexOf(a);
    const ib = MODE_ORDER.indexOf(b);
    return (ia === -1 ? 99 : ia) - (ib === -1 ? 99 : ib) || String(a).localeCompare(String(b));
  }

  function basename(path) {
    return decodeURIComponent(path.split("/").pop());
  }

  function filePathSort(a, b) {
    const nameA = basename(a);
    const nameB = basename(b);
    if (nameA === "pool-cache-perf-all.csv") return -1;
    if (nameB === "pool-cache-perf-all.csv") return 1;
    return nameA.localeCompare(nameB, undefined, { numeric: true });
  }

  function relativeToCurrentPage(href) {
    const target = new URL(href);
    if (target.origin !== window.location.origin) return null;
    const base = new URL("./", window.location.href);
    return target.pathname.startsWith("/results/")
      ? `${relativePath(base.pathname, target.pathname)}${target.search}`
      : null;
  }

  function relativePath(fromDir, toPath) {
    const from = fromDir.split("/").filter(Boolean);
    const to = toPath.split("/").filter(Boolean);
    while (from.length && to.length && from[0] === to[0]) {
      from.shift();
      to.shift();
    }
    return `${"../".repeat(from.length)}${to.map(encodeURIComponent).join("/")}`;
  }

  function csvEscape(value) {
    const text = String(value ?? "");
    return /[",\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
  }

  function escapeHtml(value) {
    return String(value)
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#039;");
  }
})();
