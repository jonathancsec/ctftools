function formatBytes(bytes) {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function initUpload() {
    const form = document.getElementById("upload-form");
    if (!form) return;

    const input = document.getElementById("file-input");
    const dropzone = document.getElementById("dropzone");
    const summary = document.getElementById("file-summary");
    const button = document.getElementById("analyze-button");
    const errorBox = document.getElementById("upload-error");
    const maxBytes = Number(form.dataset.maxBytes) || 0;

    function showError(message) {
        errorBox.hidden = !message;
        errorBox.textContent = message || "";
    }

    function describe(file) {
        if (!file) {
            summary.textContent = "No file selected.";
            button.disabled = true;
            return;
        }

        const extension = file.name.includes(".")
            ? file.name.split(".").pop().toLowerCase()
            : "(none)";
        summary.textContent = `${file.name} - ${formatBytes(file.size)} - .${extension}`;

        if (file.size === 0) {
            showError("That file is empty.");
            button.disabled = true;
            return;
        }
        if (maxBytes && file.size > maxBytes) {
            showError(`That file is larger than the ${formatBytes(maxBytes)} limit.`);
            button.disabled = true;
            return;
        }

        showError("");
        button.disabled = false;
    }

    input.addEventListener("change", () => describe(input.files[0]));

    for (const type of ["dragenter", "dragover"]) {
        dropzone.addEventListener(type, (event) => {
            event.preventDefault();
            dropzone.classList.add("is-over");
        });
    }

    dropzone.addEventListener("dragleave", () => dropzone.classList.remove("is-over"));

    dropzone.addEventListener("drop", (event) => {
        event.preventDefault();
        dropzone.classList.remove("is-over");
        const file = event.dataTransfer?.files?.[0];
        if (!file) return;

        try {
            const transfer = new DataTransfer();
            transfer.items.add(file);
            input.files = transfer.files;
        } catch {
            showError("This browser cannot attach dropped files. Use the file picker instead.");
            return;
        }
        describe(file);
    });

    form.addEventListener("submit", (event) => {
        if (!input.files.length) {
            event.preventDefault();
            showError("Choose a file to analyze.");
            return;
        }
        button.disabled = true;
        button.textContent = "Uploading...";
    });
}

function initJobPolling() {
    const panel = document.getElementById("job-progress");
    if (!panel) return;

    const statusUrl = panel.dataset.statusUrl;
    const statusEl = document.getElementById("job-status");
    const errorEl = document.getElementById("job-error");
    const metaEl = document.getElementById("job-progress-meta");
    const listEl = document.getElementById("tool-list");
    const reportLink = document.getElementById("report-link");
    let finished = panel.dataset.terminal === "true";
    if (finished) return;

    let timer = null;

    function render(data) {
        statusEl.textContent = data.status;
        statusEl.className = `status status--${data.status}`;

        errorEl.hidden = !data.error;
        errorEl.textContent = data.error || "";

        const counts = data.counts || {};
        metaEl.textContent = [
            `${counts.completed || 0} completed`,
            `${counts.running || 0} running`,
            `${counts.empty || 0} empty`,
            `${counts.skipped || 0} skipped`,
            `${counts.unavailable || 0} unavailable`,
            `${counts.failed || 0} failed`,
        ].join(" \u00b7 ");

        listEl.replaceChildren(...(data.tools || []).map((tool) => {
            const item = document.createElement("li");
            item.className = `tool tool--${tool.status}`;
            item.dataset.tool = tool.tool;

            const name = document.createElement("span");
            name.className = "tool__name";
            name.textContent = tool.name;

            const status = document.createElement("span");
            status.className = `tool__status status status--${tool.status}`;
            status.textContent = tool.status;

            const summary = document.createElement("span");
            summary.className = "tool__summary";
            summary.textContent = tool.summary || "";

            const time = document.createElement("span");
            time.className = "tool__time mono";
            time.textContent = tool.duration_ms ? `${tool.duration_ms} ms` : "";

            item.append(name, status, summary, time);
            return item;
        }));

        if (data.finished) {
            finished = true;
            reportLink.hidden = false;
            if (timer) window.clearInterval(timer);
        }
    }

    async function poll() {
        try {
            const response = await fetch(statusUrl, { headers: { Accept: "application/json" } });
            if (response.ok) render(await response.json());
        } catch {
            // Network hiccup: keep polling until the job finishes.
        }
    }

    timer = window.setInterval(poll, 1500);
    poll();
}

function initReportSearch() {
    const search = document.getElementById("report-search");
    if (!search) return;

    const sections = Array.from(document.querySelectorAll(".report-section"));
    const count = document.getElementById("search-count");

    function apply() {
        const query = search.value.trim().toLowerCase();
        let matches = 0;

        for (const section of sections) {
            const haystack = section.textContent.toLowerCase();
            const hit = !query || haystack.includes(query);
            section.hidden = !hit;
            if (hit) {
                matches += 1;
                if (query) section.open = true;
            }
        }

        count.textContent = query
            ? `${matches} of ${sections.length} sections match "${search.value.trim()}".`
            : "";
    }

    search.addEventListener("input", apply);
    search.addEventListener("keydown", (event) => {
        if (event.key === "Escape") {
            search.value = "";
            apply();
        }
    });
}

initUpload();
initJobPolling();
initReportSearch();
