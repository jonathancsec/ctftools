const form = document.getElementById("forensics-form");
const fileInput = document.getElementById("forensics-file");
const dropZone = document.getElementById("drop-zone");
const fileInfo = document.getElementById("file-info");
const analyzeButton = document.getElementById("analyze-button");
const statusLine = document.getElementById("forensics-status");
const results = document.getElementById("forensics-results");
const summary = document.getElementById("report-summary");
const sectionList = document.getElementById("report-sections");

const MAX_BYTES = 25 * 1024 * 1024;
let selectedFile = null;
let previewUrl = null;

function setStatus(message, isError = false) {
    statusLine.hidden = !message;
    statusLine.textContent = message;
    statusLine.classList.toggle("is-error", isError);
}

function formatBytes(bytes) {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function selectFile(file) {
    selectedFile = file;
    if (previewUrl) URL.revokeObjectURL(previewUrl);
    previewUrl = file.type.startsWith("image/") ? URL.createObjectURL(file) : null;

    fileInfo.textContent = `${file.name} - ${formatBytes(file.size)}`;
    results.hidden = true;
    setStatus(file.size > MAX_BYTES ? "That file is larger than 25 MB." : "", file.size > MAX_BYTES);
    analyzeButton.disabled = file.size === 0 || file.size > MAX_BYTES;
}

fileInput.addEventListener("change", () => {
    const file = fileInput.files[0];
    if (file) selectFile(file);
});

for (const eventName of ["dragenter", "dragover"]) {
    dropZone.addEventListener(eventName, (event) => {
        event.preventDefault();
        dropZone.classList.add("is-over");
    });
}

dropZone.addEventListener("dragleave", () => dropZone.classList.remove("is-over"));

dropZone.addEventListener("drop", (event) => {
    event.preventDefault();
    dropZone.classList.remove("is-over");
    const file = event.dataTransfer?.files?.[0];
    if (file) selectFile(file);
});

window.addEventListener("dragover", (event) => event.preventDefault());
window.addEventListener("drop", (event) => event.preventDefault());

function badgeText(section) {
    if (section.status === "unavailable") return "not installed";
    if (section.status === "empty") return "nothing found";
    if (section.status === "error") return "error";
    return section.duration_ms ? `ran ${section.duration_ms} ms` : "ran";
}

function renderSection(section) {
    const details = document.createElement("details");
    details.className = `report-section report-section--${section.status}`;
    details.open = section.status === "ok" && (section.text || "").length < 4000;

    const head = document.createElement("summary");
    const title = document.createElement("span");
    title.className = "report-title";
    title.textContent = section.title;
    const badge = document.createElement("span");
    badge.className = `badge badge--${section.status}`;
    badge.textContent = badgeText(section);
    head.append(title, badge);
    details.append(head);

    if (section.text) {
        const output = document.createElement("pre");
        output.className = "report-output";
        output.textContent = section.text;
        details.append(output);
    }

    for (const message of [section.note, section.hint]) {
        if (!message) continue;
        const note = document.createElement("p");
        note.className = "report-note";
        note.textContent = message;
        details.append(note);
    }

    return details;
}

function renderReport(report) {
    summary.replaceChildren();

    if (previewUrl) {
        const image = document.createElement("img");
        image.src = previewUrl;
        image.alt = `Preview of ${report.name}`;
        summary.append(image);
    }

    const meta = document.createElement("div");
    const name = document.createElement("div");
    name.className = "report-name";
    name.textContent = report.name;
    const line = document.createElement("div");
    line.className = "report-meta";
    line.textContent = `${report.type} - ${formatBytes(report.size)} - sha256 ${report.sha256.slice(0, 16)}...`;
    meta.append(name, line);
    summary.append(meta);
    summary.hidden = false;

    sectionList.replaceChildren(...report.sections.map(renderSection));
    results.hidden = false;
}

form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!selectedFile) {
        setStatus("Choose a file to analyze first.", true);
        return;
    }

    analyzeButton.disabled = true;
    results.hidden = true;
    setStatus(`Analyzing ${selectedFile.name}...`);

    try {
        const response = await fetch(`/api/forensics?name=${encodeURIComponent(selectedFile.name)}`, {
            method: "POST",
            headers: { "Content-Type": "application/octet-stream" },
            body: selectedFile
        });
        const report = await response.json();
        if (!response.ok) throw new Error(report.error || "Analysis failed.");
        renderReport(report);
        setStatus(`Analyzed ${report.name} in ${(report.duration_ms / 1000).toFixed(1)} s.`);
    } catch (error) {
        setStatus(error.message, true);
    } finally {
        analyzeButton.disabled = !selectedFile || selectedFile.size > MAX_BYTES;
    }
});
