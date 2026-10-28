async function postJson(path, request) {
    let response;
    try {
        response = await fetch(path, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(request)
        });
    } catch {
        throw new Error("Cannot reach the decoder. Run python server.py and open this page at http://127.0.0.1:8000/cryptography.html.");
    }

    const result = await response.json();
    if (!response.ok) throw new Error(result.error || "Decoding failed.");
    return result;
}

function decodeWithPython(request) {
    return postJson("/api/decode", request);
}

function setResult(element, message, isError = false) {
    element.hidden = false;
    element.classList.toggle("is-error", isError);
    element.textContent = message;
}

function wireDecoder({ formId, resultId, buildRequest }) {
    const form = document.getElementById(formId);
    const result = document.getElementById(resultId);
    if (!form || !result) return;

    form.addEventListener("submit", async (event) => {
        event.preventDefault();
        setResult(result, "Decoding...");
        try {
            const data = await decodeWithPython(buildRequest());
            setResult(result, data.text || "(empty result)");
        } catch (error) {
            setResult(result, error.message, true);
        }
    });
}

/* Auto-decode ----------------------------------------------------------- */

const autoInput = document.getElementById("auto-input");
const autoResult = document.getElementById("auto-result");
const autoResults = document.getElementById("auto-results");

function showAutoResults(candidates) {
    if (!candidates.length) {
        autoResults.hidden = true;
        setResult(autoResult, "No candidates found.");
        return;
    }

    const items = candidates.map((candidate, index) => {
        const item = document.createElement("li");
        if (index === 0) item.classList.add("is-best");
        item.title = `Heuristic score: ${candidate.score}`;

        const label = document.createElement("strong");
        label.textContent = candidate.method;

        const text = document.createElement("span");
        text.className = "candidate-text";
        text.textContent = candidate.text;

        item.append(label, text);
        return item;
    });

    autoResults.replaceChildren(...items);
    autoResult.hidden = true;
    autoResults.hidden = false;
}

document.getElementById("auto-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    autoResults.hidden = true;
    setResult(autoResult, "Trying decoders...");

    try {
        const data = await postJson("/api/autodecode", { text: autoInput.value });
        showAutoResults(data.results || []);
    } catch (error) {
        autoResults.hidden = true;
        setResult(autoResult, error.message, true);
    }
});

/* Caesar / ROT-N --------------------------------------------------------- */

const caesarInput = document.getElementById("caesar-input");
const caesarShift = document.getElementById("caesar-shift");
const caesarResult = document.getElementById("caesar-result");
const caesarCandidates = document.getElementById("caesar-candidates");

function showCaesarText(message, isError = false) {
    caesarCandidates.hidden = true;
    setResult(caesarResult, message, isError);
}

document.getElementById("caesar-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    showCaesarText("Decoding...");
    try {
        const data = await decodeWithPython({
            cipher: "caesar",
            text: caesarInput.value,
            shift: Number(caesarShift.value)
        });
        showCaesarText(data.text || "(empty result)");
    } catch (error) {
        showCaesarText(error.message, true);
    }
});

document.getElementById("caesar-rot13").addEventListener("click", () => {
    caesarShift.value = "13";
    document.getElementById("caesar-form").requestSubmit();
});

document.getElementById("caesar-all-shifts").addEventListener("click", async () => {
    if (!caesarInput.value) {
        caesarInput.focus();
        return;
    }

    caesarCandidates.hidden = true;
    setResult(caesarResult, "Trying every shift...");
    try {
        const data = await decodeWithPython({
            cipher: "caesar",
            text: caesarInput.value,
            all_shifts: true
        });
        const items = data.results.map((candidate) => {
            const item = document.createElement("li");
            const label = document.createElement("strong");
            label.textContent = `Shift ${candidate.shift}`;
            item.append(label, document.createTextNode(candidate.text));
            return item;
        });
        caesarCandidates.replaceChildren(...items);
        caesarResult.hidden = true;
        caesarCandidates.hidden = false;
    } catch (error) {
        setResult(caesarResult, error.message, true);
    }
});

/* Other decoders -------------------------------------------------------- */

wireDecoder({
    formId: "railfence-form",
    resultId: "railfence-result",
    buildRequest: () => ({
        cipher: "railfence",
        text: document.getElementById("railfence-input").value,
        rails: Number(document.getElementById("rail-count").value)
    })
});

wireDecoder({
    formId: "vigenere-form",
    resultId: "vigenere-result",
    buildRequest: () => ({
        cipher: "vigenere",
        text: document.getElementById("vigenere-input").value,
        key: document.getElementById("vigenere-key").value
    })
});

wireDecoder({
    formId: "columnar-form",
    resultId: "columnar-result",
    buildRequest: () => ({
        cipher: "columnar",
        text: document.getElementById("columnar-input").value,
        key: document.getElementById("columnar-key").value
    })
});

wireDecoder({
    formId: "beaufort-form",
    resultId: "beaufort-result",
    buildRequest: () => ({
        cipher: "beaufort",
        text: document.getElementById("beaufort-input").value,
        key: document.getElementById("beaufort-key").value
    })
});

wireDecoder({
    formId: "bifid-form",
    resultId: "bifid-result",
    buildRequest: () => ({
        cipher: "bifid",
        text: document.getElementById("bifid-input").value,
        key: document.getElementById("bifid-key").value,
        period: Number(document.getElementById("bifid-period").value)
    })
});

wireDecoder({
    formId: "playfair-form",
    resultId: "playfair-result",
    buildRequest: () => ({
        cipher: "playfair",
        text: document.getElementById("playfair-input").value,
        key: document.getElementById("playfair-key").value
    })
});

for (const [cipher, inputId] of [
    ["atbash", "atbash-input"],
    ["rot47", "rot47-input"],
    ["binary", "binary-input"],
    ["hex", "hex-input"],
    ["base32", "base32-input"],
    ["base85", "base85-input"],
    ["base64", "base64-input"],
    ["base58", "base58-input"],
    ["url", "url-input"],
    ["html", "html-input"],
    ["morse", "morse-input"],
    ["bacon", "bacon-input"],
    ["a1z26", "a1z26-input"],
    ["polybius", "polybius-input"],
    ["decimal", "decimal-input"],
    ["octal", "octal-input"],
    ["nato", "nato-input"],
    ["leetspeak", "leetspeak-input"]
]) {
    wireDecoder({
        formId: `${cipher}-form`,
        resultId: `${cipher}-result`,
        buildRequest: () => ({ cipher, text: document.getElementById(inputId).value })
    });
}

/* Search ---------------------------------------------------------------- */

const searchInput = document.getElementById("cipher-search");
const searchStatus = document.getElementById("search-status");
const toolPanels = Array.from(document.querySelectorAll(".decoder-panel"));

function filterTools() {
    const query = searchInput.value.trim().toLowerCase();
    let matches = 0;

    for (const panel of toolPanels) {
        const title = panel.querySelector("h2")?.textContent || "";
        const keywords = panel.dataset.search || "";
        const isMatch = !query || `${title} ${keywords}`.toLowerCase().includes(query);
        panel.hidden = !isMatch;
        if (isMatch) matches += 1;
    }

    if (!query) {
        searchStatus.hidden = true;
        searchStatus.textContent = "";
        return;
    }

    searchStatus.hidden = false;
    searchStatus.textContent = matches === 0
        ? `Nothing matches “${searchInput.value.trim()}”.`
        : `${matches} ${matches === 1 ? "tool matches" : "tools match"} “${searchInput.value.trim()}”.`;
}

searchInput.addEventListener("input", filterTools);
searchInput.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
        searchInput.value = "";
        filterTools();
        searchInput.blur();
    }
});
