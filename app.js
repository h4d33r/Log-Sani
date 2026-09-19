  "use strict";

  (() => {
    const $ = id => document.getElementById(id);
    const ui = {
      input: $("input"), output: $("output"), status: $("status"), progress: $("progress"),
      inputSize: $("inputSize"), outputSize: $("outputSize"),
      sanitizeBtn: $("sanitizeBtn"), maskSelectionBtn: $("maskSelectionBtn"), copyBtn: $("copyBtn"), restoreBtn: $("restoreBtn"),
      loadFileBtn: $("loadFileBtn"), downloadBtn: $("downloadBtn"),
      downloadMappingBtn: $("downloadMappingBtn"), loadMappingBtn: $("loadMappingBtn"),
      clearBtn: $("clearBtn"), fileInput: $("fileInput"), mappingInput: $("mappingInput"),
      countInternal: $("countInternal"), countIdentity: $("countIdentity"),
      countDomain: $("countDomain"), countSecret: $("countSecret"), countPublic: $("countPublic"),
      clientDomains: $("clientDomains"), netbiosDomains: $("netbiosDomains"),
      iocAllowlist: $("iocAllowlist"), customRules: $("customRules"),
      exportConfigBtn: $("exportConfigBtn"), importConfigBtn: $("importConfigBtn"),
      configInput: $("configInput"), testsBtn: $("testsBtn"), testsResult: $("testsResult"),
      reviewPanel: $("reviewPanel"), reviewSummary: $("reviewSummary"), reviewBody: $("reviewBody"),
      copyReviewBtn: $("copyReviewBtn"), suggestionsPanel: $("suggestionsPanel"),
      suggestionsSummary: $("suggestionsSummary"), suggestionsBody: $("suggestionsBody"),
      selectAllSuggestionsBtn: $("selectAllSuggestionsBtn"), maskSuggestionsBtn: $("maskSuggestionsBtn"),
      ignoreSuggestionsBtn: $("ignoreSuggestionsBtn")
    };

    let state = SanitizerEngine.createState();
    let outputText = "";
    let currentReviewRows = [];
    let currentSuggestions = [];
    const reviewDecisions = new Map();
    const manualMasks = new Map();
    const unmaskOverrides = new Map();
    let working = false;

    function setStatus(message, type = "normal") {
      ui.status.textContent = message;
      ui.status.classList.toggle("status-error", type === "error");
      ui.status.classList.toggle("status-success", type === "success");
    }

    function optionsFromUI() {
      return {
        internalIPs: true,
        identities: true,
        clientDomains: true,
        secrets: true,
        publicIPs: false
      };
    }

    function configFromUI() {
      let customRules;
      try { customRules = JSON.parse(ui.customRules.value || "[]"); }
      catch (error) { throw new Error("Custom rules JSON is invalid: " + error.message); }
      return SanitizerEngine.validateConfig({
        clientDomains: SanitizerEngine.parseList(ui.clientDomains.value),
        netbiosDomains: SanitizerEngine.parseList(ui.netbiosDomains.value),
        iocAllowlist: SanitizerEngine.parseList(ui.iocAllowlist.value),
        customRules
      });
    }

    function configJSON() {
      const config = configFromUI();
      return {
        format: "log-sani-config",
        version: 1,
        exportedAt: new Date().toISOString(),
        options: optionsFromUI(),
        ...config
      };
    }

    function applyConfig(config) {
      const clean = SanitizerEngine.validateConfig(config);
      ui.clientDomains.value = clean.clientDomains.join("\n");
      ui.netbiosDomains.value = clean.netbiosDomains.join("\n");
      ui.iocAllowlist.value = clean.iocAllowlist.join("\n");
      ui.customRules.value = JSON.stringify(clean.customRules.map(({ name, regex, replacement, flags }) => ({ name, regex, replacement, ...(flags !== "gi" ? { flags } : {}) })), null, 2);
    }

    function renderReview(text) {
      const labels = {
        internalIPs: "Internal IP", identities: "Identity", clientDomains: "Client domain",
        emails: "Email", phones: "Phone number", addresses: "Postal address",
        secrets: "Secret", publicIPs: "Public IP", manual: "Manual selection", custom: "Custom rule"
      };
      const rows = state.entries.map(entry => {
        let occurrences = 0;
        let at = 0;
        while ((at = text.indexOf(entry.token, at)) !== -1) {
          occurrences += 1;
          at += entry.token.length || 1;
        }
        return { entry, occurrences };
      }).filter(row => row.occurrences > 0);
      currentReviewRows = rows;

      ui.reviewBody.replaceChildren();
      for (const row of rows) {
        const tr = document.createElement("tr");
        const type = document.createElement("td");
        const original = document.createElement("td");
        const replacement = document.createElement("td");
        const times = document.createElement("td");
        const action = document.createElement("td");
        const originalCode = document.createElement("code");
        const replacementCode = document.createElement("code");
        const copyValueButton = document.createElement("button");
        const unmaskValueButton = document.createElement("button");
        type.textContent = row.entry.label || labels[row.entry.category] || row.entry.category;
        originalCode.textContent = row.entry.original;
        replacementCode.textContent = row.entry.token;
        original.appendChild(originalCode);
        replacement.appendChild(replacementCode);
        times.textContent = String(row.occurrences);
        copyValueButton.type = "button";
        copyValueButton.className = "copy-value";
        copyValueButton.textContent = "Copy";
        copyValueButton.setAttribute("aria-label", "Copy " + type.textContent + " value");
        copyValueButton.addEventListener("click", () => copyText(row.entry.original, "Value copied."));
        unmaskValueButton.type = "button";
        unmaskValueButton.className = "unmask-value";
        unmaskValueButton.textContent = "Unmask";
        unmaskValueButton.setAttribute("aria-label", "Unmask " + type.textContent + " everywhere");
        unmaskValueButton.addEventListener("click", () => unmaskReviewValue(row.entry));
        action.className = "row-actions";
        action.append(copyValueButton, unmaskValueButton);
        tr.append(type, original, replacement, times, action);
        ui.reviewBody.appendChild(tr);
      }
      const replacements = rows.reduce((sum, row) => sum + row.occurrences, 0);
      ui.reviewSummary.textContent = rows.length + " unique value" + (rows.length === 1 ? "" : "s") + ", " + replacements + " replacement" + (replacements === 1 ? "" : "s");
      ui.reviewPanel.classList.toggle("hidden", rows.length === 0);

      const categoryGroups = [
        ["internalIPs"],
        ["identities", "emails", "phones", "addresses"],
        ["clientDomains"],
        ["secrets"]
      ];
      const badges = [ui.countInternal, ui.countIdentity, ui.countDomain, ui.countSecret];
      categoryGroups.forEach((categories, index) => {
        const categoryRows = rows.filter(row => categories.includes(row.entry.category));
        const categoryOccurrences = categoryRows.reduce((sum, row) => sum + row.occurrences, 0);
        badges[index].textContent = String(categoryRows.length);
        badges[index].title = categoryRows.length + " unique; " + categoryOccurrences + " total replacements";
      });
    }

    function renderSuggestions() {
      ui.suggestionsBody.replaceChildren();
      currentSuggestions.forEach((suggestion, index) => {
        const tr = document.createElement("tr");
        const selectCell = document.createElement("td");
        const valueCell = document.createElement("td");
        const typeCell = document.createElement("td");
        const timesCell = document.createElement("td");
        const checkbox = document.createElement("input");
        const valueCode = document.createElement("code");
        selectCell.className = "suggestion-check";
        checkbox.type = "checkbox";
        checkbox.dataset.index = String(index);
        checkbox.setAttribute("aria-label", "Select " + suggestion.type + " " + suggestion.value);
        valueCode.textContent = suggestion.value;
        valueCell.appendChild(valueCode);
        typeCell.textContent = suggestion.type;
        timesCell.textContent = String(suggestion.occurrences);
        selectCell.appendChild(checkbox);
        tr.append(selectCell, valueCell, typeCell, timesCell);
        ui.suggestionsBody.appendChild(tr);
      });
      const total = currentSuggestions.reduce((sum, item) => sum + item.occurrences, 0);
      ui.suggestionsSummary.textContent = currentSuggestions.length + " possible value" + (currentSuggestions.length === 1 ? "" : "s") + ", " + total + " occurrence" + (total === 1 ? "" : "s");
      ui.suggestionsPanel.classList.toggle("hidden", currentSuggestions.length === 0);
      ui.countPublic.textContent = String(currentSuggestions.length);
      ui.countPublic.title = currentSuggestions.length + " value" + (currentSuggestions.length === 1 ? "" : "s") + " waiting for review";
      ui.selectAllSuggestionsBtn.textContent = "Select all";
    }

    function selectedSuggestions() {
      return Array.from(ui.suggestionsBody.querySelectorAll('input[type="checkbox"]:checked'))
        .map(checkbox => currentSuggestions[Number(checkbox.dataset.index)])
        .filter(Boolean);
    }

    function maskSelectedSuggestions() {
      const selected = selectedSuggestions();
      if (!selected.length) { setStatus("Select at least one suggested value first.", "error"); return; }
      selected.forEach(item => reviewDecisions.set(item.key, "mask"));
      const selectedKeys = new Set(selected.map(item => item.key));
      const updated = SanitizerEngine.applySuggestions(outputText, selected, state);
      currentSuggestions = currentSuggestions.filter(item => !selectedKeys.has(item.key));
      renderOutput(updated);
      renderSuggestions();
      setStatus(selected.length + " suggested value" + (selected.length === 1 ? " was" : "s were") + " masked.", "success");
    }

    function ignoreSelectedSuggestions() {
      const selected = selectedSuggestions();
      if (!selected.length) { setStatus("Select at least one suggested value first.", "error"); return; }
      selected.forEach(item => reviewDecisions.set(item.key, "ignore"));
      const selectedKeys = new Set(selected.map(item => item.key));
      currentSuggestions = currentSuggestions.filter(item => !selectedKeys.has(item.key));
      renderSuggestions();
      setStatus(selected.length + " suggested value" + (selected.length === 1 ? " was" : "s were") + " left unchanged.", "success");
    }

    function toggleAllSuggestions() {
      const checkboxes = Array.from(ui.suggestionsBody.querySelectorAll('input[type="checkbox"]'));
      const shouldSelect = checkboxes.some(checkbox => !checkbox.checked);
      checkboxes.forEach(checkbox => { checkbox.checked = shouldSelect; });
      ui.selectAllSuggestionsBtn.textContent = shouldSelect ? "Clear selection" : "Select all";
    }

    async function maskSelectedInputText() {
      const start = ui.input.selectionStart;
      const end = ui.input.selectionEnd;
      const value = ui.input.value.slice(start, end).trim();
      if (!value) { setStatus("Highlight a word or phrase in the left panel first.", "error"); return; }
      if (value.length > 5000) { setStatus("The selected text is too long. Select a word or shorter phrase.", "error"); return; }
      for (const [key, item] of unmaskOverrides) {
        if (item.original === value) unmaskOverrides.delete(key);
      }
      manualMasks.set(value, value);
      await sanitize();
    }

    function unmaskReviewValue(entry) {
      const key = SanitizerEngine.entryKey(entry.category, entry.original);
      unmaskOverrides.set(key, { category: entry.category, original: entry.original });
      outputText = SanitizerEngine.unmaskValues(outputText, state, [key]);
      renderOutput(outputText);
      setStatus("Unmasked " + (entry.label || "value") + " everywhere. This choice is remembered in this tab.", "success");
    }

    function renderOutput(text) {
      outputText = String(text);
      if (!outputText) {
        ui.output.textContent = "";
      } else {
        const tokens = state.entries.map(e => e.token).filter(token => outputText.includes(token)).sort((a, b) => b.length - a.length);
        if (!tokens.length) {
          ui.output.textContent = outputText;
        } else {
          const re = new RegExp("(" + tokens.map(token => token.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|") + ")", "g");
          const fragment = document.createDocumentFragment();
          outputText.split(re).forEach(part => {
            const entry = state.byToken.get(part);
            if (entry) {
              const mark = document.createElement("mark");
              mark.className = "token" + (entry.reviewed ? " review-token" : "");
              mark.textContent = part;
              fragment.appendChild(mark);
            } else {
              fragment.appendChild(document.createTextNode(part));
            }
          });
          ui.output.replaceChildren(fragment);
        }
      }
      ui.outputSize.textContent = outputText.length.toLocaleString() + " characters";
      renderReview(outputText);
    }

    function updateInputSize() {
      ui.inputSize.textContent = ui.input.value.length.toLocaleString() + " characters";
    }

    function setWorking(value) {
      working = value;
      document.querySelectorAll("button").forEach(button => { button.disabled = value; });
      ui.progress.classList.toggle("hidden", !value);
      if (!value) ui.progress.value = 0;
    }

    function yieldToUI() {
      return new Promise(resolve => setTimeout(resolve, 0));
    }

    function makeChunks(text, targetSize = 64000) {
      if (!text) return [""];
      const chunks = [];
      let start = 0;
      while (start < text.length) {
        let end = Math.min(start + targetSize, text.length);
        if (end < text.length) {
          const newline = text.lastIndexOf("\n", end);
          if (newline > start + Math.floor(targetSize * .5)) end = newline + 1;
        }
        chunks.push(text.slice(start, end));
        start = end;
      }
      return chunks;
    }

    async function sanitize() {
      if (working) return;
      const source = ui.input.value;
      if (!source) { setStatus("Paste or load text first.", "error"); return; }
      let config;
      try { config = configFromUI(); }
      catch (error) { setStatus(error.message, "error"); return; }
      const options = optionsFromUI();
      const chunks = makeChunks(source);
      state = SanitizerEngine.createState();
      setWorking(true);
      setStatus("Discovering identities…");
      try {
        for (let i = 0; i < chunks.length; i += 1) {
          SanitizerEngine.discoverIdentities(chunks[i], config, state, options.identities);
          ui.progress.value = Math.round(((i + 1) / chunks.length) * 25);
          if (i % 3 === 0) await yieldToUI();
        }
        const result = [];
        setStatus("Sanitizing locally…");
        for (let i = 0; i < chunks.length; i += 1) {
          result.push(SanitizerEngine.sanitizeChunk(chunks[i], config, options, state));
          ui.progress.value = 25 + Math.round(((i + 1) / chunks.length) * 75);
          if (i % 2 === 0) await yieldToUI();
        }
        let sanitizedText = result.join("");
        if (manualMasks.size) sanitizedText = SanitizerEngine.applyManualValues(sanitizedText, Array.from(manualMasks.values()), state);
        const detectedSuggestions = SanitizerEngine.detectSuggestions(sanitizedText, config);
        const rememberedMasks = detectedSuggestions.filter(item => reviewDecisions.get(item.key) === "mask");
        if (rememberedMasks.length) sanitizedText = SanitizerEngine.applySuggestions(sanitizedText, rememberedMasks, state);
        if (unmaskOverrides.size) sanitizedText = SanitizerEngine.unmaskValues(sanitizedText, state, unmaskOverrides.keys());
        currentSuggestions = detectedSuggestions.filter(item => !reviewDecisions.has(item.key));
        renderOutput(sanitizedText);
        renderSuggestions();
        const hiddenValues = state.entries.filter(entry => sanitizedText.includes(entry.token)).length;
        const suggestionText = currentSuggestions.length ? " " + currentSuggestions.length + " possible value" + (currentSuggestions.length === 1 ? " needs" : "s need") + " review." : " No uncertain values need review.";
        const rememberedText = rememberedMasks.length ? " " + rememberedMasks.length + " saved review choice" + (rememberedMasks.length === 1 ? " was" : "s were") + " applied." : "";
        setStatus("Sanitized locally. " + hiddenValues + " unique value" + (hiddenValues === 1 ? " was" : "s were") + " hidden." + rememberedText + suggestionText, "success");
      } catch (error) {
        setStatus("Sanitization failed: " + error.message, "error");
      } finally {
        setWorking(false);
      }
    }

    async function restoreInput() {
      if (working) return;
      if (!ui.input.value) { setStatus("Paste tokenized text into Input first.", "error"); return; }
      if (!state.entries.length) { setStatus("No restore key is loaded in this tab.", "error"); return; }
      setWorking(true);
      setStatus("Restoring from the private key held in this tab…");
      await yieldToUI();
      try {
        currentSuggestions = [];
        renderSuggestions();
        renderOutput(SanitizerEngine.restore(ui.input.value, state));
        setStatus("Original values restored using the key held in this tab.", "success");
      } catch (error) {
        setStatus("Restore failed: " + error.message, "error");
      } finally { setWorking(false); }
    }

    function downloadFile(filename, content, type) {
      const blob = new Blob([content], { type });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    }

    function readLocalFile(file, maxBytes = 50 * 1024 * 1024) {
      return new Promise((resolve, reject) => {
        if (!file) return reject(new Error("No file selected."));
        if (file.size > maxBytes) return reject(new Error("File exceeds the 50 MB safety limit."));
        const reader = new FileReader();
        reader.onload = () => resolve(String(reader.result));
        reader.onerror = () => reject(new Error("The local file could not be read."));
        reader.readAsText(file);
      });
    }

    async function copyText(text, successMessage) {
      try {
        await navigator.clipboard.writeText(text);
        setStatus(successMessage, "success");
      } catch (_) {
        const helper = document.createElement("textarea");
        helper.value = text;
        helper.setAttribute("readonly", "");
        helper.className = "clipboard-helper";
        document.body.appendChild(helper);
        helper.select();
        const copied = document.execCommand("copy");
        helper.remove();
        setStatus(copied ? successMessage : "Copy was blocked by the browser.", copied ? "success" : "error");
      }
    }

    async function copyOutput() {
      if (!outputText) { setStatus("There is no output to copy.", "error"); return; }
      await copyText(outputText, "Sanitized text copied.");
    }

    async function copyAllReviewValues() {
      if (!currentReviewRows.length) { setStatus("There are no masked values to copy.", "error"); return; }
      const values = currentReviewRows.map(row => row.entry.original).join("\n");
      await copyText(values, currentReviewRows.length + " masked value" + (currentReviewRows.length === 1 ? "" : "s") + " copied.");
    }

    function clearAll() {
      ui.input.value = "";
      state = SanitizerEngine.createState();
      currentSuggestions = [];
      reviewDecisions.clear();
      manualMasks.clear();
      unmaskOverrides.clear();
      renderOutput("");
      renderSuggestions();
      updateInputSize();
      ui.testsResult.className = "tests hidden";
      ui.testsResult.textContent = "";
      setStatus("Cleared. Text, restore key and review choices were removed from memory.", "success");
    }

    ui.input.addEventListener("input", updateInputSize);
    ui.sanitizeBtn.addEventListener("click", sanitize);
    ui.maskSelectionBtn.addEventListener("click", maskSelectedInputText);
    ui.restoreBtn.addEventListener("click", restoreInput);
    ui.copyBtn.addEventListener("click", copyOutput);
    ui.copyReviewBtn.addEventListener("click", copyAllReviewValues);
    ui.selectAllSuggestionsBtn.addEventListener("click", toggleAllSuggestions);
    ui.maskSuggestionsBtn.addEventListener("click", maskSelectedSuggestions);
    ui.ignoreSuggestionsBtn.addEventListener("click", ignoreSelectedSuggestions);
    ui.clearBtn.addEventListener("click", clearAll);
    ui.loadFileBtn.addEventListener("click", () => ui.fileInput.click());
    ui.loadMappingBtn.addEventListener("click", () => ui.mappingInput.click());
    ui.importConfigBtn.addEventListener("click", () => ui.configInput.click());

    ui.downloadBtn.addEventListener("click", () => {
      if (!outputText) { setStatus("There is no output to download.", "error"); return; }
      downloadFile("log-sani-output.txt", outputText, "text/plain;charset=utf-8");
      setStatus("Output download created locally.", "success");
    });

    ui.downloadMappingBtn.addEventListener("click", () => {
      if (!state.entries.length) { setStatus("There is no restore key to save.", "error"); return; }
      downloadFile("log-sani-restore-key.json", JSON.stringify(SanitizerEngine.mappingJSON(state), null, 2), "application/json");
      setStatus("Restore key saved. Protect it because it contains the original values.", "success");
    });

    ui.exportConfigBtn.addEventListener("click", () => {
      try {
        downloadFile("log-sani-config.json", JSON.stringify(configJSON(), null, 2), "application/json");
        setStatus("Configuration exported.", "success");
      } catch (error) { setStatus(error.message, "error"); }
    });

    ui.fileInput.addEventListener("change", async event => {
      try {
        ui.input.value = await readLocalFile(event.target.files[0]);
        updateInputSize();
        setStatus("File loaded locally. It has not been uploaded.", "success");
      } catch (error) { setStatus(error.message, "error"); }
      event.target.value = "";
    });

    ui.mappingInput.addEventListener("change", async event => {
      try {
        const parsed = JSON.parse(await readLocalFile(event.target.files[0], 20 * 1024 * 1024));
        if (parsed.format !== "log-sani-mapping" || parsed.version !== 1 || !Array.isArray(parsed.mappings)) throw new Error("Not a supported Log-Sani mapping file.");
        state = SanitizerEngine.createState(parsed);
        renderOutput(outputText);
        setStatus("Restore key loaded with " + state.entries.length + " original values.", "success");
      } catch (error) { setStatus("Restore-key load failed: " + error.message, "error"); }
      event.target.value = "";
    });

    ui.configInput.addEventListener("change", async event => {
      try {
        const parsed = JSON.parse(await readLocalFile(event.target.files[0], 2 * 1024 * 1024));
        if (parsed.format && parsed.format !== "log-sani-config") throw new Error("Not a supported Log-Sani config file.");
        applyConfig(parsed);
        setStatus("Configuration imported.", "success");
      } catch (error) { setStatus("Config import failed: " + error.message, "error"); }
      event.target.value = "";
    });

    ui.testsBtn.addEventListener("click", () => {
      const results = SanitizerEngine.runTests();
      const passed = results.filter(result => result.pass).length;
      ui.testsResult.textContent = results.map(result => (result.pass ? "PASS  " : "FAIL  ") + result.name).join("\n") + "\n\n" + passed + "/" + results.length + " tests passed.";
      ui.testsResult.className = "tests " + (passed === results.length ? "pass" : "fail");
      setStatus(passed === results.length ? "All self-tests passed." : "One or more self-tests failed.", passed === results.length ? "success" : "error");
    });

    updateInputSize();
    renderOutput("");
    renderSuggestions();
  })();
