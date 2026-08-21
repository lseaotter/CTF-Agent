(function () {
    "use strict";

    var state = {
        view: "overview",
        runs: [],
        run: null,
        findings: [],
        selectedId: null,
        selectedDetail: null,
        providers: [],
        evaluation: null,
        scan: null,
        toastTimer: null,
        pollTimer: null
    };

    var labels = {
        overview: ["LOCAL / OVERVIEW", "运行总览"],
        findings: ["OPENHARMONY / FINDINGS", "漏洞发现"],
        activity: ["LOCAL / HISTORY", "分析记录"],
        diagnostics: ["LOCAL / PROVIDERS", "连接诊断"]
    };

    function byId(id) { return document.getElementById(id); }

    function setText(id, value) {
        var element = byId(id);
        if (element) {
            element.textContent = value === null || value === undefined || value === "" ? "--" : String(value);
        }
    }

    function escapeHtml(value) {
        return String(value === null || value === undefined ? "" : value)
            .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;").replace(/'/g, "&#039;");
    }

    function formatDate(value, withTime) {
        if (!value) { return "--"; }
        var date = new Date(value);
        if (Number.isNaN(date.getTime())) { return String(value); }
        return new Intl.DateTimeFormat("zh-CN", withTime
            ? { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" }
            : { year: "numeric", month: "2-digit", day: "2-digit" }).format(date);
    }

    function showToast(message, error) {
        var toast = byId("toast");
        if (!toast) { return; }
        toast.textContent = message;
        toast.style.borderColor = error ? "var(--coral)" : "var(--line-strong)";
        toast.classList.add("visible");
        window.clearTimeout(state.toastTimer);
        state.toastTimer = window.setTimeout(function () { toast.classList.remove("visible"); }, 3200);
    }

    async function requestJson(url, options) {
        var response = await fetch(url, options || {});
        var payload = null;
        try { payload = await response.json(); } catch (ignore) { payload = null; }
        if (!response.ok) {
            throw new Error(payload && payload.detail ? payload.detail : "HTTP " + response.status);
        }
        return payload;
    }

    function statusBadge(status) {
        var isVerified = status === "verified" || status === "completed";
        var label = status === "verified" ? "已验证" : status === "completed" ? "完成" : status === "invalid" ? "格式错误" : "待复核";
        return "<span class=\"status-badge " + (status === "invalid" ? "invalid" : isVerified ? "verified" : "review") + "\">" + label + "</span>";
    }

    function setView(view) {
        state.view = view;
        document.querySelectorAll("[data-view-panel]").forEach(function (panel) {
            panel.classList.toggle("active", panel.getAttribute("data-view-panel") === view);
        });
        document.querySelectorAll("[data-view]").forEach(function (item) {
            item.classList.toggle("active", item.getAttribute("data-view") === view);
        });
        setText("view-eyebrow", labels[view][0]);
        setText("view-title", labels[view][1]);
        if (view === "findings" && state.run) { loadFindings(); }
    }

    function updateConnection(ok, message) {
        var element = byId("connection-state");
        if (!element) { return; }
        element.textContent = ok ? "SERVICE ONLINE" : "SERVICE OFFLINE";
        element.classList.toggle("is-error", !ok);
        setText("footer-status", message || (ok ? "本地服务正常" : "本地服务不可用"));
        setText("footer-time", formatDate(new Date().toISOString(), true));
    }

    async function loadFindings() {
        if (!state.run) { state.findings = []; renderFindings(); return; }
        var query = new URLSearchParams();
        var search = byId("finding-search").value.trim();
        var status = byId("finding-state").value;
        if (search) { query.set("q", search); }
        if (status) { query.set("state", status); }
        try {
            var result = await requestJson("/api/v1/runs/" + encodeURIComponent(state.run.run_id) + "/findings?" + query.toString());
            state.findings = result.items || [];
            state.selectedId = state.findings.some(function (item) { return item.id === state.selectedId; }) ? state.selectedId : (state.findings[0] && state.findings[0].id);
            renderFindings();
            if (state.selectedId) { await loadFindingDetail(state.selectedId); }
        } catch (error) {
            showToast(error.message, true);
        }
    }

    async function loadFindingDetail(id) {
        if (!id) { return; }
        try {
            state.selectedDetail = await requestJson("/api/v1/findings/" + encodeURIComponent(id));
            renderFindingDetail();
        } catch (error) { showToast(error.message, true); }
    }

    async function loadEvaluation() {
        if (!state.run) { state.evaluation = null; renderOverview(); return; }
        try {
            state.evaluation = await requestJson("/api/v1/evaluation?run_id=" + encodeURIComponent(state.run.run_id));
        } catch (ignore) { state.evaluation = null; }
        renderOverview();
    }

    async function selectRun(runId) {
        var selected = state.runs.find(function (item) { return item.run_id === runId; });
        if (!selected) { return; }
        state.run = selected;
        state.selectedId = null;
        state.selectedDetail = null;
        setText("current-run-label", selected.artifact || selected.run_id);
        var select = byId("run-select");
        if (select) { select.value = selected.run_id; }
        try {
            var run = await requestJson("/api/v1/runs/" + encodeURIComponent(selected.run_id));
            state.run = Object.assign({}, selected, run);
        } catch (error) { showToast(error.message, true); }
        await Promise.all([loadFindings(), loadEvaluation()]);
        renderActivity();
    }

    function renderRunTable() {
        var target = byId("run-table");
        if (!target) { return; }
        target.innerHTML = state.runs.length ? state.runs.slice(0, 12).map(function (run) {
            return "<tr class=\"selectable " + (state.run && state.run.run_id === run.run_id ? "selected" : "") + "\" data-run-id=\"" + escapeHtml(run.run_id) + "\">" +
                "<td class=\"module-cell\" title=\"" + escapeHtml(run.module + " / " + run.artifact) + "\"><strong>" + escapeHtml(run.module) + "</strong><small class=\"mono\">" + escapeHtml(run.artifact) + "</small></td>" +
                "<td class=\"mono\">" + escapeHtml(run.run_id) + "</td>" +
                "<td>" + escapeHtml(run.grouped_total) + " / " + escapeHtml(run.raw_total) + "</td>" +
                "<td>" + statusBadge(run.status) + "</td>" +
                "<td>" + escapeHtml(formatDate(run.updated_at || run.timestamp, true)) + "</td>" +
                "<td class=\"run-action-cell\"><button class=\"button button-quiet\" type=\"button\" data-run-id=\"" + escapeHtml(run.run_id) + "\">打开</button></td>" +
                "</tr>";
        }).join("") : "<tr><td colspan=\"6\"><div class=\"empty-state\">暂无结果文件。</div></td></tr>";
    }

    function renderRunSelect() {
        var select = byId("run-select");
        if (!select) { return; }
        select.innerHTML = state.runs.map(function (run) {
            return "<option value=\"" + escapeHtml(run.run_id) + "\">" + escapeHtml(run.module + " / " + run.artifact) + "</option>";
        }).join("");
        if (state.run) { select.value = state.run.run_id; }
    }

    function renderOverview() {
        setText("metric-runs", state.runs.length);
        setText("metric-findings", state.run ? (state.run.grouped_total || state.findings.length || 0) : 0);
        setText("metric-score", state.evaluation ? state.evaluation.score + "/" + state.evaluation.max_score : "--");
        setText("metric-score-detail", state.evaluation ? (Math.round(state.evaluation.accuracy * 100) + "% · L1/L2/L3") : "选择结果后计算");
        setText("current-run-label", state.run ? (state.run.artifact || state.run.run_id) : "未选择");
        renderRunTable();
        var scan = state.scan || { status: "idle" };
        setText("metric-scan", scan.status || "idle");
        setText("metric-scan-detail", scan.module || "本地进程");
        setText("scan-status-label", (scan.status || "idle").toUpperCase());
    }

    function renderFindings() {
        var target = byId("finding-table");
        var empty = byId("finding-empty");
        setText("finding-count-label", "发现 " + state.findings.length);
        if (!target) { return; }
        empty.hidden = state.findings.length > 0;
        target.innerHTML = state.findings.map(function (finding) {
            var level2 = finding.level2_commit || "未记录";
            return "<tr class=\"selectable " + (finding.id === state.selectedId ? "selected" : "") + "\" data-finding-id=\"" + escapeHtml(finding.id) + "\">" +
                "<td class=\"location-cell\"><strong class=\"mono\">" + escapeHtml(finding.location) + "</strong><small>" + escapeHtml(finding.type) + "</small></td>" +
                "<td class=\"mono\">" + escapeHtml(level2.length > 16 ? level2.slice(0, 16) + "…" : level2) + "</td>" +
                "<td>" + escapeHtml(finding.cwe) + "</td>" +
                "<td>" + statusBadge(finding.status) + "</td>" +
                "<td class=\"confidence\">" + escapeHtml(finding.confidence === null || finding.confidence === undefined ? "--" : finding.confidence + "%") + "</td>" +
                "</tr>";
        }).join("");
    }

    function renderFindingDetail() {
        var target = byId("finding-detail");
        var finding = state.selectedDetail;
        if (!target || !finding) { return; }
        var submission = finding.submission || {};
        var evidence = finding.evidence || {};
        target.innerHTML = "<div class=\"detail-content\">" +
            "<p class=\"eyebrow\">SUBMISSION CHAIN</p>" +
            "<h2 class=\"detail-title\">" + escapeHtml(finding.type) + "</h2>" +
            "<p class=\"detail-subtitle\">" + escapeHtml(finding.description) + "</p>" +
            "<div class=\"submission-grid\">" +
                submissionRow("L1", submission.L1 || finding.location) +
                submissionRow("L2", submission.L2 || "未记录") +
                submissionRow("L3", submission.L3 || finding.cwe) +
                submissionRow("ID", submission.trackId || "未记录") +
            "</div>" +
            "<div class=\"detail-actions\"><button class=\"button button-primary\" type=\"button\" data-action=\"copy-submission\">复制提交材料</button><button class=\"button button-quiet\" type=\"button\" data-action=\"open-source\">查看源码</button></div>" +
            "<div class=\"evidence-section\"><h3>Git 证据</h3><p>" + escapeHtml(evidence.available ? "修复提交与前后版本源码可读取。" : (evidence.error || "暂无 Git 证据。")) + "</p>" +
                (evidence.diff ? "<pre class=\"diff\">" + escapeHtml(evidence.diff) + "</pre>" : "") +
            "</div></div>";
    }

    function submissionRow(label, value) {
        return "<div class=\"submission-row\"><strong>" + escapeHtml(label) + "</strong><span>" + escapeHtml(value) + "</span></div>";
    }

    function renderActivity() {
        var target = byId("activity-list");
        setText("activity-count", state.runs.length + " 条");
        if (!target) { return; }
        target.innerHTML = state.runs.length ? state.runs.map(function (run) {
            return "<div class=\"activity-row\"><strong>" + escapeHtml(run.module) + "</strong><span class=\"mono\">" + escapeHtml(run.artifact) + "</span><span>" + escapeHtml(run.grouped_total) + " findings</span><span>" + statusBadge(run.status) + "</span><small>" + escapeHtml(formatDate(run.updated_at || run.timestamp, true)) + "</small></div>";
        }).join("") : "<div class=\"empty-state\">暂无运行记录。</div>";
    }

    function renderProviders() {
        var target = byId("provider-list");
        if (!target) { return; }
        target.innerHTML = state.providers.length ? state.providers.map(function (provider) {
            return "<div class=\"provider-row\"><strong>" + escapeHtml(provider.label) + "</strong><span class=\"mono\">" + escapeHtml(provider.model) + "</span><span>" + (provider.configured ? statusBadge("verified") : statusBadge("needs-review")) + "</span><small>" + escapeHtml(provider.protocol) + "</small><button class=\"button button-quiet\" type=\"button\" data-action=\"probe-provider\" data-provider=\"" + escapeHtml(provider.key) + "\">探测</button></div>";
        }).join("") : "<div class=\"empty-state\">暂无模型配置。</div>";
    }

    async function loadAll() {
        try {
            var health = await requestJson("/api/v1/health");
            updateConnection(true, "本地服务正常 · " + health.run_count + " 个结果");
            state.scan = health.scan;
            var responses = await Promise.all([requestJson("/api/v1/runs?limit=100"), requestJson("/api/v1/providers")]);
            state.runs = responses[0].items || [];
            state.providers = responses[1].items || [];
            renderRunSelect();
            renderProviders();
            renderActivity();
            renderOverview();
            if (!state.run || !state.runs.some(function (run) { return run.run_id === state.run.run_id; })) {
                state.run = state.runs[0] || null;
            }
            if (state.run) { await selectRun(state.run.run_id); }
            else { renderOverview(); renderFindings(); }
        } catch (error) {
            updateConnection(false, error.message);
            showToast(error.message, true);
        }
    }

    async function refreshScan() {
        try {
            state.scan = await requestJson("/api/v1/scans/status");
            renderOverview();
            var consoleTarget = byId("scan-console");
            if (consoleTarget) { consoleTarget.textContent = (state.scan.logs || []).join("\n") || "暂无扫描记录。"; }
            if (state.scan.status === "running" || state.scan.status === "starting" || state.scan.status === "stopping") {
                state.pollTimer = window.setTimeout(refreshScan, 1800);
            } else if (state.scan.status === "completed") {
                await loadAll();
            }
        } catch (error) { showToast(error.message, true); }
    }

    async function startScan() {
        var module = byId("scan-module").value;
        try {
            state.scan = await requestJson("/api/v1/scans", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ module: module }) });
            showToast("扫描已启动");
            await refreshScan();
        } catch (error) { showToast(error.message, true); }
    }

    async function stopScan() {
        try {
            state.scan = await requestJson("/api/v1/scans/stop", { method: "POST" });
            showToast("已请求停止扫描");
            await refreshScan();
        } catch (error) { showToast(error.message, true); }
    }

    async function copySubmission() {
        if (!state.selectedDetail) { return; }
        var submission = state.selectedDetail.submission || {};
        var content = ["trackId: " + (submission.trackId || ""), "L1: " + (submission.L1 || ""), "L2: " + (submission.L2 || ""), "L3: " + (submission.L3 || "")].join("\n");
        try {
            await navigator.clipboard.writeText(content);
            showToast("提交材料已复制");
        } catch (error) { showToast("浏览器不允许访问剪贴板", true); }
    }

    function openSource() {
        if (!state.selectedDetail || !state.run) { return; }
        var finding = state.selectedDetail;
        var start = Math.max(1, (finding.line_start || 1) - 12);
        var end = (finding.line_end || finding.line_start || 1) + 18;
        window.open("/api/v1/source?run_id=" + encodeURIComponent(state.run.run_id) + "&path=" + encodeURIComponent(finding.file) + "&start=" + start + "&end=" + end, "_blank", "noopener");
    }

    async function probeProvider(key) {
        try {
            var result = await requestJson("/api/v1/diagnostics/providers/" + encodeURIComponent(key) + "/probe", { method: "POST" });
            showToast(result.ok ? "模型连接正常" : (result.error || "模型连接失败"), !result.ok);
        } catch (error) { showToast(error.message, true); }
    }

    document.addEventListener("click", function (event) {
        var viewButton = event.target.closest("[data-view]");
        if (viewButton) {
            event.preventDefault();
            setView(viewButton.getAttribute("data-view"));
            return;
        }
        var finding = event.target.closest("[data-finding-id]");
        if (finding) {
            state.selectedId = finding.getAttribute("data-finding-id");
            renderFindings();
            loadFindingDetail(state.selectedId);
            return;
        }
        var runRow = event.target.closest("[data-run-id]");
        if (runRow) {
            selectRun(runRow.getAttribute("data-run-id"));
            setView("findings");
            return;
        }
        var action = event.target.closest("[data-action]");
        if (!action) { return; }
        var name = action.getAttribute("data-action");
        if (name === "refresh") { loadAll(); }
        if (name === "start-scan") { startScan(); }
        if (name === "stop-scan") { stopScan(); }
        if (name === "apply-filter") { loadFindings(); }
        if (name === "export-json" && state.run) { window.location.href = "/api/v1/runs/" + encodeURIComponent(state.run.run_id) + "/export?format=json"; }
        if (name === "copy-submission") { copySubmission(); }
        if (name === "open-source") { openSource(); }
        if (name === "probe-provider") { probeProvider(action.getAttribute("data-provider")); }
    });

    document.addEventListener("change", function (event) {
        if (event.target.id === "run-select") { selectRun(event.target.value); }
    });

    window.addEventListener("DOMContentLoaded", function () {
        setView("overview");
        loadAll();
    });
}());
