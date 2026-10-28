/**
 * Website Security & Threat Intelligence Analyzer
 * Client-Side Interactive Behaviors
 */

document.addEventListener("DOMContentLoaded", function () {
    // 1. Scan Progress Animation Handler
    const scanForm = document.getElementById("scanForm");
    const progressModalEl = document.getElementById("scanProgressModal");
    let progressModal = null;

    if (progressModalEl && typeof bootstrap !== "undefined") {
        progressModal = new bootstrap.Modal(progressModalEl, {
            backdrop: "static",
            keyboard: false
        });
    }

    if (scanForm && progressModal) {
        scanForm.addEventListener("submit", function () {
            progressModal.show();
            startProgressAnimation();
        });
    }

    function startProgressAnimation() {
        const steps = [
            { id: "step-1", delay: 400, text: "Validating Target URL & Enforcing SSRF Restrictions..." },
            { id: "step-2", delay: 1200, text: "Resolving DNS Records & Network Interfaces..." },
            { id: "step-3", delay: 2000, text: "Inspecting SSL/TLS Handshake & Certificate Chains..." },
            { id: "step-4", delay: 2800, text: "Auditing HTTP Headers & Cookie Configurations..." },
            { id: "step-5", delay: 3600, text: "Querying Threat Intelligence Feeds & Heuristics..." },
            { id: "step-6", delay: 4400, text: "Executing Authorized Port & Service Probing..." },
            { id: "step-7", delay: 5200, text: "Synthesizing Findings & Calculating Risk Score..." }
        ];

        steps.forEach(function (step) {
            setTimeout(function () {
                const el = document.getElementById(step.id);
                if (el) {
                    el.classList.remove("text-muted");
                    el.classList.add("active");
                    const icon = el.querySelector(".step-status-icon");
                    if (icon) {
                        icon.innerHTML = `<span class="spinner-border spinner-border-sm text-info" role="status"></span>`;
                    }
                }
            }, step.delay);

            setTimeout(function () {
                const el = document.getElementById(step.id);
                if (el) {
                    el.classList.remove("active");
                    el.classList.add("completed");
                    const icon = el.querySelector(".step-status-icon");
                    if (icon) {
                        icon.innerHTML = `<i class="bi bi-check-circle-fill text-success"></i>`;
                    }
                }
            }, step.delay + 700);
        });
    }

    // 2. Findings Severity Filter (Results Page)
    const filterButtons = document.querySelectorAll(".btn-filter-sev");
    const findingCards = document.querySelectorAll(".finding-card");

    if (filterButtons.length > 0 && findingCards.length > 0) {
        filterButtons.forEach(btn => {
            btn.addEventListener("click", function () {
                filterButtons.forEach(b => b.classList.remove("active"));
                this.classList.add("active");
                const targetSev = this.getAttribute("data-sev");

                findingCards.forEach(card => {
                    const cardSev = card.getAttribute("data-sev");
                    if (targetSev === "all" || cardSev === targetSev) {
                        card.style.display = "block";
                    } else {
                        card.style.display = "none";
                    }
                });
            });
        });
    }

    // 3. Scan History Live Search
    const historySearch = document.getElementById("historySearchInput");
    const historyRows = document.querySelectorAll(".history-row");

    if (historySearch && historyRows.length > 0) {
        historySearch.addEventListener("input", function () {
            const query = this.value.toLowerCase().trim();
            historyRows.forEach(row => {
                const domain = (row.getAttribute("data-domain") || "").toLowerCase();
                const ip = (row.getAttribute("data-ip") || "").toLowerCase();
                if (domain.includes(query) || ip.includes(query)) {
                    row.style.display = "";
                } else {
                    row.style.display = "none";
                }
            });
        });
    }

    // 4. Copy-to-Clipboard Helpers
    const copyBtns = document.querySelectorAll(".btn-copy");
    copyBtns.forEach(btn => {
        btn.addEventListener("click", function () {
            const targetText = this.getAttribute("data-clipboard-text");
            if (targetText && navigator.clipboard) {
                navigator.clipboard.writeText(targetText).then(() => {
                    const originalHtml = this.innerHTML;
                    this.innerHTML = `<i class="bi bi-check2"></i> Copied!`;
                    setTimeout(() => {
                        this.innerHTML = originalHtml;
                    }, 1800);
                });
            }
        });
    });

    // 5. Port Scan Authorization Checkbox Enabler
    const authCheckbox = document.getElementById("authorize_port_scan");
    const portInputsContainer = document.getElementById("portScanOptions");

    if (authCheckbox && portInputsContainer) {
        authCheckbox.addEventListener("change", function () {
            if (this.checked) {
                portInputsContainer.classList.remove("opacity-50");
                const input = portInputsContainer.querySelector("input");
                if (input) input.disabled = false;
            } else {
                portInputsContainer.classList.add("opacity-50");
                const input = portInputsContainer.querySelector("input");
                if (input) input.disabled = true;
            }
        });
    }
});
