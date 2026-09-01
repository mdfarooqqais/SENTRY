document.addEventListener("DOMContentLoaded", function () {
    // 1. Initialize clock & navigation
    updateClock();
    setInterval(updateClock, 1000);
    initNavigation();

    // 2. Initialize Charts
    initCharts();

    // 3. Initialize Control Handlers
    initControlHandlers();

    // 4. Start Live Polling & Packet Terminal Simulation
    pollLiveData();
    setInterval(pollLiveData, 2500);

    initPacketTerminal();
});

// State Store
const SENTRY = {
    monitoring: true,
    alerts: [],
    stats: {},
    autoScrollTerminal: true,
    charts: {
        traffic: null,
        attackType: null,
        protocol: null
    },
    lastAlertCount: 0
};

// -------------------------------------------------------------
// 1. DIGITAL CLOCK
// -------------------------------------------------------------
function updateClock() {
    const clock = document.getElementById("currentTime");
    if (!clock) return;
    const now = new Date();
    const hours = String(now.getHours()).padStart(2, "0");
    const minutes = String(now.getMinutes()).padStart(2, "0");
    const seconds = String(now.getSeconds()).padStart(2, "0");
    clock.textContent = `${hours}:${minutes}:${seconds}`;
}

// -------------------------------------------------------------
// 2. NAVIGATION MANAGER
// -------------------------------------------------------------
function initNavigation() {
    const navItems = document.querySelectorAll(".sidebar-nav .nav-item");
    const viewAllBtn = document.getElementById("viewAllAlertsBtn");

    const pageHeadings = {
        dashboard: { title: "Security Overview", subtitle: "Real-time network intrusion monitoring and threat prevention" },
        alerts: { title: "Alerts Management", subtitle: "Audit log and incident investigation matrix" },
        traffic: { title: "Network Traffic Telemetry", subtitle: "Live packet stream capture and throughput analyzer" },
        stats: { title: "Threat Statistics & Analytics", subtitle: "Historical attack distribution and protocol metrics" },
        ml: { title: "Machine Learning Engine", subtitle: "CICIDS2017 Trained Anomaly Detection Model Specifications" }
    };

    navItems.forEach(item => {
        item.addEventListener("click", function (e) {
            e.preventDefault();
            const tab = this.getAttribute("data-tab");
            switchTab(tab);
        });
    });

    if (viewAllBtn) {
        viewAllBtn.addEventListener("click", function () {
            switchTab("alerts");
        });
    }

    function switchTab(tabKey) {
        // Update nav item state
        navItems.forEach(nav => {
            if (nav.getAttribute("data-tab") === tabKey) {
                nav.classList.add("active");
            } else {
                nav.classList.remove("active");
            }
        });

        // Update tab views
        document.querySelectorAll(".tab-view").forEach(view => {
            view.classList.remove("active");
        });

        const targetView = document.getElementById(`view-${tabKey}`);
        if (targetView) targetView.classList.add("active");

        // Update topbar titles
        if (pageHeadings[tabKey]) {
            document.getElementById("pageTitle").textContent = pageHeadings[tabKey].title;
            document.getElementById("pageSubtitle").textContent = pageHeadings[tabKey].subtitle;
        }

        // Trigger chart resizes if switching to stats
        if (tabKey === "stats") {
            setTimeout(() => {
                if (SENTRY.charts.attackType) SENTRY.charts.attackType.resize();
                if (SENTRY.charts.protocol) SENTRY.charts.protocol.resize();
            }, 100);
        }
    }
}

// -------------------------------------------------------------
// 3. CHART.JS INITIALIZATION
// -------------------------------------------------------------
function initCharts() {
    // 3.1 Live Traffic Line Chart
    const ctxTraffic = document.getElementById("liveTrafficChart");
    if (ctxTraffic) {
        SENTRY.charts.traffic = new Chart(ctxTraffic, {
            type: "line",
            data: {
                labels: ["12:00:00", "12:00:03", "12:00:06", "12:00:09", "12:00:12", "12:00:15"],
                datasets: [
                    {
                        label: "Normal Traffic (PPS)",
                        data: [150, 180, 210, 195, 230, 210],
                        borderColor: "#36e0a1",
                        backgroundColor: "rgba(54, 224, 161, 0.08)",
                        fill: true,
                        tension: 0.4,
                        borderWidth: 2,
                        pointRadius: 3
                    },
                    {
                        label: "Suspicious / Anomaly (PPS)",
                        data: [12, 5, 28, 14, 8, 35],
                        borderColor: "#ff5364",
                        backgroundColor: "rgba(255, 83, 100, 0.08)",
                        fill: true,
                        tension: 0.4,
                        borderWidth: 2,
                        pointRadius: 3
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        labels: { color: "#cbd5e1", font: { family: "Inter", size: 11, weight: "bold" } }
                    }
                },
                scales: {
                    x: {
                        grid: { color: "rgba(30, 44, 64, 0.7)" },
                        ticks: { color: "#94a3b8", font: { family: "Inter", size: 10 } }
                    },
                    y: {
                        grid: { color: "rgba(30, 44, 64, 0.7)" },
                        ticks: { color: "#94a3b8", font: { family: "Inter", size: 10 } }
                    }
                }
            }
        });
    }

    // 3.2 Threat Type Donut Chart
    const ctxAttack = document.getElementById("attackTypeChart");
    if (ctxAttack) {
        SENTRY.charts.attackType = new Chart(ctxAttack, {
            type: "doughnut",
            data: {
                labels: ["Port Scan", "Telnet Suspicious", "DoS Flood Anomaly", "FTP Brute Force", "SMB Exec Pattern"],
                datasets: [{
                    data: [4, 2, 3, 2, 1],
                    backgroundColor: ["#5d8cff", "#ffbd59", "#ff5364", "#36e0a1", "#a060ff"],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { position: "right", labels: { color: "#f1f5f9", font: { family: "Inter", size: 11, weight: "bold" } } }
                }
            }
        });
    }

    // 3.3 Protocol Distribution Bar Chart
    const ctxProto = document.getElementById("protocolChart");
    if (ctxProto) {
        SENTRY.charts.protocol = new Chart(ctxProto, {
            type: "bar",
            data: {
                labels: ["TCP", "UDP", "HTTP", "ICMP"],
                datasets: [{
                    label: "Packets Captured",
                    data: [8400, 3200, 2100, 580],
                    backgroundColor: ["#36e0a1", "#5d8cff", "#ffbd59", "#94a3b8"],
                    borderRadius: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    x: { grid: { display: false }, ticks: { color: "#cbd5e1", font: { weight: "bold" } } },
                    y: { grid: { color: "rgba(30, 44, 64, 0.7)" }, ticks: { color: "#94a3b8" } }
                }
            }
        });
    }
}

// -------------------------------------------------------------
// 4. LIVE POLLING & DATA UPDATES
// -------------------------------------------------------------
async function pollLiveData() {
    try {
        // 4.1 Fetch Overall Stats
        const resStats = await fetch("/api/stats");
        const statsData = await resStats.json();

        if (statsData.status === "success") {
            SENTRY.stats = statsData;
            document.getElementById("statPackets").textContent = statsData.total_packets.toLocaleString();
            document.getElementById("statAlerts").textContent = statsData.total_alerts;
            document.getElementById("statAttacks").textContent = statsData.attack_count;
            document.getElementById("sidebarAlertBadge").textContent = statsData.high_count > 0 ? statsData.high_count : statsData.total_alerts;

            // Engine status updates
            const isMonitoring = statsData.engine_state.monitoring;
            SENTRY.monitoring = isMonitoring;
            updateEngineUIState(isMonitoring);

            // Update Donut & Bar Charts
            updateAnalyticsCharts(statsData);
        }

        // 4.2 Fetch Real-Time Traffic Graph Data
        const resTraffic = await fetch("/api/traffic");
        const trafficData = await resTraffic.json();

        if (trafficData.status === "success" && SENTRY.charts.traffic) {
            SENTRY.charts.traffic.data.labels = trafficData.timestamps;
            SENTRY.charts.traffic.data.datasets[0].data = trafficData.normal_packets;
            SENTRY.charts.traffic.data.datasets[1].data = trafficData.suspicious_packets;
            SENTRY.charts.traffic.update("none");

            document.getElementById("trafficPps").textContent = `${trafficData.current_pps} PPS`;
            document.getElementById("trafficBandwidth").textContent = `${trafficData.bandwidth_mbps} MB/s`;
        }

        // 4.3 Fetch Alerts
        const searchVal = document.getElementById("alertSearchInput") ? document.getElementById("alertSearchInput").value : "";
        const severityVal = document.getElementById("severityFilter") ? document.getElementById("severityFilter").value : "ALL";

        let url = "/api/alerts?limit=100";
        if (severityVal !== "ALL") url += `&severity=${severityVal}`;
        if (searchVal.trim() !== "") url += `&search=${encodeURIComponent(searchVal.trim())}`;

        const resAlerts = await fetch(url);
        const alertsData = await resAlerts.json();

        if (alertsData.status === "success") {
            SENTRY.alerts = alertsData.alerts;

            // Check if new alert arrived to trigger toast
            if (SENTRY.alerts.length > SENTRY.lastAlertCount && SENTRY.lastAlertCount > 0) {
                const newest = SENTRY.alerts[0];
                if (newest && newest.severity === "HIGH") {
                    triggerThreatToast(newest);
                }
            }
            SENTRY.lastAlertCount = SENTRY.alerts.length;

            renderAlertsTables(SENTRY.alerts);
        }

    } catch (err) {
        console.error("SENTRY Polling error:", err);
    }
}

// Update Charts on Analytics Tab
function updateAnalyticsCharts(stats) {
    if (stats.attack_types && SENTRY.charts.attackType) {
        const labels = Object.keys(stats.attack_types);
        const values = Object.values(stats.attack_types);
        if (labels.length > 0) {
            SENTRY.charts.attackType.data.labels = labels;
            SENTRY.charts.attackType.data.datasets[0].data = values;
            SENTRY.charts.attackType.update("none");
        }
    }

    if (stats.protocols && SENTRY.charts.protocol) {
        const labels = Object.keys(stats.protocols);
        const values = Object.values(stats.protocols);
        if (labels.length > 0) {
            SENTRY.charts.protocol.data.labels = labels;
            SENTRY.charts.protocol.data.datasets[0].data = values;
            SENTRY.charts.protocol.update("none");
        }
    }
}

// -------------------------------------------------------------
// 5. ALERT TABLES RENDERING
// -------------------------------------------------------------
function renderAlertsTables(alerts) {
    const dashTbody = document.getElementById("dashboardAlertsTbody");
    const fullTbody = document.getElementById("fullAlertsTbody");
    const filterCount = document.getElementById("filteredAlertCount");

    if (filterCount) filterCount.textContent = alerts.length;

    if (alerts.length === 0) {
        const emptyRow = `<tr><td colspan="10" class="text-center text-slate-300 py-4"><i class="fa-solid fa-shield me-2"></i> No security alerts match criteria.</td></tr>`;
        if (dashTbody) dashTbody.innerHTML = emptyRow;
        if (fullTbody) fullTbody.innerHTML = emptyRow;
        return;
    }

    // Dashboard Preview (top 5)
    if (dashTbody) {
        const topAlerts = alerts.slice(0, 5);
        dashTbody.innerHTML = topAlerts.map(alert => `
            <tr>
                <td class="text-nowrap text-slate-300">${alert.timestamp}</td>
                <td class="fw-bold text-accent">${alert.source_ip}:${alert.source_port}</td>
                <td class="text-slate-200">${alert.destination_ip}:${alert.destination_port}</td>
                <td><span class="badge bg-dark border border-secondary text-slate-200">${alert.protocol}</span></td>
                <td><span class="badge-layer">${alert.detection_type}</span></td>
                <td class="fw-bold text-light">${alert.attack_type}</td>
                <td>${getSeverityBadge(alert.severity)}</td>
                <td class="text-slate-200">${(alert.confidence * 100).toFixed(0)}%</td>
                <td>
                    <button class="btn btn-sm btn-outline-info py-0 px-2 text-slate-200" onclick="inspectAlert(${alert.id})">
                        <i class="fa-solid fa-eye"></i>
                    </button>
                </td>
            </tr>
        `).join("");
    }

    // Full Alerts View Table
    if (fullTbody) {
        fullTbody.innerHTML = alerts.map(alert => `
            <tr>
                <td class="text-slate-300">#${alert.id}</td>
                <td class="text-nowrap text-slate-300">${alert.timestamp}</td>
                <td class="fw-bold text-accent">${alert.source_ip}:${alert.source_port}</td>
                <td class="text-slate-200">${alert.destination_ip}:${alert.destination_port}</td>
                <td><span class="badge bg-dark border border-secondary text-slate-200">${alert.protocol}</span></td>
                <td><span class="badge-layer">${alert.detection_type}</span></td>
                <td class="fw-bold text-light">${alert.attack_type}</td>
                <td>${getSeverityBadge(alert.severity)}</td>
                <td>
                    <div class="progress bg-dark" style="height: 6px; width: 60px;">
                        <div class="progress-bar ${alert.severity === 'HIGH' ? 'bg-danger' : 'bg-warning'}" style="width: ${(alert.confidence * 100)}%"></div>
                    </div>
                    <small class="text-slate-300" style="font-size: 9.5px; font-weight: 600;">${(alert.confidence * 100).toFixed(0)}%</small>
                </td>
                <td>
                    <button class="btn btn-sm btn-outline-accent py-0 px-2" onclick="inspectAlert(${alert.id})">
                        Inspect
                    </button>
                </td>
            </tr>
        `).join("");
    }
}

function getSeverityBadge(severity) {
    const s = severity ? severity.toUpperCase() : "LOW";
    if (s === "HIGH") return `<span class="badge-sev badge-sev-high"><i class="fa-solid fa-circle-exclamation me-1"></i>HIGH</span>`;
    if (s === "MEDIUM") return `<span class="badge-sev badge-sev-medium"><i class="fa-solid fa-triangle-exclamation me-1"></i>MED</span>`;
    return `<span class="badge-sev badge-sev-low"><i class="fa-solid fa-info-circle me-1"></i>LOW</span>`;
}

// Inspect Packet Modal
window.inspectAlert = function (alertId) {
    const alert = SENTRY.alerts.find(a => a.id === alertId);
    if (!alert) return;

    const modalContent = document.getElementById("modalBodyContent");
    if (!modalContent) return;

    modalContent.innerHTML = `
        <div class="row g-3">
            <div class="col-md-6">
                <div class="p-3 bg-dark-soft rounded border border-secondary">
                    <div class="text-slate-300 small fw-bold">Attack Classification</div>
                    <div class="fs-5 fw-bold text-danger mt-1">${alert.attack_type}</div>
                    <div class="mt-2">${getSeverityBadge(alert.severity)} <span class="ms-2 badge bg-secondary text-slate-100">${alert.detection_type}</span></div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="p-3 bg-dark-soft rounded border border-secondary">
                    <div class="text-slate-300 small fw-bold">Detection Confidence</div>
                    <div class="fs-5 fw-bold text-accent mt-1">${(alert.confidence * 100).toFixed(1)}%</div>
                    <div class="text-slate-300 small mt-1">Logged at: ${alert.timestamp}</div>
                </div>
            </div>
            <div class="col-12">
                <h6 class="text-light fw-bold mt-2"><i class="fa-solid fa-network-wired text-accent me-2"></i> 5-Tuple Network Header Details</h6>
                <table class="table table-dark table-sm border border-secondary mb-0">
                    <tr><td class="text-slate-300">Source IP:Port</td><td class="font-monospace text-accent fw-bold">${alert.source_ip}:${alert.source_port}</td></tr>
                    <tr><td class="text-slate-300">Destination IP:Port</td><td class="font-monospace text-slate-100">${alert.destination_ip}:${alert.destination_port}</td></tr>
                    <tr><td class="text-slate-300">Transport Protocol</td><td class="text-slate-100">${alert.protocol}</td></tr>
                    <tr><td class="text-slate-300">Primary Layer</td><td class="text-slate-100">${alert.detection_type} Engine</td></tr>
                </table>
            </div>
            <div class="col-12">
                <h6 class="text-light fw-bold mt-2"><i class="fa-solid fa-user-shield me-2 text-warning"></i> Security Analyst Action Plan</h6>
                <div class="p-3 bg-dark-soft border border-warning rounded text-warning small fw-medium">
                    <i class="fa-solid fa-triangle-exclamation me-1"></i> Recommended Mitigation: Implement temporary firewall rule blocking <strong>${alert.source_ip}</strong> on port <strong>${alert.destination_port}</strong>.
                </div>
            </div>
        </div>
    `;

    const modalEl = document.getElementById("alertDetailModal");
    if (modalEl) {
        const bsModal = new bootstrap.Modal(modalEl);
        bsModal.show();
    }
};

// -------------------------------------------------------------
// 6. CONTROL BUTTON HANDLERS
// -------------------------------------------------------------
function initControlHandlers() {
    // 6.1 Toggle Monitoring
    const toggleBtn = document.getElementById("toggleMonitoringBtn");
    if (toggleBtn) {
        toggleBtn.addEventListener("click", async function () {
            const res = await fetch("/api/engine/toggle", { method: "POST" });
            const data = await res.json();
            if (data.status === "success") {
                updateEngineUIState(data.monitoring);
            }
        });
    }

    // 6.2 Simulate Attack
    const simBtn = document.getElementById("simulateAttackBtn");
    if (simBtn) {
        simBtn.addEventListener("click", async function () {
            simBtn.disabled = true;
            simBtn.innerHTML = `<i class="fa-solid fa-spinner fa-spin me-1"></i> Injecting...`;
            await fetch("/api/alerts/simulate", { method: "POST" });
            setTimeout(() => {
                simBtn.disabled = false;
                simBtn.innerHTML = `<i class="fa-solid fa-bolt me-1"></i> Simulate Attack`;
                pollLiveData();
            }, 600);
        });
    }

    // 6.3 Clear Alerts
    const clearBtn = document.getElementById("clearAlertsBtn");
    if (clearBtn) {
        clearBtn.addEventListener("click", async function () {
            if (confirm("Are you sure you want to clear all alerts from the SQLite database?")) {
                await fetch("/api/alerts/clear", { method: "POST" });
                pollLiveData();
            }
        });
    }

    // 6.4 Export CSV
    const exportBtn = document.getElementById("exportCsvBtn");
    if (exportBtn) {
        exportBtn.addEventListener("click", function () {
            if (SENTRY.alerts.length === 0) {
                alert("No alerts available to export.");
                return;
            }
            let csv = "ID,Timestamp,Source_IP,Source_Port,Dest_IP,Dest_Port,Protocol,Detection_Engine,Attack_Type,Severity,Confidence\n";
            SENTRY.alerts.forEach(a => {
                csv += `${a.id},"${a.timestamp}",${a.source_ip},${a.source_port},${a.destination_ip},${a.destination_port},${a.protocol},"${a.detection_type}","${a.attack_type}",${a.severity},${a.confidence}\n`;
            });
            const blob = new Blob([csv], { type: "text/csv" });
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = `sentry_security_report_${new Date().toISOString().slice(0, 10)}.csv`;
            a.click();
        });
    }

    // 6.5 Filters Input
    const searchInput = document.getElementById("alertSearchInput");
    const severitySelect = document.getElementById("severityFilter");
    if (searchInput) searchInput.addEventListener("input", () => pollLiveData());
    if (severitySelect) severitySelect.addEventListener("change", () => pollLiveData());
}

// UI State Updater
function updateEngineUIState(isMonitoring) {
    const toggleBtnText = document.getElementById("toggleBtnText");
    const toggleBtn = document.getElementById("toggleMonitoringBtn");
    const liveDot = document.getElementById("liveDot");
    const liveLabel = document.getElementById("liveStatusLabel");
    const bannerStatus = document.getElementById("bannerStatusText");
    const sidebarStatusDot = document.getElementById("sidebarStatusDot");
    const sidebarStatusText = document.getElementById("sidebarStatusText");

    if (isMonitoring) {
        if (toggleBtnText) toggleBtnText.textContent = "Pause";
        if (toggleBtn) {
            toggleBtn.classList.remove("btn-outline-success");
            toggleBtn.classList.add("btn-sentry-primary");
            toggleBtn.querySelector("i").className = "fa-solid fa-pause me-1";
        }
        if (liveDot) liveDot.classList.remove("paused");
        if (liveLabel) liveLabel.textContent = "LIVE";
        if (bannerStatus) bannerStatus.textContent = "MONITORING ACTIVE";
        if (sidebarStatusDot) sidebarStatusDot.className = "status-dot green";
        if (sidebarStatusText) {
            sidebarStatusText.textContent = "ONLINE";
            sidebarStatusText.className = "engine-state text-success";
        }
    } else {
        if (toggleBtnText) toggleBtnText.textContent = "Resume";
        if (toggleBtn) {
            toggleBtn.classList.remove("btn-sentry-primary");
            toggleBtn.classList.add("btn-outline-success");
            toggleBtn.querySelector("i").className = "fa-solid fa-play me-1";
        }
        if (liveDot) liveDot.classList.add("paused");
        if (liveLabel) liveLabel.textContent = "PAUSED";
        if (bannerStatus) bannerStatus.textContent = "MONITORING PAUSED";
        if (sidebarStatusDot) sidebarStatusDot.className = "status-dot red";
        if (sidebarStatusText) {
            sidebarStatusText.textContent = "PAUSED";
            sidebarStatusText.className = "engine-state text-danger";
        }
    }
}

// Trigger Toast Alert
function triggerThreatToast(alertData) {
    const toastMsg = document.getElementById("toastMessage");
    if (toastMsg) {
        toastMsg.textContent = `${alertData.attack_type} from ${alertData.source_ip} detected via ${alertData.detection_type}.`;
    }
    const toastEl = document.getElementById("threatToast");
    if (toastEl) {
        const bsToast = new bootstrap.Toast(toastEl);
        bsToast.show();
    }
}

// -------------------------------------------------------------
// 7. LIVE PACKET STREAM TERMINAL SIMULATION
// -------------------------------------------------------------
function initPacketTerminal() {
    const terminal = document.getElementById("packetTerminal");
    const autoScrollBtn = document.getElementById("autoScrollToggle");
    const clearTermBtn = document.getElementById("clearTerminalBtn");

    if (autoScrollBtn) {
        autoScrollBtn.addEventListener("click", function () {
            SENTRY.autoScrollTerminal = !SENTRY.autoScrollTerminal;
            autoScrollBtn.innerHTML = `<i class="fa-solid fa-down-long me-1"></i> Auto-Scroll: ${SENTRY.autoScrollTerminal ? 'ON' : 'OFF'}`;
        });
    }

    if (clearTermBtn && terminal) {
        clearTermBtn.addEventListener("click", function () {
            terminal.innerHTML = `<div class="terminal-line system">[SENTRY TERMINAL] Log cleared. Listening for new packets...</div>`;
        });
    }

    const sampleIPs = ["192.168.1.105", "10.0.0.45", "172.16.0.12", "192.168.1.110", "192.168.1.50", "10.0.0.88"];
    const protocols = ["TCP", "UDP", "HTTP", "DNS"];

    setInterval(() => {
        if (!SENTRY.monitoring || !terminal) return;

        const src = sampleIPs[Math.floor(Math.random() * sampleIPs.length)];
        const proto = protocols[Math.floor(Math.random() * protocols.length)];
        const srcPort = Math.floor(Math.random() * 40000) + 10000;
        const dstPort = [80, 443, 22, 53, 3389][Math.floor(Math.random() * 5)];
        const len = Math.floor(Math.random() * 1200) + 64;
        const ts = new Date().toISOString().slice(11, 19);

        const line = document.createElement("div");
        line.className = "terminal-line normal";
        line.textContent = `[${ts}] ${proto} ${src}:${srcPort} -> 10.0.0.1:${dstPort} [LEN ${len}b] FLAGS=[SYN] SENTRY_EVAL=BENIGN`;

        terminal.appendChild(line);

        if (terminal.children.length > 100) {
            terminal.removeChild(terminal.children[0]);
        }

        if (SENTRY.autoScrollTerminal) {
            terminal.scrollTop = terminal.scrollHeight;
        }
    }, 1500);
}
