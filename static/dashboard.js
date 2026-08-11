/* Dashboard Interactive Logic for Secure Online Examination Monitoring System */

// ── Module 2 Real-Time SocketIO setup ────────────────────────────────────────
const m2socket = (typeof io !== "undefined") ? io() : null;
let m2PacketBuffer = [];        // Incoming packet queue (flushed to DOM every frame)
let m2RowCount = 0;             // Total rows currently in the packet table
let m2TotalCount = 0;           // All-time packet counter
let m2DnsCount = 0;             // DNS query counter
let m2HandshakeRows = {};       // key -> TR element reference for in-place update
const M2_MAX_ROWS = 500;        // Maximum rows displayed in browser
let m2FlushScheduled = false;   // rAF flush guard

document.addEventListener("DOMContentLoaded", () => {
    initTabNavigation();
    loadOverviewData();
    loadModule1Data();
    loadModule2Data();      // loads saved JSON on initial page load
    loadModule3Data();
    loadPhase4Data();
    m2LoadInterfaces();     // populate interface dropdown
    m2InitSocketHandlers(); // register SocketIO listeners
});

let protocolChartInstance = null;
let portChartInstance = null;

// Tab Navigation Switching
function initTabNavigation() {
    const navButtons = document.querySelectorAll(".nav-btn");
    const tabContents = document.querySelectorAll(".tab-content");

    navButtons.forEach(btn => {
        btn.addEventListener("click", () => {
            const targetTab = btn.getAttribute("data-tab");

            navButtons.forEach(b => b.classList.remove("active"));
            tabContents.forEach(c => c.classList.remove("active"));

            btn.classList.add("active");
            const activeContent = document.getElementById(targetTab);
            if (activeContent) activeContent.classList.add("active");

            // Refresh charts when switching tabs
            if (targetTab === 'overview') {
                loadOverviewData();
            }
        });
    });
}

// Toast Notifications
function showToast(message, type = "info") {
    const toast = document.getElementById("toast");
    toast.textContent = message;
    toast.classList.remove("hidden");
    setTimeout(() => {
        toast.classList.add("hidden");
    }, 3500);
}

// Global Refresh
function refreshAllData() {
    showToast("Refreshing exam monitoring data...");
    loadOverviewData();
    loadModule1Data();
    loadModule2Data();
    loadModule3Data();
    loadPhase4Data();
}

// TAB 1: Overview Data Loader
function loadOverviewData() {
    fetch("/api/overview")
        .then(res => res.json())
        .then(data => {
            document.getElementById("kpi-hosts").textContent = data.total_hosts || 0;
            document.getElementById("kpi-packets").textContent = data.total_packets || 0;

            if (data.candidate_url) {
                const headerUrl = document.getElementById("headerCandidateUrl");
                if (headerUrl) {
                    headerUrl.href = data.candidate_url;
                    headerUrl.textContent = data.candidate_url;
                }
            }
            
            const mac = data.mac_status || {};
            document.getElementById("kpi-mac-status").textContent = mac.is_spoofed ? "SUSPICIOUS" : "VERIFIED";
            document.getElementById("kpi-mac-addr").textContent = mac.current_mac || "N/A";
            
            const sec = data.security_summary || {};
            document.getElementById("kpi-sec-score").textContent = `${sec.security_score || 85} / 100`;
            document.getElementById("kpi-vuln-count").textContent = `${sec.unnecessary_open_ports_count || 0} Prohibited Open Ports`;

            renderProtocolChart(data.protocol_summary || {});
        })
        .catch(err => console.error("Error loading overview:", err));
}

function renderProtocolChart(protoSummary) {
    const ctx = document.getElementById("overviewProtocolChart");
    if (!ctx) return;

    const labels = Object.keys(protoSummary);
    const values = Object.values(protoSummary);

    if (protocolChartInstance) {
        protocolChartInstance.destroy();
    }

    protocolChartInstance = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels.length ? labels : ['TCP', 'UDP', 'DNS', 'HTTP', 'ICMP'],
            datasets: [{
                data: values.length ? values : [4, 1, 2, 1, 2],
                backgroundColor: ['#3b82f6', '#8b5cf6', '#06b6d4', '#f59e0b', '#ef4444'],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { position: 'right', labels: { color: '#9ca3af' } }
            }
        }
    });
}

function renderPortChart(hostsData) {
    const ctx = document.getElementById("overviewPortChart");
    if (!ctx) return;

    const portCounts = {};
    hostsData.forEach(h => {
        (h.ports || []).forEach(p => {
            const key = `${p.port} (${p.service})`;
            portCounts[key] = (portCounts[key] || 0) + 1;
        });
    });

    const labels = Object.keys(portCounts);
    const values = Object.values(portCounts);

    if (portChartInstance) {
        portChartInstance.destroy();
    }

    portChartInstance = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Occurrences Across Exam Subnet',
                data: values,
                backgroundColor: '#06b6d4',
                borderRadius: 6
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: { ticks: { color: '#9ca3af' } },
                y: { ticks: { color: '#9ca3af', stepSize: 1 } }
            },
            plugins: {
                legend: { display: false }
            }
        }
    });
}


// TAB 2: Module 1 Network Discovery
let currentNetInfo = null;
let activeEventSource = null;

function loadNetworkInfo() {
    fetch("/api/network-info")
        .then(res => res.json())
        .then(net => {
            currentNetInfo = net;
            document.getElementById("net-ip").textContent = net.local_ip || "127.0.0.1";
            document.getElementById("net-gw").textContent = net.default_gateway || "None";
            document.getElementById("net-mask").textContent = net.subnet_mask || "255.255.255.0";
            document.getElementById("net-cidr").textContent = net.subnet_cidr || "192.168.1.0/24";
            
            const tgtInput = document.getElementById("targetSubnet");
            if (tgtInput && (!tgtInput.value || tgtInput.value === "127.0.0.1" || tgtInput.value === "192.168.1.0/24")) {
                tgtInput.value = net.subnet_cidr || "192.168.160.0/19";
            }
        });
}

function setTargetQuick(type) {
    if (!currentNetInfo) return;
    const tgtInput = document.getElementById("targetSubnet");
    if (!tgtInput) return;
    
    if (type === 'cidr') tgtInput.value = currentNetInfo.subnet_cidr;
    else if (type === 'gw') tgtInput.value = currentNetInfo.default_gateway || currentNetInfo.local_ip;
    else if (type === 'ip') tgtInput.value = currentNetInfo.local_ip;
}

function viewRawIpconfig() {
    showToast("Retrieving raw ipconfig output...");
    fetch("/api/network-info")
        .then(res => res.json())
        .then(net => {
            const consoleElem = document.getElementById("nmapTerminalConsole");
            consoleElem.textContent = `$ ipconfig\n\n${net.raw_ipconfig || 'No ipconfig output returned.'}`;
            document.getElementById("m1-engine-badge").textContent = "ipconfig";
        });
}

function updateDiscoveredHostDropdown(hosts) {
    const select = document.getElementById("discoveredIpSelect");
    if (!select) return;
    
    const currentVal = select.value;
    select.innerHTML = '<option value="">-- Select Discovered Active Host --</option>';

    if (!hosts || hosts.length === 0) {
        select.innerHTML = '<option value="">(No active hosts found yet)</option>';
        return;
    }

    hosts.forEach(h => {
        const opt = document.createElement("option");
        opt.value = h.ip;
        opt.textContent = `${h.ip} (${h.hostname}) ${h.mac_address !== 'N/A' ? '- MAC: ' + h.mac_address : ''}`;
        if (h.ip === currentVal) opt.selected = true;
        select.appendChild(opt);
    });
}

function updateProgressBar(percent, statusTitle) {
    const pBar = document.getElementById("scanProgressBar");
    const pBadge = document.getElementById("scanPercentBadge");
    const sTitle = document.getElementById("scanStatusTitle");
    const spinner = document.getElementById("scanSpinner");

    const clampPct = Math.min(100, Math.max(0, parseFloat(percent) || 0)).toFixed(1);
    
    if (pBar) pBar.style.width = `${clampPct}%`;
    if (pBadge) pBadge.textContent = `${clampPct}%`;

    if (sTitle && statusTitle) sTitle.textContent = statusTitle;

    if (spinner) {
        spinner.style.display = (clampPct > 0 && clampPct < 100) ? "inline-block" : "none";
    }
}

function renderScanResults(data) {
    if (!data) return;

    if (data.timestamp) {
        const scanTimeElem = document.getElementById("m1-scan-time");
        if (scanTimeElem) scanTimeElem.textContent = new Date(data.timestamp).toLocaleTimeString();
    }

    const engineElem = document.getElementById("m1-engine-badge");
    if (engineElem) engineElem.textContent = data.scan_mode || "Live Real Nmap";

    if (data.terminal_output) {
        const consoleElem = document.getElementById("nmapTerminalConsole");
        if (consoleElem) consoleElem.textContent = data.terminal_output;
    }

    updateDiscoveredHostDropdown(data.hosts || []);

    const hostsGrid = document.getElementById("hostsGrid");
    if (hostsGrid) {
        hostsGrid.innerHTML = "";
        (data.hosts || []).forEach(host => {
            const card = document.createElement("div");
            card.className = "host-card";

            let portsHtml = "";
            (host.ports || []).forEach(p => {
                portsHtml += `
                    <div class="port-pill">
                        <span class="port-num">Port ${p.port}/${p.protocol}</span>
                        <span>${p.service} (${p.version})</span>
                    </div>
                `;
            });

            card.innerHTML = `
                <div class="host-header">
                    <span class="host-ip">${host.ip}</span>
                    <span class="host-status">${host.status.toUpperCase()}</span>
                </div>
                <div class="host-details">
                    <div><strong>Hostname:</strong> ${host.hostname}</div>
                    <div><strong>MAC Address:</strong> ${host.mac_address}</div>
                    <div><strong>Vendor / Hardware:</strong> ${host.vendor}</div>
                    <div><strong>Detected OS:</strong> ${host.os_details}</div>
                </div>
                <h4>Open Services (${(host.ports || []).length}):</h4>
                <div class="ports-list" style="margin-top: 0.5rem;">
                    ${portsHtml || '<p style="color:#9ca3af;">No open ports detected.</p>'}
                </div>
            `;
            hostsGrid.appendChild(card);
        });
    }

    renderPortChart(data.hosts || []);
}

let commandHistoryList = [];

function loadCommandHistory() {
    fetch("/api/module1/history")
        .then(res => res.json())
        .then(data => {
            commandHistoryList = data || [];
            const tbody = document.getElementById("commandHistoryTableBody");
            if (!tbody) return;

            if (commandHistoryList.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; color:#9ca3af;">No command history logged yet. Run a step command above to generate logs.</td></tr>';
                return;
            }

            tbody.innerHTML = "";
            commandHistoryList.forEach((item, idx) => {
                const tr = document.createElement("tr");
                tr.innerHTML = `
                    <td><strong>#${item.id || (idx + 1)}</strong></td>
                    <td style="font-size:0.8rem; color:#9ca3af;">${item.timestamp}</td>
                    <td><code style="color:#00ff66;">${item.command_executed}</code></td>
                    <td><span class="badge badge-info">${item.target}</span></td>
                    <td><span class="badge badge-success">${item.total_hosts} host(s)</span></td>
                    <td>
                        <button class="btn btn-secondary" style="padding: 0.2rem 0.5rem; font-size: 0.75rem;" onclick="viewHistoryLog(${idx})">
                            <i class="fa-solid fa-terminal"></i> View Output
                        </button>
                    </td>
                `;
                tbody.appendChild(tr);
            });
        })
        .catch(err => console.error("Error loading command history:", err));
}

function viewHistoryLog(index) {
    if (commandHistoryList[index] && commandHistoryList[index].terminal_output) {
        const item = commandHistoryList[index];
        const consoleElem = document.getElementById("nmapTerminalConsole");
        consoleElem.textContent = item.terminal_output;
        document.getElementById("m1-engine-badge").textContent = `History: ${item.command_executed}`;
        showToast(`Loaded terminal log for #${item.id} (${item.command_executed})`);
        consoleElem.scrollIntoView({ behavior: 'smooth' });
    }
}

function clearCommandHistoryLog() {
    if (confirm("Are you sure you want to clear all command history logs?")) {
        fetch("/api/module1/history", { method: "DELETE" })
            .then(res => res.json())
            .then(() => {
                showToast("Command history cleared!");
                loadCommandHistory();
            });
    }
}

function loadModule1Data() {
    loadNetworkInfo();
    loadCommandHistory();
    fetch("/api/module1/scan")
        .then(res => res.json())
        .then(data => {
            renderScanResults(data);
        })
        .catch(err => console.error("Error loading Module 1:", err));
}

function fetchTerminalLog() {
    fetch("/api/module1/terminal")
        .then(res => res.json())
        .then(data => {
            if (data.terminal_output) {
                document.getElementById("nmapTerminalConsole").textContent = data.terminal_output;
            }
        });
}

function executeNmapCmd(cmdType) {
    const targetInput = document.getElementById("targetSubnet");
    const target = (targetInput && targetInput.value) ? targetInput.value.trim() : "127.0.0.1";

    showToast(`Initiating Nmap ${cmdType.replace('_', ' ').toUpperCase()} on ${target}...`);

    if (activeEventSource) {
        activeEventSource.close();
        activeEventSource = null;
    }

    updateProgressBar(0.0, `Executing ${cmdType.replace('_', ' ').toUpperCase()}...`);

    const consoleElem = document.getElementById("nmapTerminalConsole");
    consoleElem.textContent = `$ Initializing live stream on ${target}...\n`;

    const streamUrl = `/api/module1/stream-scan?cmd_type=${encodeURIComponent(cmdType)}&target=${encodeURIComponent(target)}`;
    activeEventSource = new EventSource(streamUrl);

    activeEventSource.onmessage = function(event) {
        try {
            const data = JSON.parse(event.data);

            if (data.type === 'start') {
                consoleElem.textContent = `$ ${data.cmd}\n\n[Live Stream Started]\n`;
                updateProgressBar(5.0, `Scanning target: ${target}`);
            } else if (data.type === 'log') {
                if (data.full_log) {
                    consoleElem.textContent = data.full_log;
                } else if (data.line) {
                    consoleElem.textContent += data.line;
                }
                consoleElem.scrollTop = consoleElem.scrollHeight;

                if (data.percent !== undefined) {
                    updateProgressBar(data.percent, `Scanning ${target} (${data.percent}%)...`);
                }
            } else if (data.type === 'complete') {
                updateProgressBar(100.0, `Scan Complete (100%)`);
                if (data.result) {
                    renderScanResults(data.result);
                }
                showToast(`Nmap ${cmdType.replace('_', ' ')} completed successfully!`, "success");
                loadOverviewData();
                loadPhase4Data();
                loadCommandHistory();
                activeEventSource.close();
                activeEventSource = null;
            }
        } catch (err) {
            console.error("SSE parse error:", err);
        }
    };

    activeEventSource.onerror = function(err) {
        console.warn("SSE connection error, falling back to POST API:", err);
        if (activeEventSource) {
            activeEventSource.close();
            activeEventSource = null;
        }
        fetch("/api/module1/scan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ cmd_type: cmdType, target: target })
        })
        .then(res => res.json())
        .then(data => {
            updateProgressBar(100.0, "Scan Complete");
            renderScanResults(data);
            showToast(`Nmap ${cmdType.replace('_', ' ')} completed!`, "success");
            loadOverviewData();
            loadPhase4Data();
            loadCommandHistory();
        })
        .catch(e => {
            updateProgressBar(0, "Scan Failed");
            showToast("Command execution failed.", "error");
        });
    };
}

function triggerNmapScan() {
    executeNmapCmd('service_scan');
}

// ────────────────────────────────────────────────────────────────────────────
// MODULE 2 — REAL-TIME PACKET CAPTURE
// ────────────────────────────────────────────────────────────────────────────

/** Populate the interface dropdown from the server. */
function m2LoadInterfaces() {
    fetch("/api/module2/interfaces")
        .then(r => r.json())
        .then(data => {
            const sel = document.getElementById("m2-iface-select");
            if (!sel) return;
            const ifaces = data.interfaces || [];
            sel.innerHTML = "";
            if (ifaces.length === 0) {
                sel.innerHTML = "<option value=''>No interfaces found</option>";
                return;
            }
            ifaces.forEach(iface => {
                const opt = document.createElement("option");
                opt.value = iface;
                opt.textContent = iface;
                sel.appendChild(opt);
            });
        })
        .catch(() => {
            const sel = document.getElementById("m2-iface-select");
            if (sel) sel.innerHTML = "<option value='Wi-Fi'>Wi-Fi</option><option value='Ethernet'>Ethernet</option>";
        });
}

/** Register all SocketIO event listeners for Module 2. */
function m2InitSocketHandlers() {
    if (!m2socket) {
        console.warn("Socket.IO client not loaded — live socket handlers skipped.");
        return;
    }

    // ── New packet arrives ────────────────────────────────────────────────
    m2socket.on("m2_packet", function(pkt) {
        m2PacketBuffer.push(pkt);
        if (!m2FlushScheduled) {
            m2FlushScheduled = true;
            requestAnimationFrame(m2FlushPackets);
        }
    });

    // ── Protocol statistics update ────────────────────────────────────────
    m2socket.on("m2_stats", function(data) {
        m2TotalCount = data.total || 0;
        document.getElementById("m2-total-badge").textContent = m2TotalCount + " Packets";
        document.getElementById("packet-count-badge").textContent = m2TotalCount + " Packets";
        // update kpi-packets on the overview tab as well
        const kpiEl = document.getElementById("kpi-packets");
        if (kpiEl) kpiEl.textContent = m2TotalCount;

        const counts = data.protocol_counts || {};
        const ids = ["TCP", "UDP", "DNS", "HTTPS/TLS", "ICMP", "HTTP", "QUIC", "OTHER"];
        ids.forEach(proto => {
            const el = document.getElementById("m2-cnt-" + proto);
            if (el) el.textContent = counts[proto] || 0;
        });

        // ICMP breakdown
        const icmp = data.icmp_stats || {};
        const totalIcmp = (icmp.echo_request || 0) + (icmp.echo_reply || 0) + (icmp.other || 0);
        const reqEl = document.getElementById("m2-icmp-req");
        const repEl = document.getElementById("m2-icmp-rep");
        const otherEl = document.getElementById("m2-icmp-other");
        const totalEl = document.getElementById("m2-icmp-total");
        if (reqEl) reqEl.textContent = icmp.echo_request || 0;
        if (repEl) repEl.textContent = icmp.echo_reply || 0;
        if (otherEl) otherEl.textContent = icmp.other || 0;
        if (totalEl) totalEl.textContent = totalIcmp;
    });

    // ── DNS query arrives ─────────────────────────────────────────────────
    m2socket.on("m2_dns", function(dns) {
        m2DnsCount++;
        const countEl = document.getElementById("m2-dns-count");
        if (countEl) countEl.textContent = m2DnsCount;

        const tbody = document.getElementById("m2-dns-body");
        if (!tbody) return;

        // Remove placeholder row
        const placeholder = tbody.querySelector("tr td[colspan='5']");
        if (placeholder) placeholder.parentElement.remove();

        const tr = document.createElement("tr");
        tr.innerHTML = `
            <td>${dns.timestamp || ""}</td>
            <td><strong>${escapeHtml(dns.domain || "")}</strong></td>
            <td><span class="proto-tag proto-dns">${escapeHtml(dns.query_type || "A")}</span></td>
            <td><code>${escapeHtml(dns.source_ip || "")}</code></td>
            <td><code>${escapeHtml(dns.dns_server || "")}</code></td>
        `;
        // Insert newest at top
        tbody.insertBefore(tr, tbody.firstChild);
    });

    // ── TCP handshake event ───────────────────────────────────────────────
    m2socket.on("m2_handshake", function(evt) {
        const hs = evt.data || {};
        const key = evt.key || "";
        const tbody = document.getElementById("m2-handshakes-body");
        if (!tbody) return;

        // Remove placeholder
        const placeholder = tbody.querySelector("tr td[colspan='4']");
        if (placeholder) placeholder.parentElement.remove();

        const statusClass = hs.complete ? "risk-badge risk-low" :
                            hs.syn_ack ? "risk-badge risk-medium" : "risk-badge risk-high";
        const statusText = hs.status || "SYN";
        const rowHtml = `
            <td><code>${escapeHtml(hs.client || "")}</code></td>
            <td><code>${escapeHtml(hs.server || "")}</code></td>
            <td><strong>${hs.port || ""}</strong></td>
            <td><span class="${statusClass}">${statusText}</span></td>
        `;

        if (m2HandshakeRows[key]) {
            // Update existing row in place
            m2HandshakeRows[key].innerHTML = rowHtml;
        } else {
            const tr = document.createElement("tr");
            tr.innerHTML = rowHtml;
            tbody.insertBefore(tr, tbody.firstChild);
            m2HandshakeRows[key] = tr;
            // Update handshake count badge
            const hsCountEl = document.getElementById("m2-hs-count");
            if (hsCountEl) hsCountEl.textContent = Object.keys(m2HandshakeRows).length;
        }
    });

    // ── Status update ─────────────────────────────────────────────────────
    m2socket.on("m2_status", function(data) {
        m2SetStatus(data.status, data.error, data.start_time);
    });
}

/** Batch flush the incoming packet buffer to the DOM via rAF. */
function m2FlushPackets() {
    m2FlushScheduled = false;
    if (m2PacketBuffer.length === 0) return;

    const tbody = document.getElementById("packetsTableBody");
    if (!tbody) { m2PacketBuffer = []; return; }

    // Remove placeholder row if present
    const emptyRow = document.getElementById("m2-empty-row");
    if (emptyRow) emptyRow.remove();

    // Take all buffered packets
    const batch = m2PacketBuffer.splice(0, m2PacketBuffer.length);

    batch.forEach(p => {
        // Enforce 500-row cap: remove oldest
        while (m2RowCount >= M2_MAX_ROWS && tbody.firstChild) {
            tbody.removeChild(tbody.firstChild);
            m2RowCount--;
        }

        const proto = (p.protocol || "").toLowerCase().replace(/\//, "");
        const tagClass = ["tcp","udp","dns","http","icmp","quic"].includes(proto)
            ? "proto-" + proto : "proto-tcp";

        const tr = document.createElement("tr");
        tr.innerHTML = `
            <td>${p.id || ""}</td>
            <td style="font-size:0.8rem;color:#9ca3af;">${p.timestamp || ""}</td>
            <td><code style="font-size:0.8rem;">${escapeHtml(p.src_ip || "")}</code></td>
            <td><code style="font-size:0.8rem;">${escapeHtml(p.dst_ip || "")}</code></td>
            <td><span class="proto-tag ${tagClass}">${escapeHtml(p.protocol || "")}</span></td>
            <td>${p.source_port || ""}</td>
            <td>${p.destination_port || ""}</td>
            <td>${p.length || 0}</td>
            <td style="font-size:0.8rem;max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${escapeHtml(p.details || '')}">${escapeHtml(p.details || "")}</td>
        `;
        tbody.appendChild(tr);
        m2RowCount++;
    });

    // Auto-scroll to bottom
    const scrollEl = document.getElementById("m2-packets-scroll");
    if (scrollEl) scrollEl.scrollTop = scrollEl.scrollHeight;
}

/** Start real-time capture. */
function m2StartCapture() {
    const iface = document.getElementById("m2-iface-select");
    const ifaceName = iface ? iface.value.trim() : "";
    if (!ifaceName) {
        showToast("Please select a network interface.", "error");
        return;
    }
    showToast(`Starting real-time capture on ${ifaceName}...`);
    fetch("/api/module2/start", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({interface: ifaceName})
    })
    .then(r => r.json())
    .then(data => {
        if (data.ok) {
            m2SetStatus("Capturing");
            showToast("Capture started!", "success");
        } else {
            m2SetStatus("Error", data.error);
            showToast(data.error || "Failed to start capture.", "error");
        }
    })
    .catch(err => {
        m2SetStatus("Error", err.toString());
        showToast("Request failed: " + err, "error");
    });
}

/** Stop real-time capture. */
function m2StopCapture() {
    showToast("Stopping capture...");
    fetch("/api/module2/stop", {method: "POST"})
        .then(r => r.json())
        .then(data => {
            m2SetStatus("Stopped");
            showToast(`Capture stopped. Total packets: ${data.packet_count || 0}`, "success");
        })
        .catch(() => showToast("Failed to stop capture.", "error"));
}

/** Clear all capture data. */
function m2ClearCapture() {
    fetch("/api/module2/clear", {method: "POST"})
        .then(() => {
            // Reset all UI elements
            const tbody = document.getElementById("packetsTableBody");
            if (tbody) {
                tbody.innerHTML = `<tr id="m2-empty-row"><td colspan="9" style="text-align:center;color:#6b7280;padding:2rem;">Start capture to see live packets</td></tr>`;
            }
            const dnsTbody = document.getElementById("m2-dns-body");
            if (dnsTbody) dnsTbody.innerHTML = `<tr><td colspan="5" style="text-align:center;color:#6b7280;padding:1.5rem;">No DNS queries yet</td></tr>`;
            const hsTbody = document.getElementById("m2-handshakes-body");
            if (hsTbody) hsTbody.innerHTML = `<tr><td colspan="4" style="text-align:center;color:#6b7280;padding:1.5rem;">No handshakes yet</td></tr>`;

            // Reset counters
            m2RowCount = 0; m2TotalCount = 0; m2DnsCount = 0;
            m2HandshakeRows = {}; m2PacketBuffer = [];

            ["TCP","UDP","DNS","HTTPS/TLS","ICMP","HTTP","QUIC","OTHER"].forEach(p => {
                const el = document.getElementById("m2-cnt-" + p);
                if (el) el.textContent = "0";
            });
            ["m2-icmp-req","m2-icmp-rep","m2-icmp-other","m2-icmp-total"].forEach(id => {
                const el = document.getElementById(id);
                if (el) el.textContent = "0";
            });
            document.getElementById("m2-total-badge").textContent = "0 Packets";
            document.getElementById("packet-count-badge").textContent = "0 Packets";
            document.getElementById("m2-hs-count").textContent = "0";
            document.getElementById("m2-dns-count").textContent = "0";

            showToast("Capture data cleared.");
        })
        .catch(() => showToast("Failed to clear.", "error"));
}

/** Export current capture to JSON + CSV. */
function m2ExportCapture() {
    showToast("Exporting capture data to JSON & CSV...");
    fetch("/api/module2/export", {method: "POST"})
        .then(r => r.json())
        .then(data => {
            if (data.ok) {
                showToast(`Exported ${data.total_packets} packets. Files saved!`, "success");
            } else {
                showToast(data.error || "Export failed.", "error");
            }
        })
        .catch(() => showToast("Export request failed.", "error"));
}

/** Update the status indicator dot + text + button states. */
function m2SetStatus(status, errorMsg, startTime) {
    const dot = document.getElementById("m2-status-dot");
    const text = document.getElementById("m2-status-text");
    const startBtn = document.getElementById("m2-start-btn");
    const stopBtn = document.getElementById("m2-stop-btn");
    const errSpan = document.getElementById("m2-error-text");
    const errMsg = document.getElementById("m2-error-msg");
    const startTimeEl = document.getElementById("m2-start-time");

    const dotColors = {"Capturing": "#10b981", "Stopped": "#f59e0b", "Error": "#ef4444", "Idle": "#6b7280"};
    if (dot) dot.style.background = dotColors[status] || "#6b7280";
    if (text) text.textContent = status;
    if (startBtn) startBtn.disabled = (status === "Capturing");
    if (stopBtn) stopBtn.disabled = (status !== "Capturing");

    if (startTimeEl && startTime) startTimeEl.textContent = startTime;

    if (errSpan && errMsg) {
        if (status === "Error" && errorMsg) {
            errMsg.textContent = errorMsg;
            errSpan.style.display = "inline";
        } else {
            errSpan.style.display = "none";
        }
    }
}

/**
 * loadModule2Data — loads saved packet_analysis.json on page load.
 * Still works for offline PCAP results; does NOT interfere with live capture.
 */
function loadModule2Data() {
    fetch("/api/module2/packets")
        .then(res => res.json())
        .then(data => {
            const total = data.total_packets_captured || 0;
            document.getElementById("packet-count-badge").textContent = `${total} Packets`;
            const badge = document.getElementById("m2-total-badge");
            if (badge) badge.textContent = `${total} Packets`;

            // Populate saved packets into table if any exist and capture isn't running
            const tbody = document.getElementById("packetsTableBody");
            if (!tbody) return;
            const pkts = data.packets || [];
            if (pkts.length === 0) return;

            const emptyRow = document.getElementById("m2-empty-row");
            if (emptyRow) emptyRow.remove();

            pkts.slice(-M2_MAX_ROWS).forEach(p => {
                const proto = (p.protocol || "").toLowerCase().replace(/\//, "");
                const tagClass = ["tcp","udp","dns","http","icmp","quic"].includes(proto)
                    ? "proto-" + proto : "proto-tcp";
                const tr = document.createElement("tr");
                tr.innerHTML = `
                    <td>${p.id}</td>
                    <td style="font-size:0.8rem;color:#9ca3af;">${p.timestamp || ""}</td>
                    <td><code style="font-size:0.8rem;">${escapeHtml(p.src_ip || "")}</code></td>
                    <td><code style="font-size:0.8rem;">${escapeHtml(p.dst_ip || "")}</code></td>
                    <td><span class="proto-tag ${tagClass}">${escapeHtml(p.protocol || "")}</span></td>
                    <td>${p.source_port || ""}</td>
                    <td>${p.destination_port || ""}</td>
                    <td>${p.length || 0}</td>
                    <td style="font-size:0.8rem;" title="${escapeHtml(p.details || '')}">${escapeHtml(p.details || "")}</td>
                `;
                tbody.appendChild(tr);
                m2RowCount++;
            });
        })
        .catch(err => console.error("Error loading Module 2 saved data:", err));
}

/**
 * triggerPacketCapture — kept for backward compatibility with any external callers.
 * Now just calls m2StartCapture().
 */
function triggerPacketCapture() {
    m2StartCapture();
}

/** HTML escape helper. */
function escapeHtml(str) {
    if (!str) return "";
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");
}

// TAB 4: Module 3 MAC Spoofing
function loadModule3Data() {
    fetch("/api/module3/mac")
        .then(res => res.json())
        .then(data => {
            const adapters = data.adapters || [];
            const select = document.getElementById("adapterSelect");
            select.innerHTML = "";
            adapters.forEach(ad => {
                const opt = document.createElement("option");
                opt.value = ad.name;
                opt.textContent = `${ad.name} (${ad.mac}) - ${ad.status}`;
                select.appendChild(opt);
            });

            const log = data.mac_log || {};
            document.getElementById("origMacDisplay").textContent = log.original_mac || "F4:6D:04:88:99:AA";
            document.getElementById("currMacDisplay").textContent = log.current_mac || "F4:6D:04:88:99:AA";
            
            const badge = document.getElementById("spoofStatusBadge");
            if (log.is_spoofed) {
                badge.textContent = "Suspicious MAC Change";
                badge.className = "status-badge spoofed";
            } else {
                badge.textContent = "Candidate MAC Verified";
                badge.className = "status-badge normal";
            }

            // Render Log Table
            const tbody = document.getElementById("macLogTableBody");
            tbody.innerHTML = "";
            (log.history || []).reverse().forEach(h => {
                const tr = document.createElement("tr");
                tr.innerHTML = `
                    <td>${new Date(h.timestamp).toLocaleTimeString()}</td>
                    <td><strong>${h.action}</strong></td>
                    <td>${h.adapter}</td>
                    <td><code>${h.new_mac || h.restored_mac}</code></td>
                    <td><span style="color:#10b981;"><i class="fa-solid fa-check"></i> Verified</span></td>
                `;
                tbody.appendChild(tr);
            });
        });
}

function generateRandomMacInInput() {
    const hex = "0123456789ABCDEF";
    let first = "02"; // Locally administered
    let mac = [first];
    for (let i = 0; i < 5; i++) {
        mac.push(hex[Math.floor(Math.random() * 16)] + hex[Math.floor(Math.random() * 16)]);
    }
    document.getElementById("newMacInput").value = mac.join(":");
}

function executeChangeMac() {
    const adapter = document.getElementById("adapterSelect").value || "Wi-Fi";
    const newMac = document.getElementById("newMacInput").value;

    showToast(`Changing MAC Address & Restarting ${adapter}...`);
    fetch("/api/module3/mac", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "change", adapter: adapter, new_mac: newMac })
    })
    .then(res => res.json())
    .then(data => {
        showToast(`MAC Changed & Adapter Restarted successfully!`, "success");
        loadModule3Data();
        loadOverviewData();
    });
}

function executeRestoreMac() {
    const adapter = document.getElementById("adapterSelect").value || "Wi-Fi";
    showToast(`Restoring Original MAC & Restarting ${adapter}...`);
    fetch("/api/module3/mac", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "restore", adapter: adapter })
    })
    .then(res => res.json())
    .then(data => {
        showToast("Original MAC Address Restored!", "success");
        loadModule3Data();
        loadOverviewData();
    });
}

// TAB 5: Phase 4 Security Audit
function loadPhase4Data() {
    fetch("/api/security-analysis")
        .then(res => res.json())
        .then(report => {
            // Risky Ports Table
            const tbody = document.getElementById("riskyPortsTableBody");
            tbody.innerHTML = "";
            (report.unnecessary_ports || []).forEach(p => {
                const tr = document.createElement("tr");
                const riskClass = `risk-${p.risk_level.toLowerCase()}`;
                tr.innerHTML = `
                    <td><code>${p.ip}</code></td>
                    <td><strong>${p.port}</strong></td>
                    <td>${p.service}</td>
                    <td><span class="risk-badge ${riskClass}">${p.risk_level}</span></td>
                    <td>${p.reason}</td>
                `;
                tbody.appendChild(tr);
            });

            // Insecure Protocols Cards
            const protoContainer = document.getElementById("insecureProtoContainer");
            protoContainer.innerHTML = "";
            (report.insecure_protocols || []).forEach(item => {
                const div = document.createElement("div");
                div.className = "firewall-box";
                div.innerHTML = `
                    <h4><i class="fa-solid fa-lock-open"></i> Insecure Protocol: ${item.protocol}</h4>
                    <p style="font-size:0.85rem; color:#9ca3af;">${item.details.mitigation}</p>
                `;
                protoContainer.appendChild(div);
            });

            // Firewall Recommendations
            const fwContainer = document.getElementById("firewallRulesContainer");
            fwContainer.innerHTML = "";
            (report.recommended_firewall_rules || []).forEach(rule => {
                const div = document.createElement("div");
                div.className = "firewall-box";
                div.innerHTML = `
                    <h4>Block Port ${rule.port} (${rule.service}) on ${rule.target_ip}</h4>
                    <p style="font-size:0.85rem; color:#9ca3af; margin-bottom:0.4rem;">${rule.rationale}</p>
                    <div class="cmd-block">
                        <span>${rule.windows_firewall_cmd}</span>
                        <button class="copy-btn" onclick="navigator.clipboard.writeText('${rule.windows_firewall_cmd}'); showToast('Command copied!');">
                            <i class="fa-regular fa-copy"></i>
                        </button>
                    </div>
                `;
                fwContainer.appendChild(div);
            });

            // Security Hardening Checklist
            const checkContainer = document.getElementById("securityChecklistContainer");
            checkContainer.innerHTML = "";
            (report.security_improvements || []).forEach(rec => {
                const div = document.createElement("div");
                div.className = "firewall-box";
                div.innerHTML = `
                    <h4>${rec.category} <span class="risk-badge risk-${rec.severity.toLowerCase()}">${rec.severity}</span></h4>
                    <p style="font-size:0.85rem; color:#f3f4f6; margin-top:0.3rem;"><strong>Finding:</strong> ${rec.finding}</p>
                    <p style="font-size:0.85rem; color:#10b981; margin-top:0.2rem;"><strong>Action Plan:</strong> ${rec.action_item}</p>
                `;
                checkContainer.appendChild(div);
            });
        });
}

function triggerSecurityAudit() {
    showToast("Re-analyzing Network Security Posture...");
    fetch("/api/security-analysis", { method: "POST" })
        .then(res => res.json())
        .then(report => {
            showToast("Security Assessment Updated!", "success");
            loadPhase4Data();
            loadOverviewData();
        });
}
