/* Dashboard Interactive Logic for CyberShield Suite */
document.addEventListener("DOMContentLoaded", () => {
    initTabNavigation();
    loadOverviewData();
    loadModule1Data();
    loadModule2Data();
    loadModule3Data();
    loadPhase4Data();
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
    showToast("Refreshing all module assessment data...");
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
            
            const mac = data.mac_status || {};
            document.getElementById("kpi-mac-status").textContent = mac.is_spoofed ? "SPOOFED" : "NORMAL";
            document.getElementById("kpi-mac-addr").textContent = mac.current_mac || "N/A";
            
            const sec = data.security_summary || {};
            document.getElementById("kpi-sec-score").textContent = `${sec.security_score || 85} / 100`;
            document.getElementById("kpi-vuln-count").textContent = `${sec.unnecessary_open_ports_count || 0} Open Vulnerable Ports`;

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
                label: 'Occurrences Across Hosts',
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

function loadModule1Data() {
    loadNetworkInfo();
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

// TAB 3: Module 2 Packet Capture
function loadModule2Data() {
    fetch("/api/module2/packets")
        .then(res => res.json())
        .then(data => {
            document.getElementById("packet-count-badge").textContent = `${data.total_packets_captured || 0} Packets`;

            const tbody = document.getElementById("packetsTableBody");
            tbody.innerHTML = "";

            (data.packets || []).forEach(p => {
                const tr = document.createElement("tr");
                const protoLower = p.protocol.toLowerCase();
                const tagClass = `proto-${protoLower}` in { 'proto-tcp': 1, 'proto-udp': 1, 'proto-dns': 1, 'proto-http': 1, 'proto-icmp': 1 } 
                    ? `proto-${protoLower}` : 'proto-tcp';

                let handshakeText = p.tcp_handshake || (p.dns_lookup ? `DNS: ${p.dns_lookup.query_name}` : "-");

                tr.innerHTML = `
                    <td>${p.id}</td>
                    <td>${p.timestamp}</td>
                    <td><code>${p.src_ip}</code></td>
                    <td><code>${p.dst_ip}</code></td>
                    <td><span class="proto-tag ${tagClass}">${p.protocol}</span></td>
                    <td>${p.length}</td>
                    <td>${p.details}</td>
                    <td>${handshakeText}</td>
                `;
                tbody.appendChild(tr);
            });
        })
        .catch(err => console.error("Error loading Module 2:", err));
}

function triggerPacketCapture() {
    showToast("Capturing Live Packets & Analyzing PCAP...");
    fetch("/api/module2/packets", { method: "POST" })
        .then(res => res.json())
        .then(data => {
            showToast("Packet Capture & Dissection Finished!", "success");
            loadModule2Data();
            loadOverviewData();
            loadPhase4Data();
        });
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
                badge.textContent = "MAC Spoofed";
                badge.className = "status-badge spoofed";
            } else {
                badge.textContent = "Original MAC Active";
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
