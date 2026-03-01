console.log("🛡 SmartMail AI — Enterprise Protection Active");

let lastSignature = null;
let lastUrl = location.href;
let debounceTimer = null;
let isAnalyzing = false;

// ======================================================
// EMAIL EXTRACTION
// ======================================================

function getEmailContent() {
    const subject = document.querySelector("h2[data-thread-perm-id]")?.innerText?.trim();
    const body = document.querySelector("div[role='listitem'] div.a3s")?.innerText?.trim();

    if (!subject || !body) return null;
    return { subject, body };
}

// ======================================================
// CLEANUP
// ======================================================

function removeExistingUI() {
    document.getElementById("smartmail-container")?.remove();
    document.getElementById("smartmail-quarantine-overlay")?.remove();
}

// ======================================================
// PROGRESS BAR
// ======================================================

function createProgressBar(percent, color) {
    return `
        <div style="background:#1f2937;border-radius:8px;height:8px;margin-top:8px;">
            <div style="
                width:${percent}%;
                background:${color};
                height:8px;
                border-radius:8px;
                transition:width 0.6s ease;
            "></div>
        </div>
    `;
}

// ======================================================
// QUARANTINE MODE
// ======================================================

function quarantineEmail(data) {

    const emailBody = document.querySelector("div[role='listitem'] div.a3s");
    if (!emailBody) return;

    emailBody.style.display = "none";

    const overlay = document.createElement("div");
    overlay.id = "smartmail-quarantine-overlay";

    overlay.style.cssText = `
        margin-top:20px;
        padding:40px;
        border-radius:20px;
        background:linear-gradient(135deg,#7f1d1d,#991b1b);
        color:white;
        text-align:center;
        font-family:Inter,Segoe UI;
        box-shadow:0 30px 60px rgba(0,0,0,0.5);
        animation: fadeIn 0.4s ease;
    `;

    overlay.innerHTML = `
        <div style="font-size:22px;font-weight:700;">
            🚨 Email Quarantined
        </div>

        <div style="margin-top:10px;opacity:0.9;">
            SmartMail AI detected this email as <b>${data.classification}</b>
        </div>

        <div style="margin-top:8px;">
            Threat ID: ${data.threat_id}
        </div>

        <div style="margin-top:20px;">
            🛡 Trust Score: <b>${data.trust_score}%</b>
        </div>

        <div style="margin-top:25px;">
            <button id="restore-email-btn" style="
                padding:10px 22px;
                background:#16a34a;
                border:none;
                border-radius:12px;
                color:white;
                font-weight:600;
                cursor:pointer;
                margin-right:12px;
            ">
                Mark as Safe
            </button>

            <button id="keep-blocked-btn" style="
                padding:10px 22px;
                background:#111827;
                border:none;
                border-radius:12px;
                color:white;
                font-weight:600;
                cursor:pointer;
            ">
                Keep Blocked
            </button>
        </div>
    `;

    emailBody.parentElement.prepend(overlay);

    document.getElementById("restore-email-btn").onclick = () => {
        emailBody.style.display = "block";
        overlay.remove();
    };

    document.getElementById("keep-blocked-btn").onclick = () => {
        // Do nothing (remains hidden)
    };
}

// ======================================================
// NORMAL UI MODE
// ======================================================

function injectUI(data) {

    removeExistingUI();

    const colorMap = {
        Critical: "#ef4444",
        High: "#f97316",
        Medium: "#eab308",
        Low: "#22c55e"
    };

    const color = colorMap[data.risk_level] || "#22c55e";

    const container = document.createElement("div");
    container.id = "smartmail-container";

    container.style.cssText = `
        padding:28px;
        margin:20px 0;
        border-radius:20px;
        backdrop-filter:blur(18px);
        background:rgba(17,24,39,0.85);
        color:white;
        font-family:Inter,Segoe UI;
        box-shadow:0 25px 60px rgba(0,0,0,0.4);
        border-left:6px solid ${color};
        animation:fadeIn 0.4s ease;
    `;

    container.innerHTML = `
        <div style="display:flex;justify-content:space-between;align-items:center;">
            <div>
                <div style="font-size:22px;font-weight:700;">
                    ${data.classification}
                </div>
                <div style="opacity:0.7;margin-top:4px;">
                    Threat ID: ${data.threat_id}
                </div>
            </div>

            <div style="
                padding:10px 16px;
                background:${color};
                border-radius:12px;
                font-weight:600;
            ">
                ${data.risk_level}
            </div>
        </div>

        <div style="margin-top:22px;">
            🛡 Trust Score: <b>${data.trust_score}%</b>
            ${createProgressBar(data.trust_score, color)}
        </div>

        <div style="margin-top:18px;">
            🎯 Confidence: <b>${data.confidence_score}%</b>
            ${createProgressBar(data.confidence_score, "#3b82f6")}
        </div>

        <div style="margin-top:22px;">
            <button id="smartmail-toggle" style="
                padding:8px 16px;
                background:#3b82f6;
                border:none;
                border-radius:10px;
                color:white;
                cursor:pointer;
                font-weight:500;
            ">
                View AI Analysis
            </button>

            <div id="smartmail-details" style="
                display:none;
                margin-top:16px;
                padding:14px;
                background:#111827;
                border-radius:12px;
                font-size:13px;
                line-height:1.5;
                opacity:0.9;
            ">
                ${data.llm_explanation || "No explanation available."}
            </div>
        </div>
    `;

    document.querySelector("div[role='main']")?.prepend(container);

    document.getElementById("smartmail-toggle").onclick = () => {
        const details = document.getElementById("smartmail-details");
        details.style.display =
            details.style.display === "none" ? "block" : "none";
    };

    // ===============================
    // AUTO QUARANTINE TRIGGER
    // ===============================

    if (
        data.risk_level === "High" ||
        data.risk_level === "Critical" ||
        data.classification === "Advanced Phishing" ||
        data.trust_score < 40
    ) {
        quarantineEmail(data);
    }
}

// ======================================================
// BACKEND CALL
// ======================================================

async function analyzeEmail(email) {

    if (isAnalyzing) return;
    isAnalyzing = true;

    try {
        const response = await fetch("http://127.0.0.1:8000/analyze", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(email)
        });

        if (!response.ok) {
            isAnalyzing = false;
            return;
        }

        const data = await response.json();
        injectUI(data);

    } catch (err) {
        console.error("SmartMail Error:", err);
    }

    isAnalyzing = false;
}

// ======================================================
// EMAIL MONITORING
// ======================================================

function scanEmail() {
    const email = getEmailContent();
    if (!email) return;

    const signature = email.subject + email.body;
    if (signature === lastSignature) return;

    lastSignature = signature;
    analyzeEmail(email);
}

setInterval(() => {
    if (location.href !== lastUrl) {
        lastUrl = location.href;
        clearTimeout(debounceTimer);
        debounceTimer = setTimeout(scanEmail, 1000);
    }
}, 800);

new MutationObserver(() => {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(scanEmail, 800);
}).observe(document.body, { childList: true, subtree: true });