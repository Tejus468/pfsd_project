document.getElementById("analyzeBtn").addEventListener("click", async () => {

    try {
        // Get active tab
        const [tab] = await chrome.tabs.query({
            active: true,
            currentWindow: true
        });

        if (!tab?.id) {
            showError("Unable to access current tab.");
            return;
        }

        // Inject content script if not already loaded
        await chrome.scripting.executeScript({
            target: { tabId: tab.id },
            files: ["content.js"]
        });

        // Request email content from Gmail
        chrome.tabs.sendMessage(tab.id, { action: "getEmail" }, async (response) => {

            if (!response) {
                showError("No email detected. Open an email first.");
                return;
            }

            try {
                // Call backend API
                const apiResponse = await fetch("http://127.0.0.1:8000/analyze", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify(response)
                });

                if (!apiResponse.ok) {
                    showError("Backend error.");
                    return;
                }

                const data = await apiResponse.json();

                renderResult(data);

                // Inject result into Gmail UI
                chrome.tabs.sendMessage(tab.id, {
                    action: "injectResult",
                    data: data
                });

            } catch (apiError) {
                console.error("API Error:", apiError);
                showError("Cannot connect to backend.");
            }
        });

    } catch (err) {
        console.error("Extension Error:", err);
        showError("Unexpected extension error.");
    }
});


// ===============================
// Render Popup UI Result
// ===============================

function renderResult(data) {

    const riskClass = (data.risk_level || "Low").toLowerCase();

    let breakdownHTML = `
        <div class="breakdown">
            <div>ML: ${data.ml_probability}%</div>
            <div>URL Risk: ${data.url_risk_percent}%</div>
            <div>Attachment Risk: ${data.attachment_percent}%</div>
        </div>
    `;

    let explanationHTML = "";

    if (data.anomalies?.length > 0) {
        explanationHTML += `
            <div class="why-flagged">
                <strong>Why Flagged:</strong>
                <ul>
                    ${data.anomalies.map(a => `<li>${a}</li>`).join("")}
                </ul>
            </div>
        `;
    }

    document.getElementById("result").innerHTML = `
        <div class="card ${riskClass}">
            <div class="badge">
                ${data.classification} (${data.ml_probability}%)
            </div>

            <div class="attack-type">
                🔎 ${data.attack_type || "Unknown Threat Type"}
            </div>

            <div class="risk-meter">
                <div class="risk-label">
                    Risk Level: ${data.risk_level}
                </div>
                <div class="risk-bar">
                    <div class="risk-fill" style="width:${100 - data.trust_score}%"></div>
                </div>
            </div>

            <div class="small">
                Trust Score: ${data.trust_score}%
            </div>

            ${breakdownHTML}
            ${explanationHTML}
        </div>
    `;
}

// ===============================
// Show Error Helper
// ===============================

function showError(message) {
    document.getElementById("result").innerHTML = `
        <div class="card critical">
            ${message}
        </div>
    `;
}