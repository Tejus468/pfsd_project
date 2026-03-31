async function loadDashboard() {
    try {
        const reportResponse = await fetch("http://127.0.0.1:8000/model-report");
        const report = await reportResponse.json();

        const bestResponse = await fetch("http://127.0.0.1:8000/best-model");
        const best = await bestResponse.json();

        document.getElementById("best-model").innerText = best.best_model;

        const modelNames = Object.keys(report);
        const accuracies = modelNames.map(m => report[m].accuracy);
        const f1Scores = modelNames.map(m => report[m].f1_score);

        new Chart(document.getElementById("accuracyChart"), {
            type: "bar",
            data: {
                labels: modelNames,
                datasets: [{
                    label: "Accuracy",
                    data: accuracies,
                    backgroundColor: "#4CAF50"
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: { display: false }
                }
            }
        });

        new Chart(document.getElementById("f1Chart"), {
            type: "bar",
            data: {
                labels: modelNames,
                datasets: [{
                    label: "F1 Score",
                    data: f1Scores,
                    backgroundColor: "#2196F3"
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: { display: false }
                }
            }
        });

    } catch (error) {
        console.error("Error loading dashboard:", error);
    }
}

async function analyzeEmail() {
    const subject = document.getElementById("subject").value;
    const body = document.getElementById("body").value;

    if (!subject && !body) {
        alert("Please enter subject or body.");
        return;
    }

    try {
        const response = await fetch("http://127.0.0.1:8000/analyze", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ subject, body })
        });

        const data = await response.json();

        const resultDiv = document.getElementById("analysisResult");

        let color = "green";
        if (data.risk_level === "Critical") color = "darkred";
        else if (data.risk_level === "High") color = "red";
        else if (data.risk_level === "Medium") color = "orange";

        resultDiv.innerHTML = `
            <p style="color:${color}">
                ${data.classification} (${data.ml_probability}%)
            </p>
            <p>Risk Level: <strong>${data.risk_level}</strong></p>
            <p>Attack Type: <strong>${data.attack_type}</strong></p>
        `;

    } catch (error) {
        console.error("Error analyzing email:", error);
    }
}

loadDashboard();