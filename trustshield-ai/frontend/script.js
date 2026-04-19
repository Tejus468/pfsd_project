async function analyze() {
    const subject = document.getElementById("subject").value.trim();
    const bodyText = document.getElementById("body").value.trim();

    if (!subject && !bodyText) {
        alert("Please enter email subject or body.");
        return;
    }

    try {
        const response = await fetch("/analyze", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                subject: subject,
                body: bodyText
            })
        });

        if (!response.ok) {
            throw new Error("Server error");
        }

        const data = await response.json();

        // Show classification + confidence
        document.getElementById("classification").innerText =
            data.classification;

        document.getElementById("confidence").innerText =
            data.confidence_score + "%";

        document.getElementById("explanation").innerText =
            data.explanation;

        document.getElementById("highlighted-message").innerHTML =
            data.highlighted_text;

        document.getElementById("result").classList.remove("hidden");

        setTimeout(() => {
            window.location.href = "/frontend/dashboard.html";
        }, 1200);

    } catch (error) {
        alert("Backend not running. Please start server.");
        console.error(error);
    }
}