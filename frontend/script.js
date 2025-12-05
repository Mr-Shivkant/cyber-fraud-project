async function detectScam() {
    const message = document.getElementById("messageInput").value.trim();
    const resultDiv = document.getElementById("result");

    if (!message) {
        alert("Please paste a message first.");
        return;
    }

    resultDiv.innerHTML = "Checking...";

    try {
        const response = await fetch("http://127.0.0.1:5000/detect-scam", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ message: message })
        });

        const data = await response.json();

        if (!response.ok) {
            resultDiv.innerHTML = "Error: " + (data.error || "Unknown error");
            return;
        }

        // Display result with color coding
        let color = "#2ecc71"; // default safe
        if (data.risk === "Dangerous") color = "#e74c3c";
        else if (data.risk === "Suspicious") color = "#e67e22";

        resultDiv.style.borderLeft = `6px solid ${color}`;
        resultDiv.style.backgroundColor = "#f9f9f9";

        resultDiv.innerHTML = `
            <strong>Risk:</strong> ${data.risk} <br/>
            <strong>Score:</strong> ${data.score}% <br/>
            <strong>Highlights:</strong> ${data.highlights.join(", ") || "None"} <br/>
            <em>${data.warning}</em>
        `;
    } catch (error) {
        console.error(error);
        resultDiv.innerHTML = "Error connecting to backend.";
    }
}
