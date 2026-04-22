document.getElementById('scan-btn').addEventListener('click', async () => {
    const statusText = document.getElementById('status-text');
    const statusIcon = document.getElementById('status-icon');
    const statusUrl = document.getElementById('status-url');
    const loadingState = document.getElementById('loading-state');
    const resultState = document.getElementById('result-state');
    const detailsSection = document.getElementById('details-section');
    const rulesList = document.getElementById('rules-list');
    const mainCard = document.getElementById('main-card');
    const scoreVal = document.getElementById('score-val');

    // Show loading
    loadingState.style.display = 'block';
    resultState.style.display = 'none';

    try {
        // Get current tab
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        
        // Execute script to get HTML content
        const results = await chrome.scripting.executeScript({
            target: { tabId: tab.id },
            func: () => {
                return {
                    url: window.location.href,
                    html: document.documentElement.outerHTML
                };
            }
        });

        const pageData = results[0].result;

        // Call our FastAPI server
        const response = await fetch('http://127.0.0.1:8000/predict', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                url: pageData.url,
                html_content: pageData.html
            })
        });

        if (!response.ok) throw new Error('API server is not running');

        const data = await response.json();

        // Update UI based on risk level
        loadingState.style.display = 'none';
        resultState.style.display = 'block';
        statusUrl.innerText = tab.url.substring(0, 30) + '...';
        scoreVal.innerText = `Risk Score: ${(data.confidence * 100).toFixed(1)}%`;
        
        if (data.risk_level === 'HIGH') {
            statusIcon.innerText = '🚫';
            statusText.innerText = 'DANGER';
            statusText.style.color = '#ef4444';
            mainCard.style.border = '1px solid #ef4444';
            scoreVal.style.backgroundColor = '#ef4444';
        } else if (data.risk_level === 'MEDIUM') {
            statusIcon.innerText = '⚠️';
            statusText.innerText = 'WARNING';
            statusText.style.color = '#f59e0b';
            mainCard.style.border = '1px solid #f59e0b';
            scoreVal.style.backgroundColor = '#f59e0b';
        } else {
            statusIcon.innerText = '✅';
            statusText.innerText = 'SAFE';
            statusText.style.color = '#10b981';
            mainCard.style.border = '1px solid #10b981';
            scoreVal.style.backgroundColor = '#10b981';
        }

        // Show rules if any
        if (data.triggered_rules && data.triggered_rules.length > 0) {
            detailsSection.style.display = 'block';
            rulesList.innerHTML = data.triggered_rules.map(rule => 
                `<div class="rule-item"><span class="rule-bullet">●</span> ${rule}</div>`
            ).join('');
        } else {
            detailsSection.style.display = 'none';
        }

    } catch (err) {
        loadingState.style.display = 'none';
        resultState.style.display = 'block';
        statusIcon.innerText = '❌';
        statusText.innerText = 'Error';
        statusUrl.innerText = 'Make sure the Python API is running.';
        console.error(err);
    }
});
