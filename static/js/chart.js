// Dark Web Threat Detector - Chart.js Integration

document.addEventListener('DOMContentLoaded', function() {
    // Check if we're on the dashboard page with chart containers
    if (document.getElementById('threatTypeChart') && document.getElementById('severityChart')) {
        // Get threat distribution data from the page
        const threatDistributionElement = document.getElementById('threat-distribution-data');
        const severityDistributionElement = document.getElementById('severity-distribution-data');
        
        if (threatDistributionElement && severityDistributionElement) {
            try {
                // Parse the JSON data
                const threatDistribution = JSON.parse(threatDistributionElement.textContent);
                const severityDistribution = JSON.parse(severityDistributionElement.textContent);
                
                // Create threat type distribution chart
                createThreatTypeChart(threatDistribution);
                
                // Create severity distribution chart
                createSeverityChart(severityDistribution);
            } catch (e) {
                console.error('Error parsing chart data:', e);
            }
        }
    }
});

function createThreatTypeChart(threatDistribution) {
    // Get labels and data from the distribution object
    const labels = Object.keys(threatDistribution);
    const data = Object.values(threatDistribution);
    
    // Set up colors based on threat types
    const colors = labels.map(label => {
        // Map common threat types to specific colors
        const colorMap = {
            'Malware': '#FF5733',
            'Phishing': '#33A8FF',
            'Ransomware': '#FF33A8',
            'Trojan': '#A833FF',
            'Spyware': '#33FFA8',
            'Scam': '#FFC733',
            'Fraud': '#C733FF',
            'Exploit': '#33FFE8',
            'Carding': '#FF8F33',
            'Hacking Services': '#7A33FF',
            'DDoS': '#33FF7A',
            'SQL Injection': '#FF33E8'
        };
        
        return colorMap[label] || getRandomColor();
    });
    
    // Create the chart
    const ctx = document.getElementById('threatTypeChart').getContext('2d');
    new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: data,
                backgroundColor: colors,
                borderColor: '#343a40',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right',
                    labels: {
                        color: '#e9ecef',
                        font: {
                            size: 12
                        }
                    }
                },
                title: {
                    display: true,
                    text: 'Threat Type Distribution',
                    color: '#e9ecef',
                    font: {
                        size: 16
                    }
                }
            }
        }
    });
}

function createSeverityChart(severityDistribution) {
    // Get labels and data from the distribution object
    const labels = Object.keys(severityDistribution);
    const data = Object.values(severityDistribution);
    
    // Set colors based on severity levels
    const colors = labels.map(label => {
        if (label.toLowerCase() === 'high') return '#dc3545';  // Danger
        if (label.toLowerCase() === 'medium') return '#ffc107';  // Warning
        if (label.toLowerCase() === 'low') return '#0dcaf0';  // Info
        return getRandomColor();
    });
    
    // Create the chart
    const ctx = document.getElementById('severityChart').getContext('2d');
    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Severity Distribution',
                data: data,
                backgroundColor: colors,
                borderColor: '#343a40',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        color: '#e9ecef'
                    },
                    grid: {
                        color: '#495057'
                    }
                },
                x: {
                    ticks: {
                        color: '#e9ecef'
                    },
                    grid: {
                        color: '#495057'
                    }
                }
            },
            plugins: {
                legend: {
                    display: false
                },
                title: {
                    display: true,
                    text: 'Severity Distribution',
                    color: '#e9ecef',
                    font: {
                        size: 16
                    }
                }
            }
        }
    });
}

// Helper function to generate random colors
function getRandomColor() {
    const letters = '0123456789ABCDEF';
    let color = '#';
    for (let i = 0; i < 6; i++) {
        color += letters[Math.floor(Math.random() * 16)];
    }
    return color;
}
