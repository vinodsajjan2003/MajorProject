// Dark Web Threat Detector - Main JavaScript

document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
    
    // URL scan form handling
    const scanForm = document.getElementById('scan-form');
    if (scanForm) {
        scanForm.addEventListener('submit', function(e) {
            // Show loading indicator
            document.getElementById('scan-button').disabled = true;
            document.getElementById('scan-button').innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Scanning...';
            
            // Continue with form submission
            return true;
        });
    }
    
    // Email report button handling
    const emailReportBtn = document.getElementById('email-report-btn');
    if (emailReportBtn) {
        emailReportBtn.addEventListener('click', function() {
            // Disable button to prevent multiple clicks
            emailReportBtn.disabled = true;
            emailReportBtn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Sending...';
        });
    }
    
    // Configure confident score display
    const confidenceElements = document.querySelectorAll('.confidence-fill');
    confidenceElements.forEach(function(element) {
        const score = parseFloat(element.getAttribute('data-score'));
        element.style.width = `${score * 100}%`;
        
        // Color based on confidence level
        if (score >= 0.8) {
            element.style.backgroundColor = 'var(--bs-success)';
        } else if (score >= 0.6) {
            element.style.backgroundColor = 'var(--bs-primary)';
        } else {
            element.style.backgroundColor = 'var(--bs-danger)';
        }
    });
    
    // Configure severity badges
    const severityBadges = document.querySelectorAll('.severity-badge');
    severityBadges.forEach(function(badge) {
        const severity = badge.textContent.trim().toLowerCase();
        if (severity === 'high') {
            badge.classList.add('bg-danger');
        } else if (severity === 'medium') {
            badge.classList.add('bg-warning', 'text-dark');
        } else if (severity === 'low') {
            badge.classList.add('bg-info', 'text-dark');
        }
    });
    
    // Handle automatic dismissal of alerts after 5 seconds
    const alerts = document.querySelectorAll('.alert-dismissible');
    alerts.forEach(function(alert) {
        setTimeout(function() {
            const bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        }, 5000);
    });
});

// Function to copy content to clipboard
function copyToClipboard(text) {
    navigator.clipboard.writeText(text)
        .then(() => {
            // Show success message
            const toast = document.getElementById('copy-toast');
            if (toast) {
                const bsToast = new bootstrap.Toast(toast);
                bsToast.show();
            }
        })
        .catch(err => {
            console.error('Failed to copy: ', err);
        });
}

// Function to toggle password visibility
function togglePasswordVisibility(inputId) {
    const passwordInput = document.getElementById(inputId);
    const toggleIcon = document.querySelector(`#${inputId} + .input-group-text i`);
    
    if (passwordInput.type === 'password') {
        passwordInput.type = 'text';
        toggleIcon.classList.remove('bi-eye');
        toggleIcon.classList.add('bi-eye-slash');
    } else {
        passwordInput.type = 'password';
        toggleIcon.classList.remove('bi-eye-slash');
        toggleIcon.classList.add('bi-eye');
    }
}
