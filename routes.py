import os
import pandas as pd
from flask import render_template, redirect, url_for, flash, request, jsonify, send_file
from flask_login import login_user, logout_user, login_required, current_user
# Update for newer Werkzeug versions
from urllib.parse import urlparse
from app import app, db, mail
from models import User, Scan, AutoScanURL
from forms import LoginForm, RegisterForm, URLScanForm, AutoScanURLForm
from utils.scraper import scrape_url_content
from utils.distilbert_model import detect_threat, get_threat_details
from utils.report import generate_pdf_report, send_report_email
from utils.auto_scan import process_auto_scan_url, run_auto_scan_for_user
from datetime import datetime, timedelta
from flask_mail import Message
import logging

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid email or password', 'danger')
            return redirect(url_for('login'))
        
        login_user(user)
        next_page = request.args.get('next')
        if not next_page or urlparse(next_page).netloc != '':
            next_page = url_for('dashboard')
        
        flash('Login successful!', 'success')
        return redirect(next_page)
    
    return render_template('login.html', title='Login', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = RegisterForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html', title='Register', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Get recent scans for the user
    recent_scans = Scan.query.filter_by(user_id=current_user.id).order_by(Scan.created_at.desc()).limit(10).all()
    
    # Calculate statistics
    scan_count = Scan.query.filter_by(user_id=current_user.id).count()
    auto_scan_count = AutoScanURL.query.filter_by(user_id=current_user.id, active=True).count()
    
    # Get threat distribution data for charts
    threat_distribution = {}
    severity_distribution = {}
    
    user_scans = Scan.query.filter_by(user_id=current_user.id).all()
    for scan in user_scans:
        # Threat type distribution
        if scan.threat_type in threat_distribution:
            threat_distribution[scan.threat_type] += 1
        else:
            threat_distribution[scan.threat_type] = 1
            
        # Severity distribution
        if scan.severity in severity_distribution:
            severity_distribution[scan.severity] += 1
        else:
            severity_distribution[scan.severity] = 1
    
    return render_template('dashboard.html', 
                          title='Dashboard', 
                          recent_scans=recent_scans, 
                          scan_count=scan_count,
                          auto_scan_count=auto_scan_count,
                          threat_distribution=threat_distribution,
                          severity_distribution=severity_distribution)

@app.route('/scan', methods=['GET', 'POST'])
@login_required
def scan():
    form = URLScanForm()
    
    if form.validate_on_submit():
        url = form.url.data
        
        # Check if the user has reached scan limit
        one_hour_ago = datetime.utcnow() - timedelta(hours=1)
        scan_count = Scan.query.filter(
            Scan.user_id == current_user.id,
            Scan.created_at >= one_hour_ago
        ).count()
        
        if scan_count >= app.config['MAX_SCANS_PER_HOUR']:
            flash(f'You have reached the maximum scan limit of {app.config["MAX_SCANS_PER_HOUR"]} scans per hour.', 'warning')
            return redirect(url_for('scan'))
        
        try:
            # Scrape content from the URL
            content = scrape_url_content(url)
            
            if not content:
                flash('Failed to retrieve content from the URL or the content is empty.', 'danger')
                return redirect(url_for('scan'))
            
            # Detect threat using the model
            threat_type = detect_threat(content)
            
            # Get threat details from the dataset
            threat_details = get_threat_details(threat_type)
            
            # Create new scan record with enhanced threat details
            new_scan = Scan(
                url=url,
                content=content[:10000],  # Limit content length but allow more text for analysis
                threat_type=threat_type,
                severity=threat_details['severity'],
                confidence_score=threat_details['confidence_score'],
                recommendation=threat_details['recommendation'],
                # Additional fields from the synthetic dataset
                description=threat_details.get('description'),
                ioc=threat_details.get('ioc'),
                source=threat_details.get('source'),
                user_id=current_user.id
            )
            
            db.session.add(new_scan)
            db.session.commit()
            
            flash('URL scanned successfully!', 'success')
            return redirect(url_for('report', scan_id=new_scan.id))
            
        except Exception as e:
            logging.error(f"Error scanning URL: {str(e)}")
            flash(f'Error scanning URL: {str(e)}', 'danger')
            return redirect(url_for('scan'))
    
    return render_template('scan.html', title='Scan URL', form=form)

@app.route('/report/<int:scan_id>')
@login_required
def report(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    
    # Ensure the scan belongs to the current user
    if scan.user_id != current_user.id:
        flash('Access denied. You do not have permission to view this report.', 'danger')
        return redirect(url_for('dashboard'))
    
    return render_template('report.html', title='Threat Report', scan=scan)

@app.route('/download-report/<int:scan_id>')
@login_required
def download_report(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    
    # Ensure the scan belongs to the current user
    if scan.user_id != current_user.id:
        flash('Access denied. You do not have permission to download this report.', 'danger')
        return redirect(url_for('dashboard'))
    
    try:
        # Generate PDF report
        pdf_path = generate_pdf_report(scan)
        
        # Return the PDF file for download
        return send_file(
            pdf_path,
            as_attachment=True,
            download_name=f'threat_report_{scan_id}.pdf',
            mimetype='application/pdf'
        )
    except Exception as e:
        logging.error(f"Error generating PDF report: {str(e)}")
        flash(f'Error generating PDF report: {str(e)}', 'danger')
        return redirect(url_for('report', scan_id=scan_id))

@app.route('/email-report/<int:scan_id>')
@login_required
def email_report(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    
    # Ensure the scan belongs to the current user
    if scan.user_id != current_user.id:
        flash('Access denied. You do not have permission to email this report.', 'danger')
        return redirect(url_for('dashboard'))
    
    try:
        # Generate and send email with the report
        send_report_email(scan, current_user.email)
        
        flash('Report has been sent to your email.', 'success')
    except Exception as e:
        logging.error(f"Error sending report email: {str(e)}")
        flash(f'Error sending report email: {str(e)}', 'danger')
    
    return redirect(url_for('report', scan_id=scan_id))

# Auto-scan URL management routes
@app.route('/auto-scans')
@login_required
def auto_scans():
    """View all auto-scan URLs for the current user"""
    auto_scan_urls = AutoScanURL.query.filter_by(user_id=current_user.id).order_by(AutoScanURL.created_at.desc()).all()
    
    return render_template('auto_scans.html', 
                          title='Automated URL Scans', 
                          auto_scan_urls=auto_scan_urls)

@app.route('/auto-scans/add', methods=['GET', 'POST'])
@login_required
def add_auto_scan():
    """Add a new URL for automatic scanning"""
    form = AutoScanURLForm()
    
    if form.validate_on_submit():
        # Create new auto-scan URL entry
        auto_scan = AutoScanURL(
            url=form.url.data,
            description=form.description.data,
            email_notification=form.email_notification.data,
            notification_email=form.notification_email.data or current_user.email,
            scan_frequency=form.scan_frequency.data,
            active=True,
            user_id=current_user.id
        )
        
        db.session.add(auto_scan)
        db.session.commit()
        
        flash('URL has been added for automatic scanning.', 'success')
        
        # Perform an initial scan
        try:
            scan = process_auto_scan_url(auto_scan)
            if scan:
                flash('Initial scan completed successfully.', 'success')
                return redirect(url_for('report', scan_id=scan.id))
        except Exception as e:
            logging.error(f"Error during initial scan: {str(e)}")
            flash(f'Initial scan failed: {str(e)}', 'warning')
        
        return redirect(url_for('auto_scans'))
    
    return render_template('add_auto_scan.html', title='Add Auto-Scan URL', form=form)

@app.route('/auto-scans/edit/<int:auto_scan_id>', methods=['GET', 'POST'])
@login_required
def edit_auto_scan(auto_scan_id):
    """Edit an existing auto-scan URL"""
    auto_scan = AutoScanURL.query.get_or_404(auto_scan_id)
    
    # Ensure the auto-scan URL belongs to the current user
    if auto_scan.user_id != current_user.id:
        flash('Access denied. You do not have permission to edit this auto-scan URL.', 'danger')
        return redirect(url_for('auto_scans'))
    
    form = AutoScanURLForm(obj=auto_scan)
    
    if form.validate_on_submit():
        auto_scan.url = form.url.data
        auto_scan.description = form.description.data
        auto_scan.email_notification = form.email_notification.data
        auto_scan.notification_email = form.notification_email.data or current_user.email
        auto_scan.scan_frequency = form.scan_frequency.data
        
        db.session.commit()
        
        flash('Auto-scan URL updated successfully.', 'success')
        return redirect(url_for('auto_scans'))
    
    return render_template('edit_auto_scan.html', title='Edit Auto-Scan URL', form=form, auto_scan=auto_scan)

@app.route('/auto-scans/delete/<int:auto_scan_id>')
@login_required
def delete_auto_scan(auto_scan_id):
    """Delete an auto-scan URL"""
    auto_scan = AutoScanURL.query.get_or_404(auto_scan_id)
    
    # Ensure the auto-scan URL belongs to the current user
    if auto_scan.user_id != current_user.id:
        flash('Access denied. You do not have permission to delete this auto-scan URL.', 'danger')
        return redirect(url_for('auto_scans'))
    
    db.session.delete(auto_scan)
    db.session.commit()
    
    flash('Auto-scan URL deleted successfully.', 'success')
    return redirect(url_for('auto_scans'))

@app.route('/auto-scans/toggle/<int:auto_scan_id>')
@login_required
def toggle_auto_scan(auto_scan_id):
    """Toggle the active status of an auto-scan URL"""
    auto_scan = AutoScanURL.query.get_or_404(auto_scan_id)
    
    # Ensure the auto-scan URL belongs to the current user
    if auto_scan.user_id != current_user.id:
        flash('Access denied. You do not have permission to edit this auto-scan URL.', 'danger')
        return redirect(url_for('auto_scans'))
    
    # Toggle active status
    auto_scan.active = not auto_scan.active
    db.session.commit()
    
    status = "activated" if auto_scan.active else "deactivated"
    flash(f'Auto-scan URL {status} successfully.', 'success')
    return redirect(url_for('auto_scans'))

@app.route('/auto-scans/run/<int:auto_scan_id>')
@login_required
def run_auto_scan(auto_scan_id):
    """Manually run an auto-scan for a specific URL"""
    auto_scan = AutoScanURL.query.get_or_404(auto_scan_id)
    
    # Ensure the auto-scan URL belongs to the current user
    if auto_scan.user_id != current_user.id:
        flash('Access denied. You do not have permission to run this auto-scan URL.', 'danger')
        return redirect(url_for('auto_scans'))
    
    try:
        scan = process_auto_scan_url(auto_scan)
        if scan:
            flash('Auto-scan completed successfully.', 'success')
            return redirect(url_for('report', scan_id=scan.id))
        else:
            flash('Failed to process auto-scan URL.', 'danger')
    except Exception as e:
        logging.error(f"Error running auto-scan: {str(e)}")
        flash(f'Error running auto-scan: {str(e)}', 'danger')
    
    return redirect(url_for('auto_scans'))

@app.route('/auto-scans/run-all')
@login_required
def run_all_auto_scans():
    """Manually run all auto-scans for the current user"""
    try:
        count = run_auto_scan_for_user(current_user.id)
        flash(f'Successfully processed {count} auto-scan URLs.', 'success')
    except Exception as e:
        logging.error(f"Error running all auto-scans: {str(e)}")
        flash(f'Error running all auto-scans: {str(e)}', 'danger')
    
    return redirect(url_for('auto_scans'))
