import eventlet
eventlet.monkey_patch()  # MUST be the very first lines in your file!

import os
import sys
import csv
import time
from io import StringIO, BytesIO
from flask import Flask, render_template, request, redirect, url_for, jsonify, flash, send_file, session
from flask_socketio import SocketIO
from reportlab.lib.pagesizes import landscape, A3
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch

# Import our utility modules and global variable
from utils.checker import check_host, check_bulk_hosts, process_bulk_ports
from utils.port_scanner import scan_ports, scan_bulk_ports
from utils.emailer import send_alert
from global_data import multi_scan_result, bulk_port_scan_result

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = './uploads'
app.secret_key = 'SRE_initiative'

socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet', manage_session=True)

###############################
#        HOME ROUTE
###############################
@app.route('/')
def home():
    return render_template('index.html')

###############################
#  Certificate Check: Single Host
###############################
@app.route('/certificate_single', methods=['GET'])
def certificate_single_form():
    return render_template('certificate_single.html')

@app.route('/certificate_single_check', methods=['POST'])
def certificate_single_check():
    hostname = request.form.get('hostname')
    port = request.form.get('port')
    if not hostname or not port:
        flash("Hostname and port are required.", "error")
        return redirect(url_for('certificate_single_form'))
    try:
        port = int(port)
    except ValueError:
        flash("Invalid port number.", "error")
        return redirect(url_for('certificate_single_form'))
    result = check_host(hostname, port)
    single_result = {
        "hostname": hostname,
        "checked_ports_range": str(port),
        "common_name": result.get('certificate', {}).get('common_name', 'N/A'),
        "reachable": result.get('reachable'),
        "certificate": result.get('certificate'),
        "tls_version": result.get('tls_version'),
        "days_left": result.get('days_left'),
        "status": result.get('status')
    }
    return render_template('certificate_single_results.html', result=single_result)

###############################
#  Certificate Check: Bulk Hosts
###############################
@app.route('/certificate_bulk', methods=['GET'])
def certificate_bulk_form():
    return render_template('certificate_bulk.html')

@app.route('/bulk', methods=['POST'])
def bulk_check():
    try:
        file = request.files.get('csv_file')
        if not file:
            flash('Please upload a CSV file.', 'error')
            return redirect(url_for('home'))
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        file.save(filepath)
        results = check_bulk_hosts(filepath)
        session['results'] = results
        return redirect(url_for('bulk_results'))
    except Exception as e:
        flash(str(e), 'error')
        return redirect(url_for('home'))

@app.route('/bulk_results')
def bulk_results():
    results = session.get('results', [])
    return render_template('bulk_results.html', results=results)

###############################
#  Port Check: Single Host
###############################
@app.route('/port_single', methods=['GET'])
def port_single_form():
    return render_template('port_single.html')

@app.route('/port_single_results')
def port_single_results():
    return render_template('port_single_results.html', result=multi_scan_result)

###############################
#  Port Check: Bulk Hosts
###############################
# New route for showing the bulk port form
@app.route('/port_bulk', methods=['GET'])
def port_bulk_form():
    return render_template('bulk_port.html')

@app.route('/port_bulk_check', methods=['POST'])
def port_bulk_check():
    file = request.files.get('csv_file')
    if not file:
        flash("Please upload a CSV file.", "error")
        return redirect(url_for('port_bulk_form'))
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    file.save(filepath)
    # Start the bulk scan in a background task using Socket.IO
    socketio.start_background_task(scan_bulk_ports, filepath, socketio)
    # Optionally, save the file path in session
    session['bulk_port_file'] = filepath
    return redirect(url_for('bulk_port_progress'))

@app.route('/bulk_port_progress')
def bulk_port_progress():
    # This page shows the progress of the bulk port scan.
    return render_template('bulk_port_progress.html')

@socketio.on('start_bulk_port_scan', namespace='/bulk')
def handle_start_bulk_port_scan(data):
    file_path = data.get('file_path')
    if file_path:
        scan_bulk_ports(file_path, socketio)

@app.route('/bulk_port_results')
def bulk_port_results():
    results = bulk_port_scan_result
    return render_template('bulk_port_results.html', results=results)

@app.route('/export_bulk_port_csv', methods=['GET'])
def export_bulk_port_csv():
    results = bulk_port_scan_result
    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(['Hostname', 'Start Port', 'End Port', 'Open Ports'])
    for result in results:
        cw.writerow([
            result.get('hostname', 'N/A'),
            result.get('start_port', 'N/A'),
            result.get('end_port', 'N/A'),
            ", ".join(map(str, result.get('open_ports', [])))
        ])
    output = BytesIO()
    output.write(si.getvalue().encode('utf-8'))
    output.seek(0)
    return send_file(output, mimetype='text/csv', as_attachment=True, download_name='bulk_port_results.csv')

@app.route('/export_bulk_port_pdf', methods=['GET'])
def export_bulk_port_pdf():
    results = bulk_port_scan_result
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=landscape(A3))
    elements = []
    styles = getSampleStyleSheet()
    custom_style = ParagraphStyle('Custom', parent=styles["Normal"], fontSize=7, leading=9, wordWrap='CJK')
    headers = ['Hostname', 'Start Port', 'End Port', 'Open Ports']
    data = [headers]
    for result in results:
        row = [
            result.get('hostname', 'N/A'),
            str(result.get('start_port', 'N/A')),
            str(result.get('end_port', 'N/A')),
            ", ".join(map(str, result.get('open_ports', [])))
        ]
        data.append(row)
    colWidths = [1.5*inch, 1*inch, 1*inch, 3*inch]
    table = Table(data, colWidths=colWidths)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.grey),
        ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('GRID', (0,0), (-1,-1), 0.5, colors.black),
        ('FONTSIZE', (0,0), (-1,-1), 7)
    ]))
    elements.append(table)
    doc.build(elements)
    buffer.seek(0)
    return send_file(buffer, mimetype='application/pdf', as_attachment=True, download_name='bulk_port_results.pdf')

###############################
#  Email Alert Route
###############################
@app.route('/send_alert', methods=['POST'])
def send_alert_route():
    try:
        recipients = request.form.get('recipients', '')
        hostname = request.form.get('hostname', '')
        if not recipients:
            return jsonify({'status': 'error', 'message': 'Recipients are required.'}), 400
        recipient_list = [r.strip() for r in recipients.split(',')]
        result = check_host(hostname)
        message = f"Status of the host: {result['status']}"
        send_alert(recipient_list, message, result)
        flash('Alert sent successfully!', 'success')
        return redirect(url_for('send_alert_page', hostname=hostname, recipients=",".join(recipient_list)))
    except Exception as e:
        flash(str(e), 'error')
        return redirect(url_for('send_alert_page', hostname=hostname, recipients=",".join(recipient_list)))

@app.route('/send_alert_page')
def send_alert_page():
    hostname = request.args.get('hostname')
    recipients = request.args.get('recipients', '').split(',')
    result = check_host(hostname)
    return render_template('send_alert_page.html', hostname=hostname, recipients=recipients, result=result)

###############################
#  Socket.IO Events
###############################
@socketio.on('start_port_scan')
def handle_start_port_scan(data):
    hostname = data.get('hostname')
    start_port = int(data.get('start_port'))
    end_port = int(data.get('end_port'))
    # only_ports=True means we scan for open ports without checking certificates
    scan_ports(hostname, start_port, end_port, socketio, only_ports=True)

@socketio.on('start_scan')
def handle_start_scan(data):
    hostname = data.get('hostname')
    start_port = data.get('start_port')
    end_port = data.get('end_port')
    scan_ports(hostname, start_port, end_port, socketio)

###############################
#  Main
###############################
if __name__ == '__main__':
    socketio.run(app, debug=True, use_reloader=False, port=5000)
