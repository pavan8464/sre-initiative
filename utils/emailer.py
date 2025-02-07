import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

def send_alert(recipients, message, result):
    sender_email = "pavankalyan8464@gmail.com"  # Your Gmail address
    sender_password = "vadn kqaw xnxb jskp"        # Your Gmail app password
    smtp_server = "smtp.gmail.com"
    smtp_port = 587

    # Setup the MIME message
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = ", ".join(recipients)
    msg['Subject'] = f"Message: {result['status']}"

    # Prepare the email body with host details in an HTML table
    email_body = f"""
    <html>
      <body>
        <p>Dear Recipients,</p>
        <p>You are receiving this email because the host <strong>{result['hostname']}</strong> has a status of: <strong>{result['status']}</strong>.</p>
        <p><strong>Host Details:</strong></p>
        <table border="1" cellpadding="5" cellspacing="0">
          <tr>
            <th>Hostname</th>
            <th>Port</th>
            <th>Reachable</th>
            <th>TLS Version</th>
            <th>Certificate Expiry</th>
            <th>Days Left</th>
            <th>Certificate Issuer</th>
            <th>Certificate Type</th>
            <th>Status</th>
          </tr>
          <tr>
            <td>{result['hostname']}</td>
            <td>{result['port']}</td>
            <td>{'Yes' if result['reachable'] else 'No'}</td>
            <td>{', '.join(result['tls_version']) if result['tls_version'] else 'N/A'}</td>
            <td>{result['certificate'].get('valid_to', 'N/A')}</td>
            <td>{result['days_left'] if result['days_left'] is not None else 'N/A'}</td>
            <td>{result['certificate'].get('issuer', 'N/A')}</td>
            <td>{result['certificate'].get('type', 'N/A')}</td>
            <td>{result['status']}</td>
          </tr>
        </table>
        <p>Kindly review this issue and take appropriate action.</p>
        <p>Regards,<br>GI SRE</p>
      </body>
    </html>
    """

    # Attach the HTML body to the email
    msg.attach(MIMEText(email_body, 'html'))

    try:
        # Create the SMTP session and send the email
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()  # Secure the connection
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, recipients, msg.as_string())
        print("Alert email sent successfully.")
    except Exception as e:
        print(f"Error sending email: {e}")
