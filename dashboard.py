import os
import re
import mysql.connector
import pandas as pd
from flask import Flask, render_template_string, request, jsonify, redirect, url_for
from datetime import datetime, timedelta
import subprocess

app = Flask(__name__, static_folder='/home/student/static')

# MySQL Configuration
DB_CONFIG = {
    "host": "localhost",
    "user": "student",
    "password": "C00per0!0",
    "database": "squid_logs",
    "ssl_disabled": True
}

# Connect to MySQL
db = mysql.connector.connect(**DB_CONFIG)
cursor = db.cursor(buffered=True)


# Squid log file location
LOG_FILE = "/var/log/squid/access.log"
LOG_FILE2 = "/var/log/c-icap/server.log"

VALID_WEBSITE_REGEX = re.compile(r'\b[a-zA-Z0-9.-]+\.(com|net|org|edu|gov|io|uk|sg|au|ca|jp|fr|de|in)\b')

EXCLUDED_DOMAINS = [
    "cdn.jsdelivr.net", "cdnjs.cloudflare.com", "fonts.googleapis.com",
    "fonts.gstatic.com", "ka-f.fontawesome.com", "use.fontawesome.com",
    "assets.adobedtm.com", "static.cloudflareinsights.com", "assets.wogaa.sg"
]

METHOD = ["CONNECT", "GET", "POST"]
STATUS_CODE = ["NONE_NONE/200", "TCP_HIT/200", "NONE_NONE/403", "TCP_DENIED/200", "TCP_DENIED/403", "TCP_INM_HIT/304"]


# Function to extract domain from URL
def extract_domain(url):
    try:
        match = re.search(r'([a-zA-Z0-9.-]+\.[a-zA-Z]{2,6})$', url)  # Updated regex
        return match.group(1) if match else url
    except:
        return url

def is_valid_website(url):
    domain = extract_domain(url)
    
    # Ignore Google autocomplete requests
    if "google.com/complete/search" in url:
        return False
        
    # Exclude known asset/CDN domains
    if domain in EXCLUDED_DOMAINS:
        return False
        
    #Check if domain is a valid website and not an API
    if "api" in domain or "push" in domain or "safebrowsing" in domain:  # Add more filters as needed
        return False
    return bool(VALID_WEBSITE_REGEX.search(domain))

def save_to_mysql_batch(logs):
    try:
        sql = """INSERT INTO logs (timestamp, client_ip, status_code, method, url, message, process_time, full_log_line)
                 VALUES (%s, %s, %s, %s, %s, %s, %s, %s)"""
        cursor.executemany(sql, logs)
        db.commit()
    except Exception as e:
        print(f"Error saving logs to DB: {e}")
     

def parse_squid_logs():
    logs_to_insert = []
    with open(LOG_FILE, "r") as file:
        for line in file:
            parts = line.split()
            if len(parts) < 8:
                continue

            timestamp, process_time, client_ip, status_code, method, url = parts[0], float(parts[1]), parts[2], parts[3], parts[5], parts[6]
            domain = extract_domain(url)

            # Filter by method and status code
            if str(method) not in METHOD:
                continue

            if str(status_code) not in STATUS_CODE:
                continue

            # Check if the URL is valid (not an API, or any unwanted domain)
            if not is_valid_website(url):
                continue

            timestamp = pd.to_datetime(timestamp, unit='s', errors='coerce')
            if pd.isna(timestamp):
                continue
                
            timestamp = timestamp + timedelta(hours=8) #Convert to Singapore time.

            full_log_line = line.strip()  # Capture the full raw log line

            should_alert = False
            alert_reason = ""

            if status_code in ["TCP_DENIED/200", "TCP_DENIED/403"]:
                should_alert = True
                alert_reason = f"Access to {domain} is forbidden during work hours."

            if should_alert:
                create_alert(client_ip, method, url, alert_reason) 
            
            message = f"Request {method} to {url} resulted in status {status_code}"
            logs_to_insert.append((timestamp.strftime('%Y-%m-%d %H:%M:%S'), client_ip, status_code, method, url, message, process_time, full_log_line))

            if len(logs_to_insert) >= 1000:  # Perform batch insert every 1000 entries
                save_to_mysql_batch(logs_to_insert)
                logs_to_insert.clear()

    if logs_to_insert:
        save_to_mysql_batch(logs_to_insert)  # Insert remaining logs
def parse_icap_logs():
    # Parsing LOG_FILE2 for Virus Found logs
    with open(LOG_FILE2, "r") as file:
        for line in file:
        # Check if the line contains "LOG Virus found"
            if "LOG Virus found" in line:
                # Split the line by commas or spaces (depending on the structure)
                parts = line.split(',')
                
                # Extract Timestamp (first part)
                timestamp = parts[0].strip() if parts else "Unknown"
                
                # Extract URL by searching for "https://"
                url_start = line.find("https://")
                url_end = line.find(" ", url_start) if url_start != -1 else len(line)
                url = line[url_start:url_end].strip() if url_start != -1 else "Unknown"
                
                # Extract Message after the URL (this assumes the message starts right after the URL)
                message_start = url_end
                message = line[message_start:].strip() if message_start < len(line) else "Unknown"
                client_ip = "Unknown"
                method = "GET"
                alert_reason = "Virus detected during download"
                # Print or process the extracted parts
                create_alert(client_ip, method, url,alert_reason)
                
        

def create_alert(client_ip, method, url, message):
    domain = extract_domain(url)

    # Retrieve the existing alert if it exists
    cursor.execute(""" 
        SELECT id, visit_count, status, severity, timestamp FROM alerts 
        WHERE url = %s AND client_ip = %s 
        ORDER BY timestamp DESC LIMIT 1
    """, (domain, client_ip))
    existing_alert = cursor.fetchone()

    SEVERITY_THRESHOLDS = {
        "Low": 10,       # Escalates to Medium
        "Medium": 20,    # Escalates to High
        "High": 30,      # Escalates to Critical
        "Critical": float('inf')
    }

    if existing_alert:
        alert_id, visit_count, status, current_severity, last_timestamp = existing_alert

        # If the alert is resolved, create a new alert for any new activity
        if status == 'Resolved':
            print(f"Alert for {domain} is already resolved. Creating a new alert.")  # Debugging print
            
            # Create a new alert for the new activity (even if the domain/client already had one)
            cursor.execute(""" 
                INSERT INTO alerts (client_ip, method, url, message, severity, visit_count, status, timestamp) 
                VALUES (%s, %s, %s, %s, 'Low', 1, 'Open', NOW())
            """, (client_ip, method, domain, message))
            db.commit()
            print(f"New alert created for {client_ip} - {url}")  # Debugging print
            return  # Skip further processing and don't update the resolved alert

        # If the alert is not resolved, increment the visit count
        new_count = visit_count + 1

        # Determine new severity level based on visit count
        if message == "Virus detected during download":
            new_severity = "Critical"
        elif new_count >= SEVERITY_THRESHOLDS["High"]:
            new_severity = "Critical"
        elif new_count >= SEVERITY_THRESHOLDS["Medium"]:
            new_severity = "High"
        elif new_count >= SEVERITY_THRESHOLDS["Low"]:
            new_severity = "Medium"
        else:
            new_severity = current_severity  # Maintain current severity

        if status in ('Open', 'Acknowledged'):
            if message == "Virus detected during download":
                cursor.execute(""" 
                    UPDATE alerts 
                    SET visit_count = 1, timestamp = NOW(), severity = %s 
                    WHERE id = %s 
                """, (new_severity, alert_id))
                db.commit()
                return
        cursor.execute(""" 
            UPDATE alerts 
            SET visit_count = %s, timestamp = NOW(), severity = %s 
            WHERE id = %s 
        """, (new_count, new_severity, alert_id))
        db.commit()
        return  # Do not create a new alert if we are updating an existing alert

    # Create a new alert if no existing alert was found
    if message == "Virus detected during download":
        cursor.execute(""" 
            INSERT INTO alerts (client_ip, method, url, message, severity, visit_count, status, timestamp) 
            VALUES (%s, %s, %s, %s, 'Critical', 1, 'Open', NOW())
        """, (client_ip, method, domain, message))
        db.commit()
        print(f"New alert created for {client_ip} - {url}")  # Debugging print
    else:
        cursor.execute(""" 
            INSERT INTO alerts (client_ip, method, url, message, severity, visit_count, status, timestamp) 
            VALUES (%s, %s, %s, %s, 'Low', 1, 'Open', NOW())
        """, (client_ip, method, domain, message))
        db.commit()
        print(f"New alert created for {client_ip} - {url}")  # Debugging print


# Flask Web App
app = Flask(__name__)

HOME_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Squid Proxy Dashboard</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='dashboard.css') }}">
    <link rel="stylesheet" type="text/css" href="https://unpkg.com/phosphor-icons@1.4.2/src/css/icons.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
<div class="app">
	<header class="app-header">
		<div class="app-header-logo">
			<div class="logo">
				<span class="logo-icon">
					<img src="https://assets.codepen.io/285131/almeria-logo.svg" />
				</span>
				<h1 class="logo-title">
					<span>XYZ</span>
				</h1>f
			</div>
		</div>
		<div class="app-header-navigation">
			<div class="tabs">
				<a href="/" class="active">
					Dashboard
				</a>
				<a href="/alerts">
					Alerts
				</a>
				<a href="/cases">
					Cases
				</a>
				<a href="/caching">
					Caching
				</a>
			<form method="GET" action="/">
			<div class="box">
                <input type="text" class="input search-input" name="search" onmouseout="this.value = ''; this.blur();" placeholder="Search URL or Status Code" value="{{ search_query }}">
            </div>
            <button class="button-33" type="button" id="refreshBtn">Refresh</button>
            </form>
		</div>

	</header>
		<div class="app-body-main-content">
				<div class="tiles">
                    <article class="tile">
					    <div class="tile-header">
						    <i class="ph ph-gauge"></i>
						    <h3>
							    <span>Total logs</span>
							    <span id="logCounter">{{ total_logs }}</span>
						    </h3>
					    </div>
					    <a href="/">
						    <span>Dashboard</span>
						    <span class="icon-button">
							    <i class="ph-caret-right-bold"></i>
						    </span>
					    </a>
					</article>
					<article class="tile">
						<div class="tile-header">
							<i class="ph ph-alarm"></i>
							<h3>
								<span>Open alerts</span>
								<span id="logCounter">{{ total_alerts }}</span>
							</h3>
						</div>
						<a href="/alerts">
							<span>Go to alerts</span>
							<span class="icon-button">
								<i class="ph-caret-right-bold"></i>
							</span>
						</a>
					</article>
					<article class="tile">
						<div class="tile-header">
							<i class="ph ph-briefcase"></i>
							<h3>
								<span>Open cases</span>
								<span id="logCounter">{{ total_cases }}</span>
							</h3>
						</div>
						<a href="cases">
							<span>Go to cases</span>
							<span class="icon-button">
								<i class="ph-caret-right-bold"></i>
							</span>
						</a>
					</article>
					<article class="tile">
						<div class="tile-header">
							<i class="ph ph-address-book"></i>
							<h3>
								<span>Cache logs</span>
								<span id="logCounter">{{ total_cache}}</span>
							</h3>
						</div>
						<a href="/caching">
							<span>Go to cache</span>
							<span class="icon-button">
								<i class="ph-caret-right-bold"></i>
							</span>
						</a>
					</article>
					<article>
                        <h3>Most visited websites</h3>
                        <canvas id="visitChart" width="400" height="400"></canvas>
                    </article>
                    
				</div>
			<section class="transfer-section">
			    <div class="table-wrapper">
                <table class="fl-table">
                    <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>Client IP</th>
                        <th>Status Code</th>
                        <th>Method</th>
                        <th>URL</th>
	                <th>More Info</th>
                    </tr>
                    </thead>
                    <tbody>
                    {% for log in logs %}
                    <tr class="log-row" on click="toggleDetails(this)">
                        <tr>
                        <td>{{ log['Timestamp'] }} SGT</td>
                        <td>{{ log['Client IP'] }}</td>
                        <td>{{ log['Status Code'] }}</td>
                        <td>{{ log['Method'] }}</td>
                        <td><a href="https://{{ log['URL'] }}" target="_blank">{{ log['URL'] }}</a></td>
	                    <td><button class="expand-btn" onclick="toggleDetails(this)">Expand</button></td>
	                    </tr>
                    </tr>
	                <tr class="log-details hidden">
		                <td colspan="6">
			                <strong>Message:</strong> {{ log['Message'] }} <br>
			                <strong>Full Log:</strong> {{ log['Full Log'] }} <br>
		                </td>
	                </tr>
                        {% endfor %}
                    <tbody>
                </table>
            </div>
            <footer class="footer">
				<div class="bottom-controls">
                    <form action="/clear-logs" method="POST" onsubmit="return confirm('Are you sure you want to clear all logs?');">
                        <button type="submit" class="clear-logs-btn">🗑️ Clear Logs</button>
                    </form>

                    <div class="pagination">
                        <a href="?page={{ page - 1 }}" {% if page == 1 %}style="visibility: hidden;"{% endif %}>&laquo;</a>
                        <span>{{ page }}</span>
                        <a href="?page={{ page + 1 }}" {% if page == total_pages %}style="visibility: hidden;"{% endif %}>&raquo;</a>
                    </div>
                </div>
			</footer>
			</section>
		</div>
	</div>
</div>

<script>
    function loadPieChart() {
        fetch('/website-data')
        .then(response => response.json())
        .then(data => {
            let ctx = document.getElementById('visitChart').getContext('2d');
            new Chart(ctx, {
                type: 'pie',
                data: {
                    labels: data.labels,
                    datasets: [{
                        data: data.counts,
                        backgroundColor: ['#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', '#9966FF']
                    }]
                }
            });
        })
        .catch(error => console.error("Error loading chart data:", error));
    }
    document.addEventListener("DOMContentLoaded", loadPieChart);
</script>
<script>
	function toggleDetails(button) {
		let row = button.closest("tr");
		let detailsRow = row.nextElementSibling;
		if (detailsRow && detailsRow.classList.contains("log-details")) {
			detailsRow.classList.toggle("hidden");
			button.textContent = detailsRow.classList.contains("hidden") ? "Expand" : "Collapse";
		}
    }
    </script>
<script>
    document.getElementById("refreshBtn").addEventListener("click", function() {
        location.reload();  // Refreshes the page
    });
</script>
</body>
</html>
"""

ALERTS_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Alerts Dashboard</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='alerts.css') }}">
    <link rel="stylesheet" type="text/css" href="https://unpkg.com/phosphor-icons@1.4.2/src/css/icons.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
<div class="app">
	<header class="app-header">
		<div class="app-header-logo">
			<div class="logo">
				<span class="logo-icon">
					<img src="https://assets.codepen.io/285131/almeria-logo.svg" />
				</span>
				<h1 class="logo-title">
					<span>XYZ</span>
				</h1>
			</div>
		</div>
		<div class="app-header-navigation">
			<div class="tabs">
				<a href="/">
					Dashboard
				</a>
				<a href="/alerts" class="active">
					Alerts
				</a>
				<a href="/cases">
					Cases
				</a>
				<a href="/caching">
					Caching
				</a>
            <button class="button-33" type="button" id="refreshBtn">Refresh</button>
		</div>

	</header>
		<div class="app-body-main-content">
				<div class="tiles">
                    <article class="tile">
					    <div class="tile-header">
						    <i class="ph ph-gauge"></i>
						    <h3>
							    <span>Total Alerts</span>
							    <span id="logCounter">{{ total_alerts }}</span>
						    </h3>
					    </div>
					    <a href="/alerts">
						    <span>Alerts</span>
						    <span class="icon-button">
							    <i class="ph-caret-right-bold"></i>
						    </span>
					    </a>
					</article>
					<article>
						<h3>Severity</h3>
                        <canvas id="severityChart" width="400" height="400"></canvas>
					</article>
					<article>
                        <h3>Alert count</h3>
                        <canvas id="visitChart" width="400" height="400"></canvas>
                    </article>
				</div>
				<div class="tiles2">
                    <article class="tile">
					    <div class="tile-header">
						    <i class="ph ph-gauge"></i>
						    <h3>
							    <span>Total Open Alerts</span>
							    <span id="logCounter">{{ total_open_alerts }}</span>
						    </h3>
					    </div>
					    <a href="/alerts/open">
						    <span>Go to open alerts</span>
						    <span class="icon-button">
							    <i class="ph-caret-right-bold"></i>
						    </span>
					    </a>
					</article>
					<article class="tile">
						<div class="tile-header">
							<i class="ph ph-alarm"></i>
							<h3>
								<span>Total Acknowledged Alerts</span>
								<span id="logCounter">{{ total_acknowledged_alerts }}</span>
							</h3>
						</div>
						<a href="/alerts/acknowledged">
							<span>Go to acknowledged alerts</span>
							<span class="icon-button">
								<i class="ph-caret-right-bold"></i>
							</span>
						</a>
					</article>
					<article class="tile">
						<div class="tile-header">
							<i class="ph ph-briefcase"></i>
							<h3>
								<span>Total Closed Alerts</span>
								<span id="logCounter">{{ total_closed_alerts }}</span>
							</h3>
						</div>
						<a href="/alerts/closed">
							<span>Go to closed alerts</span>
							<span class="icon-button">
								<i class="ph-caret-right-bold"></i>
							</span>
						</a>
					</article>
				</div>
				<footer class="footer">
				<div class="bottom-controls">
                    <form action="/clear-alerts" method="POST" onsubmit="return confirm('Are you sure you want to clear all alerts and cases?');">
                        <button type="submit" class="clear-logs-btn">🗑️ Clear Alerts & Cases</button>
                    </form>
                </div>
			</footer>
				
			
<script>
    function loadPieChart() {
        fetch('/alert-data')
        .then(response => response.json())
        .then(data => {
            let ctx = document.getElementById('visitChart').getContext('2d');
            new Chart(ctx, {
                type: 'pie',
                data: {
                    labels: data.labels,
                    datasets: [{
                        data: data.counts,
                        backgroundColor: ['#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', '#9966FF']
                    }]
                }
            });
        })
        .catch(error => console.error("Error loading chart data:", error));
    }
    document.addEventListener("DOMContentLoaded", loadPieChart);
</script>
<script>
    function severityPieChart() {
        fetch('/alert-data')
        .then(response => response.json())
        .then(data => {
            const severityColors = {
                "Critical": "#FF0000",  // red
                "High": "#FF4500",      // orange red
                "Medium": "#FFA500",    // orange
                "Low": "#00FF00"        // green
                // Add more severity levels as needed
            };
                
            const backgroundColors = data.severity_labels.map(label => {
            return severityColors[label] || "#CCCCCC"; // Default color if label not found
            });
            
            let ctx = document.getElementById('severityChart').getContext('2d');
            new Chart(ctx, {
                type: 'pie',
                data: {
                    labels: data.severity_labels,
                    datasets: [{
                        data: data.severity_counts,
                        backgroundColor: backgroundColors
                    }]
                }
            });
        })
        .catch(error => console.error("Error loading chart data:", error));
    }
    document.addEventListener("DOMContentLoaded", severityPieChart);
</script>
<script>
	function toggleDetails(button) {
		let row = button.closest("tr");
		let detailsRow = row.nextElementSibling;
		if (detailsRow && detailsRow.classList.contains("log-details")) {
			detailsRow.classList.toggle("hidden");
			button.textContent = detailsRow.classList.contains("hidden") ? "Expand" : "Collapse";
		}
    }
    </script>
<script>
    document.getElementById("refreshBtn").addEventListener("click", function() {
        location.reload();  // Refreshes the page
    });
</script>
</body>
</html>
"""

ALERTS_OPEN_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Squid Proxy Dashboard</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='alerts_open.css') }}">
    <link rel="stylesheet" type="text/css" href="https://unpkg.com/phosphor-icons@1.4.2/src/css/icons.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
<div class="app">
	<header class="app-header">
		<div class="app-header-logo">
			<div class="logo">
				<span class="logo-icon">
					<img src="https://assets.codepen.io/285131/almeria-logo.svg" />
				</span>
				<h1 class="logo-title">
					<span>XYZ</span>
				</h1>
			</div>
		</div>
		<div class="app-header-navigation">
			<div class="tabs">
				<a href="/">
					Dashboard
				</a>
				<a href="/alerts" class="active"">
					Alerts
				</a>
				<a href="/cases">
					Cases
				</a>
				<a href="/caching">
					Caching
				</a>
			<form method="GET" action="/alerts/open">
            <button class="button-33" type="button" id="refreshBtn">Refresh</button>
            </form>
		</div>

	</header>
		<div class="app-body-main-content">
				<div class="tiles">
                    <article class="tile">
					    <div class="tile-header">
						    <i class="ph ph-gauge"></i>
						    <h3>
							    <span>Total Open Alerts</span>
							    <span id="logCounter">{{ total_open_alerts }}</span>
						    </h3>
					    </div>
					    <a href="/alerts">
						    <span>Go to alerts summary</span>
						    <span class="icon-button">
							    <i class="ph-caret-right-bold"></i>
						    </span>
					    </a>
					</article>
					<article>
                        <h3>Severity</h3>
                        <canvas id="severityChart" width="400" height="400"></canvas>
                    </article>
					<article>
                        <h3>Alert count</h3>
                        <canvas id="visitChart" width="400" height="400"></canvas>
                    </article>
                    
				</div>
			<section class="transfer-section">
			    <div class="table-wrapper">
                <table class="fl-table">
                    <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>Client IP</th>
                        <th>Method</th>
                        <th>URL</th>
                        <th>Message</th>
                        <th>Severity</th>
                        <th>Assigned To</th>
                        <th>Status</th>
                        <th>Actions</th>
                    </tr>
                    </thead>
                    <tbody>
                    {% for alert in alerts %}
                    <tr class="log-row" on click="toggleDetails(this)">
                        <tr>
                        <td>{{ alert['timestamp'] }}</td>
                        <td>{{ alert['client_ip'] }}</td>
                        <td>{{ alert['method'] }}</td>
                        <td><a href="{{ alert['url'] }}" target="_blank">{{ alert['url'] }}</a></td>
                        <td>{{ alert['message'] }}</td>
                        <td>{{ alert['severity'] }}</td>
                        <td>{{ alert['assigned_to'] }}</td>
                        <td>{{ alert['status'] }}</td>
                        <td class="actions">
	                        <button class="expand-btn" onclick="toggleDetails(this)">Expand</button>
	                        <button class="expand-btn" onclick="window.location.href='/create-case?alert_id={{ alert['id'] }}'">Create Case</button>
	                    </td>
	                    </tr>
                    </tr>
                    <tr class="log-details hidden">
                        <td colspan="9">
                            <strong>Alert Visits:</strong> {{ alert['visit_count'] }} <br>
                        </td>
                    </tr>
                        {% endfor %}
                    <tbody>
                </table>
            </div>
            <footer class="footer">
				<div class="bottom-controls">
                    <form action="/clear-logs" style="visibility: hidden;" method="POST" onsubmit="return confirm('Are you sure you want to clear all logs?');">
                        <button type="submit" class="clear-logs-btn">🗑️ Clear Logs</button>
                    </form>

                    <div class="pagination">
                        <a href="?page={{ page - 1 }}" {% if page == 1 %}style="visibility: hidden;"{% endif %}>&laquo;</a>
                        <span>{{ page }}</span>
                        <a href="?page={{ page + 1 }}" {% if page == total_pages %}style="visibility: hidden;"{% endif %}>&raquo;</a>
                    </div>
                </div>
			</footer>
			</section>
		</div>
	</div>
</div>

<script>
    function loadPieChart() {
        fetch('/alert-data')
        .then(response => response.json())
        .then(data => {
            let ctx = document.getElementById('visitChart').getContext('2d');
            new Chart(ctx, {
                type: 'pie',
                data: {
                    labels: data.open_labels,
                    datasets: [{
                        data: data.open_counts,
                        backgroundColor: ['#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', '#9966FF']
                    }]
                }
            });
        })
        .catch(error => console.error("Error loading chart data:", error));
    }
    document.addEventListener("DOMContentLoaded", loadPieChart);
</script>
<script>
    function severityPieChart() {
        fetch('/alert-data')
        .then(response => response.json())
        .then(data => {
            const severityColors = {
                "Critical": "#FF0000",  // red
                "High": "#FF4500",      // orange red
                "Medium": "#FFA500",    // orange
                "Low": "#00FF00"        // green
                // Add more severity levels as needed
            };
                
            const backgroundColors = data.severity_labels.map(label => {
            return severityColors[label] || "#CCCCCC"; // Default color if label not found
            });
            
            let ctx = document.getElementById('severityChart').getContext('2d');
            new Chart(ctx, {
                type: 'pie',
                data: {
                    labels: data.open_severity_labels,
                    datasets: [{
                        data: data.open_severity_counts,
                        backgroundColor: backgroundColors
                    }]
                }
            });
        })
        .catch(error => console.error("Error loading chart data:", error));
    }
    document.addEventListener("DOMContentLoaded", severityPieChart);
</script>
<script>
	function toggleDetails(button) {
		let row = button.closest("tr");
		let detailsRow = row.nextElementSibling;
		if (detailsRow && detailsRow.classList.contains("log-details")) {
			detailsRow.classList.toggle("hidden");
			button.textContent = detailsRow.classList.contains("hidden") ? "Expand" : "Collapse";
		}
    }
    </script>
<script>
    document.getElementById("refreshBtn").addEventListener("click", function() {
        location.reload();  // Refreshes the page
    });
</script>
</body>
</html>
"""
ALERTS_ACKNOWLEDGED_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Squid Proxy Dashboard</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='alerts_acknowledged.css') }}">
    <link rel="stylesheet" type="text/css" href="https://unpkg.com/phosphor-icons@1.4.2/src/css/icons.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
<div class="app">
	<header class="app-header">
		<div class="app-header-logo">
			<div class="logo">
				<span class="logo-icon">
					<img src="https://assets.codepen.io/285131/almeria-logo.svg" />
				</span>
				<h1 class="logo-title">
					<span>XYZ</span>
				</h1>
			</div>
		</div>
		<div class="app-header-navigation">
			<div class="tabs">
				<a href="/">
					Dashboard
				</a>
				<a href="/alerts" class="active"">
					Alerts
				</a>
				<a href="/cases">
					Cases
				</a>
				<a href="/caching">
					Caching
				</a>
			<form method="GET" action="/">
            <button class="button-33" type="button" id="refreshBtn">Refresh</button>
            </form>
		</div>

	</header>
		<div class="app-body-main-content">
				<div class="tiles">
                    <article class="tile">
					    <div class="tile-header">
						    <i class="ph ph-gauge"></i>
						    <h3>
							    <span>Total Acknowledged Alerts</span>
							    <span id="logCounter">{{ total_acknowledged_alerts }}</span>
						    </h3>
					    </div>
					    <a href="/alerts">
						    <span>Go to alerts summary</span>
						    <span class="icon-button">
							    <i class="ph-caret-right-bold"></i>
						    </span>
					    </a>
					</article>
					<article>
                        <h3>Severity</h3>
                        <canvas id="severityChart" width="400" height="400"></canvas>
                    </article>
					<article>
                        <h3>Alert count</h3>
                        <canvas id="visitChart" width="400" height="400"></canvas>
                    </article>
                    
				</div>
			<section class="transfer-section">
			    <div class="table-wrapper">
                <table class="fl-table">
                    <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>Client IP</th>
                        <th>Method</th>
                        <th>URL</th>
                        <th>Message</th>
                        <th>Severity</th>
                        <th>Assigned To</th>
                        <th>Status</th>
                        <th>Actions</th>
                    </tr>
                    </thead>
                    <tbody>
                    {% for alert in alerts %}
                    <tr class="log-row" on click="toggleDetails(this)">
                        <tr>
                        <td>{{ alert['timestamp'] }}</td>
                        <td>{{ alert['client_ip'] }}</td>
                        <td>{{ alert['method'] }}</td>
                        <td><a href="{{ alert['url'] }}" target="_blank">{{ alert['url'] }}</a></td>
                        <td>{{ alert['message'] }}</td>
                        <td>{{ alert['severity'] }}</td>
                        <td>{{ alert['assigned_to'] }}</td>
                        <td>{{ alert['status'] }}</td>
                        <td class="actions">
	                        <button class="expand-btn" onclick="toggleDetails(this)">Expand</button>
	                    </td>
	                    </tr>
                    </tr>
                    <tr class="log-details hidden">
                        <td colspan="9">
                            <strong>Alert Visits:</strong> {{ alert['visit_count'] }} <br>
                        </td>
                    </tr>
                        {% endfor %}
                    <tbody>
                </table>
            </div>
            <footer class="footer">
				<div class="bottom-controls">
                    <form action="/clear-logs" style="visibility: hidden;" method="POST" onsubmit="return confirm('Are you sure you want to clear all logs?');">
                        <button type="submit" class="clear-logs-btn">🗑️ Clear Logs</button>
                    </form>

                    <div class="pagination">
                        <a href="?page={{ page - 1 }}" {% if page == 1 %}style="visibility: hidden;"{% endif %}>&laquo;</a>
                        <span>{{ page }}</span>
                        <a href="?page={{ page + 1 }}" {% if page == total_pages %}style="visibility: hidden;"{% endif %}>&raquo;</a>
                    </div>
                </div>
			</footer>
			</section>
		</div>
	</div>
</div>

<script>
    function loadPieChart() {
        fetch('/alert-data')
        .then(response => response.json())
        .then(data => {
            let ctx = document.getElementById('visitChart').getContext('2d');
            new Chart(ctx, {
                type: 'pie',
                data: {
                    labels: data.acknowledged_labels,
                    datasets: [{
                        data: data.acknowledged_counts,
                        backgroundColor: ['#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', '#9966FF']
                    }]
                }
            });
        })
        .catch(error => console.error("Error loading chart data:", error));
    }
    document.addEventListener("DOMContentLoaded", loadPieChart);
</script>
<script>
    function severityPieChart() {
        fetch('/alert-data')
        .then(response => response.json())
        .then(data => {
            const severityColors = {
                "Critical": "#FF0000",  // red
                "High": "#FF4500",      // orange red
                "Medium": "#FFA500",    // orange
                "Low": "#00FF00"        // green
                // Add more severity levels as needed
            };
                
            const backgroundColors = data.severity_labels.map(label => {
            return severityColors[label] || "#CCCCCC"; // Default color if label not found
            });
            
            let ctx = document.getElementById('severityChart').getContext('2d');
            new Chart(ctx, {
                type: 'pie',
                data: {
                    labels: data.acknowledged_severity_labels,
                    datasets: [{
                        data: data.acknowledged_severity_counts,
                        backgroundColor: backgroundColors
                    }]
                }
            });
        })
        .catch(error => console.error("Error loading chart data:", error));
    }
    document.addEventListener("DOMContentLoaded", severityPieChart);
</script>
<script>
	function toggleDetails(button) {
		let row = button.closest("tr");
		let detailsRow = row.nextElementSibling;
		if (detailsRow && detailsRow.classList.contains("log-details")) {
			detailsRow.classList.toggle("hidden");
			button.textContent = detailsRow.classList.contains("hidden") ? "Expand" : "Collapse";
		}
    }
    </script>
<script>
    document.getElementById("refreshBtn").addEventListener("click", function() {
        location.reload();  // Refreshes the page
    });
</script>
</body>
</html>
"""

ALERTS_CLOSED_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Squid Proxy Dashboard</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='alerts_closed.css') }}">
    <link rel="stylesheet" type="text/css" href="https://unpkg.com/phosphor-icons@1.4.2/src/css/icons.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
<div class="app">
	<header class="app-header">
		<div class="app-header-logo">
			<div class="logo">
				<span class="logo-icon">
					<img src="https://assets.codepen.io/285131/almeria-logo.svg" />
				</span>
				<h1 class="logo-title">
					<span>XYZ</span>
				</h1>
			</div>
		</div>
		<div class="app-header-navigation">
			<div class="tabs">
				<a href="/">
					Dashboard
				</a>
				<a href="/alerts" class="active"">
					Alerts
				</a>
				<a href="/cases">
					Cases
				</a>
				<a href="/caching">
					Caching
				</a>
			<form method="GET" action="/">
            <button class="button-33" type="button" id="refreshBtn">Refresh</button>
            </form>
		</div>

	</header>
		<div class="app-body-main-content">
				<div class="tiles">
                    <article class="tile">
					    <div class="tile-header">
						    <i class="ph ph-gauge"></i>
						    <h3>
							    <span>Total Closed Alerts</span>
							    <span id="logCounter">{{ total_closed_alerts }}</span>
						    </h3>
					    </div>
					    <a href="/alerts">
						    <span>Go to alerts summary</span>
						    <span class="icon-button">
							    <i class="ph-caret-right-bold"></i>
						    </span>
					    </a>
					</article>
					<article>
                        <h3>Severity</h3>
                        <canvas id="severityChart" width="400" height="400"></canvas>
                    </article>
					<article>
                        <h3>Alert count</h3>
                        <canvas id="visitChart" width="400" height="400"></canvas>
                    </article>
                    
				</div>
			<section class="transfer-section">
			    <div class="table-wrapper">
                <table class="fl-table">
                    <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>Client IP</th>
                        <th>Method</th>
                        <th>URL</th>
                        <th>Message</th>
                        <th>Severity</th>
                        <th>Assigned To</th>
                        <th>Status</th>
                        <th>Actions</th>
                    </tr>
                    </thead>
                    <tbody>
                    {% for alert in alerts %}
                    <tr class="log-row" on click="toggleDetails(this)">
                        <tr>
                        <td>{{ alert['timestamp'] }}</td>
                        <td>{{ alert['client_ip'] }}</td>
                        <td>{{ alert['method'] }}</td>
                        <td><a href="{{ alert['url'] }}" target="_blank">{{ alert['url'] }}</a></td>
                        <td>{{ alert['message'] }}</td>
                        <td>{{ alert['severity'] }}</td>
                        <td>{{ alert['assigned_to'] }}</td>
                        <td>{{ alert['status'] }}</td>
                        <td class="actions">
	                        <button class="expand-btn" onclick="toggleDetails(this)">Expand</button>
	                    </td>
	                    </tr>
                    </tr>
                    <tr class="log-details hidden">
                        <td colspan="9">
                            <strong>Alert Visits:</strong> {{ alert['visit_count'] }} <br>
                        </td>
                    </tr>
                        {% endfor %}
                    <tbody>
                </table>
            </div>
            <footer class="footer">
				<div class="bottom-controls">
                    <form action="/clear-logs" style="visibility: hidden;" method="POST" onsubmit="return confirm('Are you sure you want to clear all logs?');">
                        <button type="submit" class="clear-logs-btn">🗑️ Clear Logs</button>
                    </form>

                    <div class="pagination">
                        <a href="?page={{ page - 1 }}" {% if page == 1 %}style="visibility: hidden;"{% endif %}>&laquo;</a>
                        <span>{{ page }}</span>
                        <a href="?page={{ page + 1 }}" {% if page == total_pages %}style="visibility: hidden;"{% endif %}>&raquo;</a>
                    </div>
                </div>
			</footer>
			</section>
		</div>
	</div>
</div>

<script>
    function loadPieChart() {
        fetch('/alert-data')
        .then(response => response.json())
        .then(data => {
            let ctx = document.getElementById('visitChart').getContext('2d');
            new Chart(ctx, {
                type: 'pie',
                data: {
                    labels: data.closed_labels,
                    datasets: [{
                        data: data.closed_counts,
                        backgroundColor: ['#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', '#9966FF']
                    }]
                }
            });
        })
        .catch(error => console.error("Error loading chart data:", error));
    }
    document.addEventListener("DOMContentLoaded", loadPieChart);
</script>
<script>
    function severityPieChart() {
        fetch('/alert-data')
        .then(response => response.json())
        .then(data => {
            const severityColors = {
                "Critical": "#FF0000",  // red
                "High": "#FF4500",      // orange red
                "Medium": "#FFA500",    // orange
                "Low": "#00FF00"        // green
                // Add more severity levels as needed
            };
                
            const backgroundColors = data.severity_labels.map(label => {
            return severityColors[label] || "#CCCCCC"; // Default color if label not found
            });
            
            let ctx = document.getElementById('severityChart').getContext('2d');
            new Chart(ctx, {
                type: 'pie',
                data: {
                    labels: data.closed_severity_labels,
                    datasets: [{
                        data: data.closed_severity_counts,
                        backgroundColor: backgroundColors
                    }]
                }
            });
        })
        .catch(error => console.error("Error loading chart data:", error));
    }
    document.addEventListener("DOMContentLoaded", severityPieChart);
</script>
<script>
	function toggleDetails(button) {
		let row = button.closest("tr");
		let detailsRow = row.nextElementSibling;
		if (detailsRow && detailsRow.classList.contains("log-details")) {
			detailsRow.classList.toggle("hidden");
			button.textContent = detailsRow.classList.contains("hidden") ? "Expand" : "Collapse";
		}
    }
    </script>
<script>
    document.getElementById("refreshBtn").addEventListener("click", function() {
        location.reload();  // Refreshes the page
    });
</script>
</body>
</html>
"""

CASES_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cases Dashboard</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='cases.css') }}">
    <link rel="stylesheet" type="text/css" href="https://unpkg.com/phosphor-icons@1.4.2/src/css/icons.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
<div class="app">
	<header class="app-header">
		<div class="app-header-logo">
			<div class="logo">
				<span class="logo-icon">
					<img src="https://assets.codepen.io/285131/almeria-logo.svg" />
				</span>
				<h1 class="logo-title">
					<span>XYZ</span>
				</h1>
			</div>
		</div>
		<div class="app-header-navigation">
			<div class="tabs">
				<a href="/">
					Dashboard
				</a>
				<a href="/alerts">
					Alerts
				</a>
				<a href="/cases" class="active">
					Cases
				</a>
				<a href="/caching">
					Caching
				</a>
            <button class="button-33" type="button" id="refreshBtn">Refresh</button>
		</div>

	</header>
		<div class="app-body-main-content">
				<div class="tiles">
                    <article class="tile">
					    <div class="tile-header">
						    <i class="ph ph-gauge"></i>
						    <h3>
							    <span>Total Cases</span>
							    <span id="logCounter">{{ total_cases }}</span>
						    </h3>
					    </div>
					    <a href="/cases">
						    <span>Cases</span>
						    <span class="icon-button">
							    <i class="ph-caret-right-bold"></i>
						    </span>
					    </a>
					</article>
					<article>
						<h3>Severity</h3>
                        <canvas id="severityChart" width="400" height="400"></canvas>
					</article>
					<article>
                        <h3>Case count</h3>
                        <canvas id="visitChart" width="400" height="400"></canvas>
                    </article>
				</div>
				<div class="tiles2">
					<article class="tile">
						<div class="tile-header">
							<i class="ph ph-alarm"></i>
							<h3>
								<span>Total ongoing Cases</span>
								<span id="logCounter">{{ total_ip_cases }}</span>
							</h3>
						</div>
						<a href="/cases/ip">
							<span>Go to ongoing cases</span>
							<span class="icon-button">
								<i class="ph-caret-right-bold"></i>
							</span>
						</a>
					</article>
					<article class="tile">
						<div class="tile-header">
							<i class="ph ph-briefcase"></i>
							<h3>
								<span>Total Closed cases</span>
								<span id="logCounter">{{ total_closed_cases }}</span>
							</h3>
						</div>
						<a href="/cases/closed">
							<span>Go to closed cases</span>
							<span class="icon-button">
								<i class="ph-caret-right-bold"></i>
							</span>
						</a>
					</article>
				</div>
				<footer class="footer">
				<div class="bottom-controls">
                    <form action="/clear-cases" method="POST" onsubmit="return confirm('Are you sure you want to clear all alerts and cases?');">
                        <button type="submit" class="clear-logs-btn">🗑️ Clear Alerts & Cases</button>
                    </form>
                </div>
			</footer>
				
<script>
    function loadPieChart() {
        fetch('/case-data')
        .then(response => response.json())
        .then(data => {
            let ctx = document.getElementById('visitChart').getContext('2d');
            new Chart(ctx, {
                type: 'pie',
                data: {
                    labels: data.labels,
                    datasets: [{
                        data: data.counts,
                        backgroundColor: ['#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', '#9966FF']
                    }]
                }
            });
        })
        .catch(error => console.error("Error loading chart data:", error));
    }
    document.addEventListener("DOMContentLoaded", loadPieChart);
</script>
<script>
    function severityPieChart() {
        fetch('/case-data')
        .then(response => response.json())
        .then(data => {
            const severityColors = {
                "Critical": "#FF0000",  // red
                "High": "#FF4500",      // orange red
                "Medium": "#FFA500",    // orange
                "Low": "#00FF00"        // green
                // Add more severity levels as needed
            };
                
            const backgroundColors = data.severity_labels.map(label => {
            return severityColors[label] || "#CCCCCC"; // Default color if label not found
            });
            
            let ctx = document.getElementById('severityChart').getContext('2d');
            new Chart(ctx, {
                type: 'pie',
                data: {
                    labels: data.severity_labels,
                    datasets: [{
                        data: data.severity_counts,
                        backgroundColor: backgroundColors
                    }]
                }
            });
        })
        .catch(error => console.error("Error loading chart data:", error));
    }
    document.addEventListener("DOMContentLoaded", severityPieChart);
</script>
<script>
	function toggleDetails(button) {
		let row = button.closest("tr");
		let detailsRow = row.nextElementSibling;
		if (detailsRow && detailsRow.classList.contains("log-details")) {
			detailsRow.classList.toggle("hidden");
			button.textContent = detailsRow.classList.contains("hidden") ? "Expand" : "Collapse";
		}
    }
    </script>
<script>
    document.getElementById("refreshBtn").addEventListener("click", function() {
        location.reload();  // Refreshes the page
    });
</script>
</body>
</html>
"""

CASES_IP_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Squid Proxy Dashboard</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='cases_ip.css') }}">
    <link rel="stylesheet" type="text/css" href="https://unpkg.com/phosphor-icons@1.4.2/src/css/icons.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
<div class="app">
	<header class="app-header">
		<div class="app-header-logo">
			<div class="logo">
				<span class="logo-icon">
					<img src="https://assets.codepen.io/285131/almeria-logo.svg" />
				</span>
				<h1 class="logo-title">
					<span>XYZ</span>
				</h1>
			</div>
		</div>
		<div class="app-header-navigation">
			<div class="tabs">
				<a href="/">
					Dashboard
				</a>
				<a href="/alerts">
					Alerts
				</a>
				<a href="/cases" class="active">
					Cases
				</a>
				<a href="/caching">
					Caching
				</a>
            <button class="button-33" type="button" id="refreshBtn">Refresh</button>
		</div>

	</header>
		<div class="app-body-main-content">
				<div class="tiles">
                    <article class="tile">
					    <div class="tile-header">
						    <i class="ph ph-gauge"></i>
						    <h3>
							    <span>Total Ongoing Cases</span>
							    <span id="logCounter">{{ total_ip_cases }}</span>
						    </h3>
					    </div>
					    <a href="/cases">
						    <span>Go to cases summary</span>
						    <span class="icon-button">
							    <i class="ph-caret-right-bold"></i>
						    </span>
					    </a>
					</article>
					<article>
                        <h3>Severity</h3>
                        <canvas id="severityChart" width="400" height="400"></canvas>
                    </article>
					<article>
                        <h3>Case Count</h3>
                        <canvas id="visitChart" width="400" height="400"></canvas>
                    </article>
				</div>
			<section class="transfer-section">
			    <div class="table-wrapper">
                <table class="fl-table">
                    <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>Client IP</th>
                        <th>Status Code</th>
                        <th>Method</th>
                        <th>URL</th>
                        <th>Severity</th>
                        <th>Assigned To</th>
                        <th>Alert Message</th>
                        <th>More Information</th>
                        <th>Status</th>
                        <th>Actions</th>
                    </tr>
                    </thead>
                    <tbody>
                        {% for case in cases %}
                        <tr>
                            <td>{{ case['timestamp'] }}</td>
                            <td>{{ case['client_ip'] }}</td>
                            <td>{{ case['status_code'] }}</td>
                            <td>{{ case['method'] }}</td>
                            <td><a href="https://{{ case['url'] }}" target="_blank">{{ case['url'] }}</a></td>
                            <td>{{ case['severity'] }}</td>
                            <td>{{ case['assigned_to'] }}</td>
                            <td>{{ case['message'] }}</td>
                            <td>{{ case['case_details'] if case['case_details'] else "No details yet" }}</td>
                            <td>{{ case['status'] }}</td>
                            <td>
                            <button onclick="window.location.href='/edit-case/{{ case['id'] }}'" class="expand-btn">Edit</button>
                            {% if case['status'] != "Closed" %}
                                <button onclick="closeCase({{ case['id'] }})" class="expand-btn">Close</button>
                            {% endif %}
                        </td>
                        </tr>
                    {% endfor %}
                    <tbody>
                </table>
            </div>
            <footer class="footer">
				<div class="bottom-controls">
                    <form action="/clear-logs" style="visibility: hidden;" method="POST" onsubmit="return confirm('Are you sure you want to clear all logs?');">
                        <button type="submit" class="clear-logs-btn">🗑️ Clear Logs</button>
                    </form>

                    <div class="pagination">
                        <a href="?page={{ page - 1 }}" {% if page == 1 %}style="visibility: hidden;"{% endif %}>&laquo;</a>
                        <span>{{ page }}</span>
                        <a href="?page={{ page + 1 }}" {% if page == total_pages %}style="visibility: hidden;"{% endif %}>&raquo;</a>
                    </div>
                </div>
			</footer>
			</section>
		</div>
	</div>
</div>
<script>
    function closeCase(caseId) {
        if (confirm("Are you sure you want to close this case?")) {
            window.location.href = `/close-case/${caseId}`;
        }
    }
</script>

<script>
    function loadPieChart() {
        fetch('/case-data')
        .then(response => response.json())
        .then(data => {
            let ctx = document.getElementById('visitChart').getContext('2d');
            new Chart(ctx, {
                type: 'pie',
                data: {
                    labels: data.ip_labels,
                    datasets: [{
                        data: data.ip_counts,
                        backgroundColor: ['#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', '#9966FF']
                    }]
                }
            });
        })
        .catch(error => console.error("Error loading chart data:", error));
    }
    document.addEventListener("DOMContentLoaded", loadPieChart);
</script>
<script>
    function severityPieChart() {
        fetch('/case-data')
        .then(response => response.json())
        .then(data => {
            const severityColors = {
                "Critical": "#FF0000",  // red
                "High": "#FF4500",      // orange red
                "Medium": "#FFA500",    // orange
                "Low": "#00FF00"        // green
                // Add more severity levels as needed
            };
                
            const backgroundColors = data.ip_severity_labels.map(label => {
            return severityColors[label] || "#CCCCCC"; // Default color if label not found
            });
            
            let ctx = document.getElementById('severityChart').getContext('2d');
            new Chart(ctx, {
                type: 'pie',
                data: {
                    labels: data.ip_severity_labels,
                    datasets: [{
                        data: data.ip_severity_counts,
                        backgroundColor: backgroundColors
                    }]
                }
            });
        })
        .catch(error => console.error("Error loading chart data:", error));
    }
    document.addEventListener("DOMContentLoaded", severityPieChart);
</script>
<script>
	function toggleDetails(button) {
		let row = button.closest("tr");
		let detailsRow = row.nextElementSibling;
		if (detailsRow && detailsRow.classList.contains("log-details")) {
			detailsRow.classList.toggle("hidden");
			button.textContent = detailsRow.classList.contains("hidden") ? "Expand" : "Collapse";
		}
    }
    </script>
<script>
    document.getElementById("refreshBtn").addEventListener("click", function() {
        location.reload();  // Refreshes the page
    });
</script>
</body>
</html>
"""

CASES_CLOSED_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Squid Proxy Dashboard</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='cases_closed.css') }}">
    <link rel="stylesheet" type="text/css" href="https://unpkg.com/phosphor-icons@1.4.2/src/css/icons.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
<div class="app">
	<header class="app-header">
		<div class="app-header-logo">
			<div class="logo">
				<span class="logo-icon">
					<img src="https://assets.codepen.io/285131/almeria-logo.svg" />
				</span>
				<h1 class="logo-title">
					<span>XYZ</span>
				</h1>
			</div>
		</div>
		<div class="app-header-navigation">
			<div class="tabs">
				<a href="/">
					Dashboard
				</a>
				<a href="/alerts">
					Alerts
				</a>
				<a href="/cases" class="active">
					Cases
				</a>
				<a href="/caching">
					Caching
				</a>
            <button class="button-33" type="button" id="refreshBtn">Refresh</button>
		</div>

	</header>
		<div class="app-body-main-content">
				<div class="tiles">
                    <article class="tile">
					    <div class="tile-header">
						    <i class="ph ph-gauge"></i>
						    <h3>
							    <span>Total Closed Cases</span>
							    <span id="logCounter">{{ total_closed_cases }}</span>
						    </h3>
					    </div>
					    <a href="/cases">
						    <span>Go to cases summary</span>
						    <span class="icon-button">
							    <i class="ph-caret-right-bold"></i>
						    </span>
					    </a>
					</article>
					<article>
                        <h3>Severity</h3>
                        <canvas id="severityChart" width="400" height="400"></canvas>
                    </article>
					<article>
                        <h3>Case count</h3>
                        <canvas id="visitChart" width="400" height="400"></canvas>
                    </article>
                    
				</div>
			<section class="transfer-section">
			    <div class="table-wrapper">
                <table class="fl-table">
                    <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>Client IP</th>
                        <th>Status Code</th>
                        <th>Method</th>
                        <th>URL</th>
                        <th>Severity</th>
                        <th>Assigned To</th>
                        <th>Alert Message</th>
                        <th>More Information</th>
                        <th>Status</th>
                        <th>Actions</th>
                    </tr>
                    </thead>
                    <tbody>
                        {% for case in cases %}
                        <tr>
                            <td>{{ case['timestamp'] }}</td>
                            <td>{{ case['client_ip'] }}</td>
                            <td>{{ case['status_code'] }}</td>
                            <td>{{ case['method'] }}</td>
                            <td><a href="https://{{ case['url'] }}" target="_blank">{{ case['url'] }}</a></td>
                            <td>{{ case['severity'] }}</td>
                            <td>{{ case['assigned_to'] }}</td>
                            <td>{{ case['message'] }}</td>
                            <td>{{ case['case_details'] if case['case_details'] else "No details yet" }}</td>
                            <td>{{ case['status'] }}</td>
                            <td>
                            <button onclick="window.location.href='/edit-case/{{ case['id'] }}'" class="expand-btn">Edit</button>
                        </td>
                        </tr>
                    {% endfor %}
                    <tbody>
                </table>
            </div>
            <footer class="footer">
				<div class="bottom-controls">
                    <form action="/clear-logs" style="visibility: hidden;" method="POST" onsubmit="return confirm('Are you sure you want to clear all logs?');">
                        <button type="submit" class="clear-logs-btn">🗑️ Clear Logs</button>
                    </form>

                    <div class="pagination">
                        <a href="?page={{ page - 1 }}" {% if page == 1 %}style="visibility: hidden;"{% endif %}>&laquo;</a>
                        <span>{{ page }}</span>
                        <a href="?page={{ page + 1 }}" {% if page == total_pages %}style="visibility: hidden;"{% endif %}>&raquo;</a>
                    </div>
                </div>
			</footer>
			</section>
		</div>
	</div>
</div>

<script>
    function loadPieChart() {
        fetch('/case-data')
        .then(response => response.json())
        .then(data => {
            let ctx = document.getElementById('visitChart').getContext('2d');
            new Chart(ctx, {
                type: 'pie',
                data: {
                    labels: data.closed_labels,
                    datasets: [{
                        data: data.closed_counts,
                        backgroundColor: ['#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', '#9966FF']
                    }]
                }
            });
        })
        .catch(error => console.error("Error loading chart data:", error));
    }
    document.addEventListener("DOMContentLoaded", loadPieChart);
</script>
<script>
    function severityPieChart() {
        fetch('/case-data')
        .then(response => response.json())
        .then(data => {
            const severityColors = {
                "Critical": "#FF0000",  // red
                "High": "#FF4500",      // orange red
                "Medium": "#FFA500",    // orange
                "Low": "#00FF00"        // green
                // Add more severity levels as needed
            };
                
            const backgroundColors = data.severity_labels.map(label => {
            return severityColors[label] || "#CCCCCC"; // Default color if label not found
            });
            
            let ctx = document.getElementById('severityChart').getContext('2d');
            new Chart(ctx, {
                type: 'pie',
                data: {
                    labels: data.closed_severity_labels,
                    datasets: [{
                        data: data.closed_severity_counts,
                        backgroundColor: backgroundColors
                    }]
                }
            });
        })
        .catch(error => console.error("Error loading chart data:", error));
    }
    document.addEventListener("DOMContentLoaded", severityPieChart);
</script>
<script>
	function toggleDetails(button) {
		let row = button.closest("tr");
		let detailsRow = row.nextElementSibling;
		if (detailsRow && detailsRow.classList.contains("log-details")) {
			detailsRow.classList.toggle("hidden");
			button.textContent = detailsRow.classList.contains("hidden") ? "Expand" : "Collapse";
		}
    }
    </script>
<script>
    document.getElementById("refreshBtn").addEventListener("click", function() {
        location.reload();  // Refreshes the page
    });
</script>
</body>
</html>
"""


EDIT_CASE_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Edit Case</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='cases_edit.css') }}">
</head>
<body>
<div class="app">
	<header class="app-header">
		<div class="app-header-logo">
			<div class="logo">
				<span class="logo-icon">
					<img src="https://assets.codepen.io/285131/almeria-logo.svg" />
				</span>
				<h1 class="logo-title">
					<span>XYZ</span>
				</h1>
			</div>
		</div>
		<div class="app-header-navigation">
			<div class="tabs">
				<a href="/">
					Dashboard
				</a>
				<a href="/alerts">
					Alerts
				</a>
				<a href="/cases" class="active">
					Cases
				</a>
				<a href="/caching">
					Caching
				</a>
		</div>

	</header>
		<div class="app-body-main-content">
			<section class="transfer-section">
                <div class="form-container">
                    <form method="POST" action="/update-case/{{ case['id'] }}">
                        
                        <label for="client_ip">Client IP:</label>
                        <p class="readonly-field">{{ case['client_ip'] }}</p>  <!-- Non-clickable -->

                        <label for="status_code">Status Code:</label>
                        <p class="readonly-field">{{ case['status_code'] }}</p>  <!-- Non-clickable -->

                        <label for="method">Method:</label>
                        <p class="readonly-field">{{ case['method'] }}</p>  <!-- Non-clickable -->

                        <label for="url">URL:</label>
                        <p class="readonly-field"><a href="https://{{ case['url'] }}" target="_blank">{{ case['url'] }}</a></p>  <!-- Non-clickable -->

                        <label for="severity">Severity:</label>
                        <p class="readonly-field">{{ case['severity'] }}</p>  <!-- Non-clickable -->

                        <label for="alert_message">Alert Message:</label>
                        <p class="readonly-field">{{ case['message'] }}</p>  <!-- Non-clickable -->

                        <label for="assigned_to">Assigned To:</label>
                        <input type="text" id="assigned_to" name="assigned_to" value="{{ case['assigned_to'] }}" required>

                        <label for="case_details">More Information (Case Details):</label>
                        <textarea id="case_details" name="case_details" maxlength="300" oninput="updateCharCount(this)">{{ case['case_details'] }}</textarea>
                        <small id="charCount">0/300 characters</small>

                        <label for="status">Status:</label>
                        <select id="status" name="status">
                            <option value="Open" {% if case['status'] == 'Open' %}selected{% endif %}>Open</option>
                            <option value="In Progress" {% if case['status'] == 'In Progress' %}selected{% endif %}>In Progress</option>
                            <option value="Closed" {% if case['status'] == 'Closed' %}selected{% endif %}>Closed</option>
                        </select>

                        <button type="submit">Update Case</button>
                    </form>
                </div>
			</section>
		</div>
	</div>
</div>


    <script>
        function updateCharCount(input) {
            let countDisplay = document.getElementById("charCount");
            countDisplay.textContent = input.value.length + "/300 characters";
        }
    </script>
</body>
</html>
"""

# Create the CREATE_CASE template string (the HTML content you provided)
CREATE_CASE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Create New Case</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='cases_create.css') }}">
</head>
<body>
<div class="app">
	<header class="app-header">
		<div class="app-header-logo">
			<div class="logo">
				<span class="logo-icon">
					<img src="https://assets.codepen.io/285131/almeria-logo.svg" />
				</span>
				<h1 class="logo-title">
					<span>XYZ</span>
				</h1>
			</div>
		</div>
		<div class="app-header-navigation">
			<div class="tabs">
				<a href="/">
					Dashboard
				</a>
				<a href="/alerts">
					Alerts
				</a>
				<a href="/cases" class="active">
					Cases
				</a>
				<a href="/caching">
					Caching
				</a>
		</div>

	</header>
		<div class="app-body-main-content">
			<section class="transfer-section">
                <div class="form-container">
                    <form method="POST" action="/create-case">
                        <input type="hidden" name="alert_id" value="{{ alert_id }}">

                        <label for="client_ip">Client IP:</label>
                        <div class="readonly-field">{{ client_ip }}</div>

                        <label for="status_code">Status Code:</label>
                        <div class="readonly-field">{{ status_code }}</div>

                        <label for="method">Method:</label>
                        <div class="readonly-field">{{ method }}</div>

                        <label for="url">URL:</label>
                        <div class="readonly-field">{{ url }}</div>

                        <label for="severity">Severity:</label>
                        <div class="readonly-field">{{ severity }}</div>

                        <label for="message">Alert Message:</label>
                        <div class="readonly-field">{{ message }}</div>

                        <label for="assigned_to">Assigned To:</label>
                        <input type="text" id="assigned_to" name="assigned_to" required>

                        <button type="submit">Create Case</button>
                    </form>
                </div>
            </section>
        </div>

    <script>
        function updateCharCount(input) {
            let countDisplay = document.getElementById("charCount");
            countDisplay.textContent = input.value.length + "/100 characters";
        }
    </script>
</body>
</html>
"""

CACHING_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Squid Proxy Dashboard</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='caching.css') }}">
    <link rel="stylesheet" type="text/css" href="https://unpkg.com/phosphor-icons@1.4.2/src/css/icons.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
<div class="app">
	<header class="app-header">
		<div class="app-header-logo">
			<div class="logo">
				<span class="logo-icon">
					<img src="https://assets.codepen.io/285131/almeria-logo.svg" />
				</span>
				<h1 class="logo-title">
					<span>XYZ</span>
				</h1>
			</div>
		</div>
		<div class="app-header-navigation">
			<div class="tabs">
				<a href="/">
					Dashboard
				</a>
				<a href="/alerts">
					Alerts
				</a>
				<a href="/cases">
					Cases
				</a>
				<a href="/caching" class="active">
					Caching
				</a>
			<form method="GET" action="/caching">
			<div class="box">
                <input type="text" class="input search-input" name="search" onmouseout="this.value = ''; this.blur();" placeholder="Search URL or Status Code" value="{{ search_query }}">
            </div>
            <button class="button-33" type="button" id="refreshBtn">Refresh</button>
            </form>
		</div>

	</header>
		<div class="app-body-main-content">
				<div class="tiles">
                    <article class="tile">
					    <div class="tile-header">
						    <i class="ph ph-gauge"></i>
						    <h3>
							    <span>Total logs</span>
							    <span id="logCounter">{{ total_logs }}</span>
						    </h3>
					    </div>
					    <a href="/caching">
						    <span>Caching</span>
						    <span class="icon-button">
							    <i class="ph-caret-right-bold"></i>
						    </span>
					    </a>
					</article>
					<article>
                        <h3>Cache count</h3>
                        <canvas id="visitChart" width="400" height="400"></canvas>
                    </article> 
				</div>
			<section class="transfer-section">
			    <div class="table-wrapper">
                <table class="fl-table">
                    <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>Client IP</th>
                        <th>Status Code</th>
                        <th>Method</th>
                        <th>URL</th>
	                <th>More Info</th>
                    </tr>
                    </thead>
                    <tbody>
                    {% for log in logs %}
                    <tr class="log-row" on click="toggleDetails(this)">
                        <tr>
                        <td>{{ log['Timestamp'] }} SGT</td>
                        <td>{{ log['Client IP'] }}</td>
                        <td>{{ log['Status Code'] }}</td>
                        <td>{{ log['Method'] }}</td>
                        <td><a href="https://{{ log['URL'] }}" target="_blank">{{ log['URL'] }}</a></td>
	                    <td><button class="expand-btn" onclick="toggleDetails(this)">Expand</button></td>
	                    </tr>
                    </tr>
	                <tr class="log-details hidden">
		                <td colspan="6">
			                <strong>Message:</strong> {{ log['Message'] }} <br>
			                <strong>Process Time:</strong> {{ log['Process Time'] }} <br>
			                <strong>Full Log:</strong> {{ log['Full Log'] }} <br>
		                </td>
	                </tr>
                        {% endfor %}
                    <tbody>
                </table>
            </div>
            <footer class="footer">
				<div class="bottom-controls">
                    <form action="/clear-logs" method="POST" onsubmit="return confirm('Are you sure you want to clear all logs?');">
                        <button type="submit" class="clear-logs-btn">🗑️ Clear Logs</button>
                    </form>

                    <div class="pagination">
                        <a href="?page={{ page - 1 }}" {% if page == 1 %}style="visibility: hidden;"{% endif %}>&laquo;</a>
                        <span>{{ page }}</span>
                        <a href="?page={{ page + 1 }}" {% if page == total_pages %}style="visibility: hidden;"{% endif %}>&raquo;</a>
                    </div>
                </div>
			</footer>
			</section>
		</div>
	</div>
</div>

<script>
    function loadPieChart() {
        fetch('/website-data')
        .then(response => response.json())
        .then(data => {
            let ctx = document.getElementById('visitChart').getContext('2d');
            new Chart(ctx, {
                type: 'pie',
                data: {
                    labels: data.labels6,
                    datasets: [{
                        data: data.counts6,
                        backgroundColor: ['#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', '#9966FF']
                    }]
                }
            });
        })
        .catch(error => console.error("Error loading chart data:", error));
    }
    document.addEventListener("DOMContentLoaded", loadPieChart);
</script>
<script>
	function toggleDetails(button) {
		let row = button.closest("tr");
		let detailsRow = row.nextElementSibling;
		if (detailsRow && detailsRow.classList.contains("log-details")) {
			detailsRow.classList.toggle("hidden");
			button.textContent = detailsRow.classList.contains("hidden") ? "Expand" : "Collapse";
		}
    }
    </script>
<script>
    document.getElementById("refreshBtn").addEventListener("click", function() {
        location.reload();  // Refreshes the page
    });
</script>
</body>
</html>
"""

@app.route('/')
def index():
    parse_squid_logs()
    parse_icap_logs()
    search_query = request.args.get('search', '')
    page = request.args.get('page', 1, type=int)  # Get current page number
    per_page = 10  # Number of logs per page

    # Adjust query to include method filter (only CONNECT)
    cursor.execute("""
        SELECT COUNT(*) FROM logs 
        WHERE status_code IN ('NONE_NONE/200', 'NONE_NONE/403') 
        AND method = 'CONNECT'  -- Filter by CONNECT method
        AND (status_code LIKE %s OR url LIKE %s)
    """, (f"%{search_query}%", f"%{search_query}%"))
    total_logs = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM alerts WHERE status = 'Open'")
    total_alerts = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM cases WHERE status = 'In Progress'")
    total_cases = cursor.fetchone()[0] 
    
    cursor.execute("""
    SELECT COUNT(*) 
    FROM logs 
    WHERE method IN ('GET', 'POST', 'PUT', 'DELETE') 
    AND status_code IN ('NONE_NONE/200', 'TCP_HIT/200', 'TCP_INM_HIT/304')
    """)
    total_cache = cursor.fetchone()[0]
    
    

    # If no results found
    if total_logs == 0:
        no_results = "No results found for your search query."
    else:
        no_results = ""

    # Calculate offset for pagination
    offset = (page - 1) * per_page

    # Adjust query to include method filter (only CONNECT)
    query = """
        SELECT timestamp, client_ip, status_code, method, url, message, full_log_line
        FROM logs 
        WHERE status_code IN ('NONE_NONE/200', 'NONE_NONE/403') 
        AND method = 'CONNECT'  -- Filter by CONNECT method
        AND (status_code LIKE %s OR url LIKE %s)
        ORDER BY timestamp DESC 
        LIMIT %s OFFSET %s
    """
    cursor.execute(query, (f"%{search_query}%", f"%{search_query}%", per_page, offset))
    logs = cursor.fetchall()

    log_data = [{
        "Timestamp": log[0],
        "Client IP": log[1],
        "Status Code": log[2],
        "Method": log[3],
        "URL": log[4],
        "Message": log[5] if log[5] else "No details",
        "Full Log": log[6],  # Add full_log_line to the log data
    } for log in logs]

    total_pages = (total_logs + per_page - 1) // per_page  # Calculate total pages

    return render_template_string(HOME_TEMPLATE, logs=log_data, search_query=search_query, total_logs=total_logs, total_alerts=total_alerts, total_cases=total_cases, total_cache=total_cache, page=page, total_pages=total_pages, no_results=no_results)



@app.route('/website-data')
def website_data():
    cursor = db.cursor(buffered=True)
    cursor.execute("SELECT url, COUNT(*) FROM logs GROUP BY url ORDER BY COUNT(*) DESC LIMIT 5")
    result = cursor.fetchall()

    labels = [row[0] for row in result]
    counts = [row[1] for row in result]
    
    cursor.execute("SELECT url, COUNT(*) FROM alerts GROUP BY url ORDER BY COUNT(*) DESC LIMIT 5")
    result2 = cursor.fetchall()

    labels2 = [row[0] for row in result2]
    counts2 = [row[1] for row in result2]
    
    cursor.execute("SELECT url, SUM(visit_count) AS total_visit_countx FROM alerts WHERE status = 'Open' GROUP BY url ORDER BY COUNT(*) DESC LIMIT 5" )
    result3 = cursor.fetchall()

    labels3 = [row[0] for row in result3]
    counts3 = [row[1] for row in result3]
    
    cursor.execute("SELECT url, COUNT(*) FROM alerts WHERE status = 'Acknowledged' GROUP BY url ORDER BY COUNT(*) DESC LIMIT 5" )
    result4 = cursor.fetchall()

    labels4 = [row[0] for row in result4]
    counts4 = [row[1] for row in result4]
    
    cursor.execute("SELECT url, COUNT(*) FROM alerts WHERE status = 'Closed' GROUP BY url ORDER BY COUNT(*) DESC LIMIT 5" )
    result5 = cursor.fetchall()

    labels5 = [row[0] for row in result5]
    counts5 = [row[1] for row in result5]
    
    cursor.execute("SELECT url,COUNT(*) FROM logs WHERE method IN ('GET', 'POST', 'PUT', 'DELETE') AND status_code IN ('NONE_NONE/200', 'TCP_HIT/200', 'TCP_INM_HIT/304') GROUP BY url");
    result6 = cursor.fetchall()
    
    labels6 = [row[0] for row in result6]
    counts6 = [row[1] for row in result6]

    return {"labels": labels, "counts": counts, "labels2": labels2, "counts2": counts2,"labels3": labels3, "counts3": counts3,"labels4": labels4, "counts4": counts4, "labels5":labels5, "counts5": counts5, "labels6": labels6, "counts6": counts6}

@app.route('/alerts')
def view_alerts():
    parse_squid_logs()
    parse_icap_logs()
    
    # Get total number of alerts
    cursor.execute("SELECT COUNT(*) FROM alerts")
    total_alerts = cursor.fetchone()[0]

    # Group alerts by domain and sum visit counts
    cursor.execute(""" 
        SELECT 
            url AS domain, 
            SUM(visit_count) AS total_visits 
        FROM alerts 
        GROUP BY domain 
        ORDER BY total_visits DESC
    """)
    grouped_alerts = cursor.fetchall()
    grouped_alerts_dict = {alert[0]: alert[1] for alert in grouped_alerts}

    # Fetch all alerts
    cursor.execute("""
        SELECT id, timestamp, client_ip, method, url, message, severity, assigned_to, status, visit_count 
        FROM alerts 
        ORDER BY timestamp DESC
    """)
    alerts = cursor.fetchall()

    # Separate alerts by status
    open_alerts = []
    acknowledged_alerts = []
    resolved_alerts = []
    
    cursor.execute("SELECT COUNT(*) FROM alerts WHERE status = 'Open'")
    total_open_alerts = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM alerts WHERE status = 'Acknowledged'")
    total_acknowledged_alerts = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM alerts WHERE status = 'Resolved'")
    total_closed_alerts = cursor.fetchone()[0]
    

    for alert in alerts:
        alert_data = {
            "id": alert[0],
            "timestamp": alert[1],
            "client_ip": alert[2],
            "method": alert[3],
            
            "url": alert[4],
            "message": alert[5],
            "severity": alert[6],
            "assigned_to": alert[7] if alert[7] else "Unassigned",
            "status": alert[8],
            "visit_count": alert[9]
        }

        if alert[8] == "Open":
            open_alerts.append(alert_data)
        elif alert[8] == "Acknowledged":
            acknowledged_alerts.append(alert_data)
        elif alert[8] == "Resolved":
            resolved_alerts.append(alert_data)

    return render_template_string(
        ALERTS_TEMPLATE,
        open_alerts=open_alerts or [],
        acknowledged_alerts=acknowledged_alerts or [],
        resolved_alerts=resolved_alerts or [],
        grouped_alerts=grouped_alerts_dict,
        total_alerts=total_alerts,
        total_open_alerts=total_open_alerts,
        total_acknowledged_alerts=total_acknowledged_alerts,
        total_closed_alerts=total_closed_alerts
    )


@app.route('/alert-data')
def alert_data():
    cursor = db.cursor(buffered=True)
    # Fetch total number of alerts
    cursor.execute("SELECT COUNT(*) FROM alerts")
    total_alerts = cursor.fetchone()[0]
    
    cursor.execute("SELECT severity, COUNT(*) FROM alerts GROUP BY severity")
    severity_data = cursor.fetchall()
    severity_labels = [row[0] for row in severity_data]
    severity_counts = [row[1] for row in severity_data]
    
    cursor.execute("SELECT url, SUM(visit_count) AS total_visit_countx FROM alerts GROUP BY url ORDER BY COUNT(*) DESC LIMIT 5" )
    result = cursor.fetchall()

    labels = [row[0] for row in result]
    counts = [row[1] for row in result]

    # Fetch severity distribution
    cursor.execute("SELECT severity, COUNT(*) FROM alerts WHERE status='Open' GROUP BY severity")
    open_severity_data = cursor.fetchall()
    open_severity_labels = [row[0] for row in open_severity_data]
    open_severity_counts = [row[1] for row in open_severity_data]

    # Fetch status distribution
    cursor.execute("SELECT status, COUNT(*) FROM alerts GROUP BY status")
    status_data = cursor.fetchall()
    status_labels = [row[0] for row in status_data]
    status_counts = [row[1] for row in status_data]
    
    cursor.execute("SELECT url, SUM(visit_count) AS total_visit_countx FROM alerts WHERE status = 'Open' GROUP BY url ORDER BY COUNT(*) DESC LIMIT 5" )
    result = cursor.fetchall()

    open_labels = [row[0] for row in result]
    open_counts = [row[1] for row in result]
    
    # Fetch severity distribution
    cursor.execute("SELECT severity, COUNT(*) FROM alerts WHERE status='Acknowledged' GROUP BY severity")
    acknowledged_severity_data = cursor.fetchall()
    acknowledged_severity_labels = [row[0] for row in acknowledged_severity_data]
    acknowledged_severity_counts = [row[1] for row in acknowledged_severity_data]
    
    cursor.execute("SELECT url, SUM(visit_count) AS total_visit_countx FROM alerts WHERE status = 'Acknowledged' GROUP BY url ORDER BY COUNT(*) DESC LIMIT 5" )
    acknowledged_result = cursor.fetchall()

    acknowledged_labels = [row[0] for row in acknowledged_result]
    acknowledged_counts = [row[1] for row in acknowledged_result]
    
    # Fetch severity distribution
    cursor.execute("SELECT severity, COUNT(*) FROM alerts WHERE status='Resolved' GROUP BY severity")
    closed_severity_data = cursor.fetchall()
    closed_severity_labels = [row[0] for row in closed_severity_data]
    closed_severity_counts = [row[1] for row in closed_severity_data]
    
    cursor.execute("SELECT url, SUM(visit_count) AS total_visit_countx FROM alerts WHERE status = 'Resolved' GROUP BY url ORDER BY COUNT(*) DESC LIMIT 5" )
    closed_result = cursor.fetchall()

    closed_labels = [row[0] for row in closed_result]
    closed_counts = [row[1] for row in closed_result]
    

    return jsonify({
        "total_alerts": total_alerts,
        "severity_labels": severity_labels,
        "severity_counts": severity_counts,
        "status_labels": status_labels,
        "status_counts": status_counts,
        "labels": labels,
        "counts": counts,
        "acknowledged_severity_labels": acknowledged_severity_labels,
        "acknowledged_severity_counts": acknowledged_severity_counts,
        "acknowledged_labels": acknowledged_labels,
        "acknowledged_counts": acknowledged_counts,
        "closed_severity_labels": closed_severity_labels,
        "closed_severity_counts": closed_severity_counts,
        "closed_labels": closed_labels,
        "closed_counts": closed_counts,
        "open_severity_labels": open_severity_labels,
        "open_severity_counts": open_severity_counts,
        "open_labels": open_labels,
        "open_counts": open_counts
    })
    
@app.route('/clear-alerts', methods=['POST'])
def clear_alerts():
    try:
        # First, delete related cases that reference alerts
        cursor.execute("DELETE FROM cases WHERE alert_id IS NOT NULL")
        db.commit()

        # Now delete all alerts
        cursor.execute("DELETE FROM alerts")
        db.commit()

        print("All alerts and related cases have been cleared.")
    except Exception as e:
        print(f"Error clearing alerts: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

    return redirect(url_for('view_alerts'))  # Redirect back to the Alerts page
    
@app.route('/clear-cases', methods=['POST'])
def clear_cases():
    try:
        # First, delete related cases that reference alerts
        cursor.execute("DELETE FROM cases WHERE alert_id IS NOT NULL")
        db.commit()

        # Now delete all alerts
        cursor.execute("DELETE FROM alerts")
        db.commit()

        print("All alerts and related cases have been cleared.")
    except Exception as e:
        print(f"Error clearing alerts: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

    return redirect(url_for('view_cases'))  # Redirect back to the Alerts page

@app.route('/edit-case/<int:case_id>', methods=['GET', 'POST'])
def edit_case(case_id):
    if request.method == 'POST':
        assigned_to = request.form['assigned_to']
        severity = request.form['severity']
        status = request.form['status']
        method = request.form['method']
        message = request.form['message']
        case_details = request.form['case_details']  # New More Information field

        cursor.execute("""
            UPDATE cases 
            SET assigned_to = %s, severity = %s, status = %s, method = %s, message = %s, case_details = %s
            WHERE id = %s
        """, (assigned_to, severity, status, method, message, case_details, case_id))
        db.commit()

        return redirect(url_for('view_cases'))

    cursor.execute("SELECT * FROM cases WHERE id = %s", (case_id,))
    case = cursor.fetchone()

    if not case:
        return "Case not found", 404

    case_data = {
        "id": case[0],
        "timestamp": case[1],
        "client_ip": case[2],
        "status_code": case[3],
        "method": case[4],
        "url": case[5],
        "severity": case[6],
        "assigned_to": case[7] if case[7] else "Unassigned",
        "message": case[8],  # Alert message
        "status": case[9],
        "case_details": case[11] if case[11] else "",  # More Information field
    } 

    return render_template_string(EDIT_CASE_TEMPLATE, case=case_data)
    
@app.route('/case-data')
def case_data():
    cursor = db.cursor(buffered=True)

    cursor.execute("SELECT COUNT(*) FROM cases")
    total_cases = cursor.fetchone()[0]
    
    cursor.execute("SELECT severity, COUNT(*) FROM cases GROUP BY severity")
    severity_data = cursor.fetchall()
    severity_labels = [row[0] for row in severity_data]
    severity_counts = [row[1] for row in severity_data]
    
    cursor.execute("SELECT url, COUNT(*) FROM cases GROUP BY url ORDER BY COUNT(*) DESC LIMIT 5" )
    result = cursor.fetchall()

    labels = [row[0] for row in result]
    counts = [row[1] for row in result]

    # Fetch severity distribution
    cursor.execute("SELECT severity, COUNT(*) FROM cases WHERE status='In Progress' GROUP BY severity")
    ip_severity_data = cursor.fetchall()
    ip_severity_labels = [row[0] for row in ip_severity_data]
    ip_severity_counts = [row[1] for row in ip_severity_data]

    # Fetch status distribution
    cursor.execute("SELECT status, COUNT(*) FROM cases GROUP BY status")
    status_data = cursor.fetchall()
    status_labels = [row[0] for row in status_data]
    status_counts = [row[1] for row in status_data]
    
    cursor.execute("SELECT url, COUNT(*) FROM cases WHERE status = 'In Progress' GROUP BY url ORDER BY COUNT(*) DESC LIMIT 5" )
    result = cursor.fetchall()

    ip_labels = [row[0] for row in result]
    ip_counts = [row[1] for row in result]
        
    # Fetch severity distribution
    cursor.execute("SELECT severity, COUNT(*) FROM cases WHERE status='Closed' GROUP BY severity")
    closed_severity_data = cursor.fetchall()
    closed_severity_labels = [row[0] for row in closed_severity_data]
    closed_severity_counts = [row[1] for row in closed_severity_data]
    
    cursor.execute("SELECT url,COUNT(*) FROM cases WHERE status = 'Closed' GROUP BY url ORDER BY COUNT(*) DESC LIMIT 5" )
    closed_result = cursor.fetchall()

    closed_labels = [row[0] for row in closed_result]
    closed_counts = [row[1] for row in closed_result]
    

    return jsonify({
        "total_cases": total_cases,
        "severity_labels": severity_labels,
        "severity_counts": severity_counts,
        "status_labels": status_labels,
        "status_counts": status_counts,
        "labels": labels,
        "counts": counts,
        "ip_severity_labels": ip_severity_labels,
        "ip_severity_counts": ip_severity_counts,
        "ip_labels": ip_labels,
        "ip_counts": ip_counts,
        "closed_severity_labels": closed_severity_labels,
        "closed_severity_counts": closed_severity_counts,
        "closed_labels": closed_labels,
        "closed_counts": closed_counts,
    })
    
@app.route('/cases')
def view_cases():
    parse_squid_logs()

    cursor.execute("SELECT COUNT(*) FROM cases")
    total_cases = cursor.fetchone()[0]

    cursor.execute(""" 
        SELECT 
        url AS domain
        FROM cases 
        GROUP BY domain 
    """)
    

    # Fetch all cases
    cursor.execute("""
        SELECT id, timestamp, client_ip, status_code, method, url, severity, assigned_to, message, status, case_details, alert_id 
        FROM cases 
        ORDER BY timestamp DESC
    """)
    cases = cursor.fetchall()

    cursor.execute("SELECT COUNT(*) FROM cases WHERE status = 'In Progress'")
    total_ip_cases = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM cases WHERE status = 'Closed'")
    total_closed_cases = cursor.fetchone()[0]


    for case in cases:
        case_data = {
            "id": case[0],
            "timestamp": case[1],
            "client_ip": case[2],
            "status_code": case[3],
            "method": case[4],
            "url": case[5],
            "severity": case[6],
            "assigned_to": case[7] if case[7] else "Unassigned",
            "message": case[8],
            "status": case[9],
            "case_details": case[10] if case[10] else "",
            "alert_id": case[11]
        }

    return render_template_string(
        CASES_TEMPLATE,
        total_cases=total_cases,
        total_ip_cases=total_ip_cases,
        total_closed_cases=total_closed_cases
    )
    
@app.route('/cases/ip')
def view_ip_cases():
    parse_squid_logs()
    page = request.args.get('page', 1, type=int)  # Get current page number
    per_page = 10

    offset= (page - 1) * per_page

    cursor.execute("""
        SELECT id, timestamp, client_ip, status_code, method, url,  severity, assigned_to, message, status, case_details, alert_id 
        FROM cases 
        WHERE status = 'In Progress'
        ORDER BY timestamp DESC
    """)
    ip_cases = cursor.fetchall()

    cursor.execute("SELECT COUNT(*) FROM cases WHERE status = 'In Progress'", per_page, offset)
    total_ip_cases = cursor.fetchone()[0]

    total_pages = (total_ip_cases + per_page - 1) // per_page

    case_data = [{
            "id": case[0],
            "timestamp": case[1],
            "client_ip": case[2],
            "status_code": case[3],
            "method": case[4],
            "url": case[5],
            "severity": case[6],
            "assigned_to": case[7] if case[7] else "Unassigned",
            "message": case[8],
            "status": case[9],
            "case_details": case[10] if case[10] else "",
            "alert_id": case[11]
    } for case in ip_cases]

    return render_template_string(CASES_IP_TEMPLATE, cases=case_data, total_ip_cases=total_ip_cases, page=page, total_pages=total_pages)  
    
@app.route('/cases/closed')
def view_closed_cases():
    parse_squid_logs()
    page = request.args.get('page', 1, type=int)  # Get current page number
    per_page = 10

    offset= (page - 1) * per_page

    cursor.execute("""
        SELECT id, timestamp, client_ip, status_code, method, url,  severity, assigned_to, message, status, case_details, alert_id 
        FROM cases 
        WHERE status = 'Closed'
        ORDER BY timestamp DESC
    """)
    closed_cases = cursor.fetchall()

    cursor.execute("SELECT COUNT(*) FROM cases WHERE status = 'Closed'", per_page, offset)
    total_closed_cases = cursor.fetchone()[0]

    total_pages = (total_closed_cases + per_page - 1) // per_page

    case_data = [{
            "id": case[0],
            "timestamp": case[1],
            "client_ip": case[2],
            "status_code": case[3],
            "method": case[4],
            "url": case[5],
            "severity": case[6],
            "assigned_to": case[7] if case[7] else "Unassigned",
            "message": case[8],
            "status": case[9],
            "case_details": case[10] if case[10] else "",
            "alert_id": case[11]
    } for case in closed_cases]

    return render_template_string(CASES_CLOSED_TEMPLATE, cases=case_data, total_closed_cases=total_closed_cases, page=page, total_pages=total_pages)
    
@app.route('/update-case/<int:case_id>', methods=['POST'])
def update_case(case_id):
    assigned_to = request.form.get("assigned_to", "Unassigned")
    status = request.form.get("status", "Open")
    method = request.form.get("method", "GET")
    case_details = request.form.get("case_details", "")

    # Ensure valid status values
    allowed_statuses = ["Open", "In Progress", "Closed"]
    if status not in allowed_statuses:
        return "Invalid status update", 400

    # Update the case in the database
    cursor.execute("""
        UPDATE cases 
        SET assigned_to = %s, status = %s, method = %s, case_details = %s
        WHERE id = %s
    """, (assigned_to, status, method, case_details, case_id))
    db.commit()

    # Fetch the associated alert_id
    cursor.execute("SELECT alert_id FROM cases WHERE id = %s", (case_id,))
    alert_id = cursor.fetchone()

    if alert_id:
        alert_id = alert_id[0]

        # Update the alert status based on the case status
        if status == "In Progress":
            cursor.execute("UPDATE alerts SET status = 'Acknowledged' WHERE id = %s", (alert_id,))
        elif status == "Closed":
            cursor.execute("UPDATE alerts SET status = 'Resolved' WHERE id = %s", (alert_id,))
        elif status == "Open":  
            cursor.execute("UPDATE alerts SET status = 'Open' WHERE id = %s", (alert_id,))

        db.commit()

    return redirect(url_for('view_cases'))


@app.route('/close-case/<int:case_id>')
def close_case(case_id):
    # Update the case status to "Closed"
    cursor.execute("UPDATE cases SET status = 'Closed' WHERE id = %s", (case_id,))
    db.commit()

    # Fetch associated alert_id
    cursor.execute("SELECT alert_id FROM cases WHERE id = %s", (case_id,))
    alert_id = cursor.fetchone()

    if alert_id:
        # Update the related alert's status to "Resolved"
        cursor.execute("UPDATE alerts SET status = 'Resolved' WHERE id = %s", (alert_id[0],))
        db.commit()

    return redirect(url_for('view_cases'))


# Route to show the create case form
@app.route('/create-case', methods=['GET'])
def create_case_form():
    alert_id = request.args.get("alert_id")

    # Fetch alert details for pre-filling
    cursor.execute("SELECT client_ip, method, url, severity, message FROM alerts WHERE id = %s", (alert_id,))
    alert = cursor.fetchone()

    if not alert:
        return "Error: Alert not found", 404  # Prevent unpacking if no alert is found

    # Ensure that the alert contains the correct number of values
    if len(alert) != 5:
        return f"Error: Expected 5 values but got {len(alert)}", 500

    client_ip, method, url, severity, message = alert  

    status_code = "TCP_DENIED/403"  

    return render_template_string(
        CREATE_CASE,
        alert_id=alert_id,
        client_ip=client_ip,
        status_code=status_code,
        method=method,
        url=url,
        severity=severity,
        message=message
    )



# Route to handle case creation
@app.route('/create-case', methods=['POST'])
def create_case():
    if request.method == 'POST':
        alert_id = request.form.get('alert_id')  # Capture alert_id
        assigned_to = request.form['assigned_to']  # User input
        
        # Fetch alert details
        cursor.execute("SELECT client_ip, method, url, severity, message FROM alerts WHERE id = %s", (alert_id,))
        alert = cursor.fetchone()
        if not alert:
            return "Alert not found", 404  # Ensure the alert exists

        client_ip, method, url, severity, message = alert
        status_code = "TCP_DENIED/403"  # Example status code, change if necessary

        # Insert the case into the database with "In Progress" status
        cursor.execute("""
            INSERT INTO cases (alert_id, client_ip, status_code, method, url, severity, assigned_to, message, status)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'In Progress')
        """, (alert_id, client_ip, status_code, method, url, severity, assigned_to, message))
        db.commit()

        # Update the alert status to "Acknowledged"
        cursor.execute("UPDATE alerts SET status = 'Acknowledged', assigned_to = %s WHERE id = %s", (assigned_to, alert_id))
        db.commit()

        return redirect(url_for('view_cases'))


@app.route('/clear-logs', methods=['POST'])
def clear_logs():
    try:
        cursor.execute("DELETE FROM logs")  # Delete all logs
        db.commit()
        print("All logs have been cleared.")
        subprocess.run(["sudo", "truncate", "-s", "0", "/var/log/squid/access.log"], check=True)
        print("Squid access log file has been cleared.")
    except Exception as e:
        print(f"Error clearing logs: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

    return redirect(url_for('index'))  # Redirect back to the dashboard

CACHING_METHOD = ["GET", "POST", "PUT", "DELETE"]
CACHING_STATUS_CODES = ["NONE_NONE/200", "TCP_HIT/200", "TCP_INM_HIT/304"]

@app.route('/caching')
def caching():
    parse_squid_logs()
    search_query = request.args.get('search', '')
    page = request.args.get('page', 1, type=int)  # Get current page number
    per_page = 10  # Number of logs per page

    # Create placeholders for SQL query
    method_placeholders = ', '.join(['%s'] * len(CACHING_METHOD))
    status_placeholders = ', '.join(['%s'] * len(CACHING_STATUS_CODES))

    # ✅ Fix: Ensure correct ordering of conditions
    query_count = f"""
        SELECT COUNT(*) FROM logs 
        WHERE method IN ({method_placeholders}) 
        AND status_code IN ({status_placeholders})
        AND (client_ip LIKE %s OR url LIKE %s)
    """
    params_count = (*CACHING_METHOD, *CACHING_STATUS_CODES, f"%{search_query}%", f"%{search_query}%")
    cursor.execute(query_count, params_count)
    total_logs = cursor.fetchone()[0]

    # If no results found
    no_results = "No results found for your search query." if total_logs == 0 else ""

    # Calculate offset for pagination
    offset = (page - 1) * per_page

    # ✅ Fix: Ensure correct ordering of conditions
    query_logs = f"""
        SELECT timestamp, client_ip, status_code, method, url, message, process_time, full_log_line 
        FROM logs 
        WHERE method IN ({method_placeholders})
        AND status_code IN ({status_placeholders})
        AND (client_ip LIKE %s OR url LIKE %s)
        ORDER BY timestamp DESC 
        LIMIT %s OFFSET %s
    """
    params_logs = (*CACHING_METHOD, *CACHING_STATUS_CODES, f"%{search_query}%", f"%{search_query}%", per_page, offset)
    cursor.execute(query_logs, params_logs)
    logs = cursor.fetchall()

    log_data = [{
        "Timestamp": log[0],
        "Client IP": log[1],
        "Status Code": log[2],
        "Method": log[3],
        "URL": log[4],
        "Message": log[5] if log[5] else "No details",
        "Process Time": log[6],
        "Full Log": log[7],
    } for log in logs]

    total_pages = (total_logs + per_page - 1) // per_page  # Calculate total pages

    return render_template_string(CACHING_TEMPLATE, logs=log_data, search_query=search_query, total_logs=total_logs, page=page, total_pages=total_pages, no_results=no_results)
    
@app.route('/alerts/open')
def view_open_alerts():
    parse_squid_logs()
    page = request.args.get('page', 1, type=int)  # Get current page number
    per_page = 10
    severity_filter = request.args.get('search', '')  # Get severity filter from query string
    
    offset= (page - 1) * per_page
    cursor.execute("""
        SELECT id, timestamp, client_ip, method, url, message, severity, assigned_to, status, visit_count 
        FROM alerts 
        WHERE status = 'Open'
        ORDER BY timestamp DESC
    """)
    open_alerts = cursor.fetchall()
    
    cursor.execute("SELECT COUNT(*) FROM alerts WHERE status = 'Open'", per_page, offset)
    total_open_alerts = cursor.fetchone()[0]
    
    total_pages = (total_open_alerts + per_page - 1) // per_page
    

    alert_data = [{
        "id": alert[0],
        "timestamp": alert[1],
        "client_ip": alert[2],
        "method": alert[3],
        "url": alert[4],
        "message": alert[5],
        "severity": alert[6],
        "assigned_to": alert[7] if alert[7] else "Unassigned",
        "status": alert[8],
        "visit_count": alert[9]
    } for alert in open_alerts]
    

    return render_template_string(ALERTS_OPEN_TEMPLATE, alerts=alert_data, total_open_alerts=total_open_alerts, page=page, total_pages=total_pages)


@app.route('/alerts/acknowledged')
def view_acknowledged_alerts():
    parse_squid_logs()
    page = request.args.get('page', 1, type=int)  # Get current page number
    per_page = 10
    
    offset= (page - 1) * per_page
    
    cursor.execute("""
        SELECT id, timestamp, client_ip, method, url, message, severity, assigned_to, status, visit_count 
        FROM alerts 
        WHERE status = 'Acknowledged'
        ORDER BY timestamp DESC
    """)
    acknowledged_alerts = cursor.fetchall()
    
    cursor.execute("SELECT COUNT(*) FROM alerts WHERE status = 'Acknowledged'", per_page, offset)
    total_acknowledged_alerts = cursor.fetchone()[0]
    
    total_pages = (total_acknowledged_alerts + per_page - 1) // per_page

    alert_data = [{
        "id": alert[0],
        "timestamp": alert[1],
        "client_ip": alert[2],
        "method": alert[3],
        "url": alert[4],
        "message": alert[5],
        "severity": alert[6],
        "assigned_to": alert[7] if alert[7] else "Unassigned",
        "status": alert[8],
        "visit_count": alert[9]
    } for alert in acknowledged_alerts]

    return render_template_string(ALERTS_ACKNOWLEDGED_TEMPLATE, alerts=alert_data, total_acknowledged_alerts=total_acknowledged_alerts, page=page, total_pages=total_pages)


@app.route('/alerts/closed')
def view_closed_alerts():
    parse_squid_logs()
    page = request.args.get('page', 1, type=int)  # Get current page number
    per_page = 10
    
    offset= (page - 1) * per_page
    
    cursor.execute("""
        SELECT id, timestamp, client_ip, method, url, message, severity, assigned_to, status, visit_count 
        FROM alerts 
        WHERE status = 'Resolved'
        ORDER BY timestamp DESC
    """)
    closed_alerts = cursor.fetchall()
    
    cursor.execute("SELECT COUNT(*) FROM alerts WHERE status = 'Resolved'", per_page, offset)
    total_closed_alerts = cursor.fetchone()[0]
    
    total_pages = (total_closed_alerts + per_page - 1) // per_page

    alert_data = [{
        "id": alert[0],
        "timestamp": alert[1],
        "client_ip": alert[2],
        "method": alert[3],
        "url": alert[4],
        "message": alert[5],
        "severity": alert[6],
        "assigned_to": alert[7] if alert[7] else "Unassigned",
        "status": alert[8],
        "visit_count": alert[9]
    } for alert in closed_alerts]

    return render_template_string(ALERTS_CLOSED_TEMPLATE, alerts=alert_data, total_closed_alerts=total_closed_alerts, page=page, total_pages=total_pages)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True)
