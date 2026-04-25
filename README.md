# Insider Threat Detection & Simulation Ecosystem

A professional, multi-user web-based insider threat detection simulation designed for hackathons and cybersecurity demonstrations.

## Features
* **Master Control Hub**: Orchestrates the environment with dynamic multi-pane split screens to view the entire attack surface simultaneously.
* **User Dashboard (E-Commerce)**: A fully functional simulated storefront with Cart, Checkout, and Order Tracking.
* **Hacker Terminal**: A cyberpunk-themed exploit toolkit featuring live packet sniffing, GPS tracking, and automated firewall bypass mechanisms.
* **Admin SOC Dashboard**: A high-end glassmorphic security operations center with real-time dwell time analysis, forensic history logging, and emergency override controls.

## Architecture
This project uses a serverless front-end architecture designed for easy demonstration. It utilizes the browser's `localStorage` API as a shared network bus to facilitate real-time communication between the Victim, the Hacker, and the Admin SOC without requiring a complex backend database.

## Installation & Usage

1. **Download or Clone** this repository.
2. **Start a Local Web Server**: Because the simulation relies on `localStorage` across iframes, the files must be served over HTTP (not opened directly via `file://`).
   
   If you have Python installed, open your terminal in this directory and run:
   ```bash
   python -m http.server 8000
   ```
3. **Launch the Simulation**: Open your web browser and navigate to:
   ```text
   http://localhost:8000/master_dashboard.html
   ```

## Demo Credentials

**Admin SOC Dashboard:**
* **Email:** `mohanreddyn18@gmail.com`
* **Password:** `mohanreddyn18`

**User Dashboards:**
* Users can create any mock email (e.g., `alice@example.com`, `bob@example.com`) to sign in. 
* *Note: The system enforces concurrent session checks, so User 1 and User 2 cannot use the same email simultaneously.*
