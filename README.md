Behavioural Monitoring Agent for Linux-Based IoT Devices

Overview

This is a lightweight, event-driven behavioral monitoring agent written in C for Linux-based IoT devices (e.g., i.MX8, i.MX6). The agent collects security-relevant and system usage data, and publishes optimized JSON payloads to a remote MQTT server using secure TLS communication. It is designed to run as a daemon via systemd.

Key Features

✅ Real-Time System Monitoring

CPU temperature, usage, and top processes

Memory and disk usage

Network interface usage with IP and MAC info

Device ID and OS/kernel info

System uptime

✅ Event-Driven Behavioral Logs

Login Activity: Tracks current users and detects login/logout events

Failed Logins: Detects new failed login attempts and sudo access denials

Reboot Events: Captures and reports reboots only if new ones occur

Package Monitoring: Sends package install/removal events with package names

✅ Efficient MQTT Transmission

Sends a unified JSON object every 10 seconds

Only includes data that has changed since the last transmission

Uses secure TLS (port 8883) with client and server certificates

Directory Structure

project/
|│-- Behavioural_Attributes_Buff.c        # Main C source code
|│-- cert/
|   |│-- ca.crt                           # CA certificate (for server verification)
|   |│-- client.crt                       # Client certificate
|   |│-- client.key                       # Client private key
|│-- Behavioural_Attributes.service      # Systemd service file
|│-- README.md                          # This file

Installation & Setup

1. Prerequisites

Install required packages:

sudo apt install libmosquitto-dev mosquitto-clients build-essential

2. Build

gcc Behavioural_Attributes_Buff.c -o Behavioural_Attributes_Buff_Static -lmosquitto
sudo cp Behavioural_Attributes_Buff_Static /usr/local/bin/

3. Certificates

Place your certificates at:

/etc/ssl/behavioural_agent/
  - ca.crt
  - client.crt
  - client.key

Ensure correct permissions:

sudo chown root:root /etc/ssl/behavioural_agent/*
sudo chmod 600 /etc/ssl/behavioural_agent/*

4. Service Setup

Copy and enable the systemd service:

sudo cp Behavioural_Attributes.service /etc/systemd/system/
sudo systemctl daemon-reexec
sudo systemctl daemon-reload
sudo systemctl enable Behavioural_Attributes.service
sudo systemctl start Behavioural_Attributes.service

5. Check Logs

tail -f /var/log/Behavioural_Attributes.log

Output JSON Format (Sample)

{
  "Timestamp": "2025-08-08T12:00:00Z",
  "Device_ID": "a1b2c3d4...",
  "Up_Time": "12345.67",
  "CPU_Usage": { ... },
  "Memory_Usage": { ... },
  "Top_CPU_Processes": [ ... ],
  "User_Events": [
    {"user": "pi", "action": "logged_in"},
    {"user": "om", "action": "logged_out"}
  ],
  "Failed_Login_Events": [
    {"user": "om", "host": "192.168.1.2", "time": "2025-08-08 11:55:00"}
  ],
  "Reboot_Event": {
    "type": "Reboot", "time": "2025-08-08 10:00:00"
  },
  "Package_Events": [
    {"package": "htop", "status": "installed"},
    {"package": "vim", "status": "removed"}
  ]
}

6. Install as Daemon (Systemd)
Copy binary to /usr/local/bin/:
sudo cp Behavioural_Attributes_Buff_Static /usr/local/bin/

Copy the service file:
sudo cp Behavioural_Attributes.service /etc/systemd/system/

Reload systemd and enable:
sudo systemctl daemon-reexec
sudo systemctl enable Behavioural_Attributes
sudo systemctl start Behavioural_Attributes

Check status:
sudo systemctl status Behavioural_Attributes
tail -f /var/log/Behavioural_Attributes.log

7. MQTT Configuration

#define BROKER "your.broker.ip"
#define TOPIC  "device/data"

#define CA_CERT_PATH      "/etc/ssl/behavioural_agent/ca.crt"
#define CLIENT_CERT_PATH  "/etc/ssl/behavioural_agent/client.crt"
#define CLIENT_PVT_KEY_PATH "/etc/ssl/behavioural_agent/client.key"

8. Verifying Functionality
Monitor real-time JSON output via MQTT subscriber (e.g., using mosquitto_sub)
Cross-check system metrics using native Linux tools:
uptime, top, free -m, df -h, who, last -f /var/log/btmp

9. Cleanup
To stop and disable the daemon:
sudo systemctl stop Behavioural_Attributes
sudo systemctl disable Behavioural_Attributes

To remove log files:
sudo rm /var/log/Behavioural_Attributes.log

10. Known Limitations
Cached state is held in-memory only (resets on reboot)

Requires sudo/root for reading sensitive logs

Assumes standard Linux file locations (/var/log/, /proc/, /sys/)

Security Considerations

All MQTT data is encrypted with TLS 1.2V

The device uses unique client certificates for authentication

Only essential file reads (no shell commands)

Runs with reduced privileges using DynamicUser=yes

Tested On

i.MX 8ULP (Debian-based image)

i.MX 6 Quad (Timesys Linux)

Raspberry Pi 4 (Debian Buster)

Contributions & License

This is a research-grade project developed at CDAC Bangalore for secure IoT onboarding and monitoring. 
