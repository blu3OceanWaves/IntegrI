# IntegrI

**System Integrity & Change Detection Tool**

-- A lightweight Python tool for monitoring Linux system changes, detecting file modifications, tracking user accounts, and maintaining system baselines --

## ✨ Features

- **📁 File System Monitoring** - Track changes to files and directories with hash verification
- **📋 Log Monitoring** - Monitor log files for size and modification time changes
- **🗂 User Account Tracking** - Detect changes to system user accounts
- **📦 Package Management** - Monitor installed packages (supports APT and RPM)
- **🔄 Real-time Watching** - Continuous monitoring with configurable intervals
- **💾 Atomic Operations** - Safe baseline storage with atomic file writes
- **🎯 Flexible Scanning** - Recursive and non-recursive directory scanning
- **🎨 Colorized Output** - Clear, colored terminal output for easy reading

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/blu3OceanWaves/integri.git
cd integri

# Make executable
chmod +x integri.py

# Optional: Make symlink for global access
sudo ln -s $(pwd)/integri.py /usr/local/bin/integri
```

### Basic Usage

```bash
# Scan system and generate baseline
integri scan -f /etc -u -p -o baseline.json

# Compare current state with baseline
integri diff -i baseline.json -f /etc -u -p

# Monitor changes in real-time
integri watch -f /home/user -o monitoring.json -t 30
```

## 📖 Usage Guide

### Commands

| Command | Description |
|---------|-------------|
| `scan` | Generate a system baseline snapshot |
| `diff` | Compare current state with saved baseline |
| `watch` | Continuously monitor for changes |

### Options

| Option | Description | Default |
|--------|-------------|---------|
| `-f, --files [DIR]` | Scan files/directories | `/etc` |
| `-l, --logs [DIR]` | Scan log files | `/var/log` |
| `-u, --users` | Monitor user accounts | - |
| `-p, --packages` | Monitor installed packages | - |
| `--no-recursive` | Disable recursive directory scanning | - |
| `-o, --output FILE` | Output baseline file | - |
| `-i, --input FILE` | Input baseline file for comparison | - |
| `-t, --interval N` | Watch interval in seconds | `10` |

### Examples

#### System Configuration Monitoring
```bash
# Generate baseline for critical system files
integri scan -f /etc -f /usr/local/etc -u -p -o system-baseline.json

# Check for changes
integri diff -i system-baseline.json -f /etc -f /usr/local/etc -u -p
```

#### Home Directory Monitoring
```bash
# Monitor user home directory
integri watch -f /home/username --no-recursive -o home-monitor.json -t 60
```

#### Log File Monitoring
```bash
# Monitor system logs
integri scan -l /var/log -o log-baseline.json
integri diff -i log-baseline.json -l /var/log
```

#### Security Compliance Scanning
```bash
# Comprehensive system scan for compliance
integri scan -f /etc -f /usr/bin -f /usr/sbin -l /var/log -u -p -o compliance-baseline.json
```

## 🔍 What Gets Monitored

### Files (`-f, --files`)
- **Hash (SHA-256)** - Detects content changes
- **Permissions** - File mode changes
- **Ownership** - UID/GID changes
- **Path** - New/removed files

### Logs (`-l, --logs`)
- **File Size** - Growth or truncation
- **Modification Time** - When files were last changed
- **Path** - New/removed log files

### Users (`-u, --users`)
- **User ID** - UID changes
- **Group ID** - Primary GID changes
- **Home Directory** - Home path changes
- **Shell** - Login shell changes

### Packages (`-p, --packages`)
- **Package Versions** - Version changes
- **Installation Status** - Added/removed packages
- **Package Names** - All installed packages

## 📊 Output Format

### Change Detection Symbols
- 🟢 **Added** - New files, users, or packages
- 🔴 **Removed** - Deleted files, users, or packages  
- 🟠 **Changed** - Modified files, users, or packages

### Baseline Format
```json
{
  "schema_version": 1,
  "generated_at": "2024-01-15T10:30:00Z",
  "components": {
    "files": {
      "recursive": true,
      "data": {
        "/etc/passwd": {
          "hash": "a1b2c3...",
          "mode": 33188,
          "uid": 0,
          "gid": 0
        }
      }
    }
  }
}
```

## ⚙️ Advanced Usage

### Ignoring Files
The tool automatically ignores its own baseline files to prevent self-monitoring loops.

### Permission Handling
IntegrI gracefully handles permission denied errors and continues scanning accessible files, displaying warnings for inaccessible locations.

### Atomic Operations
Baseline files are written atomically to prevent corruption during system interruptions.

### Signal Handling
Supports graceful shutdown with Ctrl+C (SIGINT) and SIGTERM signals.

## 🛡️ Security Considerations

- Run with appropriate privileges for the directories you want to monitor
- Store baselines in secure locations to prevent tampering
- Consider encrypting baseline files for sensitive environments
- Regularly update baselines for systems with expected changes
- Use specific directory targets rather than scanning entire filesystems

## 🔧 Requirements

- **Python 3.6+**
- **Linux/Unix system** (uses pwd module and system package managers)
- **Permissions** appropriate for monitored directories

### Package Manager Support
- **APT** (Debian/Ubuntu) - via `dpkg-query`
- **RPM** (RHEL/CentOS/Fedora) - via `rpm`

## ⚙️ Troubleshooting

### Common Issues

**Permission Denied Warnings**
```bash
# Run with appropriate privileges
sudo integri scan -f /etc -o baseline.json
```

**Package Detection Not Working**
- Ensure `dpkg-query` or `rpm` commands are available
- Check if running on supported Linux distribution

**Baseline File Corruption**
- IntegrI uses atomic writes, but ensure sufficient disk space
- Check file permissions on output directory

## Contact
For bugs, feedback, or questions, connect with me on LinkedIn:  

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Yassin-blue?style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/yassin-el-wardioui-34016b332/)

---

**IntegrI** - Keep your system integrity in check! 🔒
