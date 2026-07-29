# PyNetworkIntel CLI Stats Dashboard

## Overview

PyNetworkIntel includes a real-time statistics dashboard that launches in a separate terminal window during network scans and analysis operations. The dashboard provides live updates on scan progress, device discovery, and security findings.

## Features

- **Real-time Stats Display**: Live updates on devices discovered, online status, and security findings
- **Severity Breakdown**: Shows critical, high, medium, low, and info-level findings
- **Cross-platform Support**: Works on macOS, Linux, and Windows with appropriate terminal emulators
- **Separate Terminal Window**: Dashboard runs in its own terminal, separate from the main scan output
- **Auto-platform Detection**: Automatically detects the OS and launches the appropriate terminal application
- **IPC Communication**: Uses sockets (Unix) or named pipes (Windows) for stats synchronization

## Usage

### Basic Usage

Launch the dashboard during a network scan:

```bash
# Scan with live dashboard
pynetworkintel scan 192.168.1.0/24 --dashboard

# Full analysis with dashboard
pynetworkintel analyze 192.168.1.0/24 --dashboard --summarize
```

### Standalone Dashboard Viewer

View stats from an active scan server (advanced usage):

```bash
# Connect to existing stats server
pynetworkintel dashboard --socket /tmp/pynetworkintel_stats_12345.sock
```

## Dashboard Display

The dashboard shows the following information:

### Header Panel
- **Target Network**: The CIDR range or IP being scanned
- **Scan Status**: Current status (Idle, Scanning, Complete)
- **Current Phase**: What phase of scanning is active (Device Discovery, Analysis, etc.)

### Summary Panel (Left)
- **Elapsed Time**: Time since scan started (formatted as s/m/h)
- **Devices Discovered**: Total devices found on the network
- **Devices Online**: Number of responsive devices
- **Configs Grabbed**: SSH configs successfully retrieved

### Findings Panel (Right)
- **Total Findings**: Aggregated security findings across all severity levels
- **Critical**: High-severity vulnerabilities (displayed in red if > 0)
- **High**: High-priority issues (displayed in yellow if > 0)
- **Medium**: Medium-priority issues (displayed in cyan if > 0)
- **Low**: Low-priority issues
- **Info**: Informational findings
- **Current Device**: Device currently being analyzed (if available)

### Footer Panel
- **Error Summary**: Last few errors encountered (if any)
- **Last Update**: Timestamp of the most recent stats update
- **Status Indicator**: Green checkmark if running smoothly, red warning if errors occurred

## Platform-Specific Behavior

### macOS
- Uses Terminal.app to launch the dashboard
- Automatically opens a new terminal window
- Dashboard process runs independently

### Linux
The system automatically detects and uses the first available terminal emulator:
1. `gnome-terminal` (GNOME)
2. `konsole` (KDE)
3. `xterm` (universal fallback)
4. `xfce4-terminal` (XFCE)
5. `terminator` (advanced users)
6. `rxvt` (minimal systems)

### Windows
- Uses `cmd.exe` to launch a new command prompt window
- Dashboard runs in the new terminal instance

## Technical Architecture

### Stats Collection

The `StatsCollector` class tracks:
- Scan target and status
- Device discovery metrics
- Configuration grab counts
- Security findings by severity
- Elapsed time
- Current phase and device
- Error log

### IPC Communication

**Unix/Linux/macOS**: Unix domain sockets (`AF_UNIX`)
- Fast, efficient inter-process communication
- Socket file created in `/tmp/pynetworkintel_stats_<PID>.sock`
- Automatically cleaned up when scan completes

**Windows**: Named pipes
- Uses `\\.\pipe\pynetworkintel_stats` namespace
- Requires Windows 7+

### Dashboard Rendering

Uses the **Rich** library for terminal rendering:
- Live updates without flickering (uses ANSI escape codes)
- Styled tables and panels
- Color-coded severity levels
- Responsive layout that adapts to terminal width

## Examples

### Basic Scan with Dashboard

```bash
$ pynetworkintel scan 192.168.1.0/24 --dashboard

╔═══════════════════════════════════════════════════════════╗
║ PyNetworkIntel Dashboard                   Status: Scanning
║ Target: 192.168.1.0/24  Phase: Device Discovery
╚═══════════════════════════════════════════════════════════╝

┌─ Summary ────────────────────┬─ Findings ─────────────────┐
│ Elapsed Time:        45s     │ Total Findings:          8  │
│ Devices Discovered:  42      │ Critical:                1  │
│ Devices Online:      38      │ High:                    3  │
│ Configs Grabbed:     12      │ Medium:                  4  │
│                              │ Low:                     0  │
│ Current Device: 192.168.1.25 │ Info:                    0  │
└──────────────────────────────┴────────────────────────────┘

┌─ Status ───────────────────────────────────────────────────┐
│ ✓ Running smoothly | Last update: 14:23:45                │
└────────────────────────────────────────────────────────────┘
```

### Full Analysis with Dashboard

```bash
$ pynetworkintel analyze 192.168.1.0/24 --dashboard --summarize

# Dashboard displays live updates as:
# 1. Device discovery begins
# 2. Devices are analyzed
# 3. Findings are collected
# 4. Summary is generated
```

## Troubleshooting

### Dashboard Doesn't Launch

1. **Ensure Rich is installed**: 
   ```bash
   pip install rich>=13.0
   ```

2. **Verify terminal emulator is available**:
   - macOS: Terminal.app comes pre-installed
   - Linux: Install preferred terminal (`apt install gnome-terminal` or similar)
   - Windows: cmd.exe comes with Windows

3. **Check permissions**: Ensure execute permissions on temporary scripts

### Stats Not Updating

1. **Socket file permission issue**: Check `/tmp/` permissions
2. **Terminal emulator crashed**: Re-run with `--dashboard`
3. **Old socket file exists**: Remove `/tmp/pynetworkintel_stats_*.sock`

### Colors Not Showing

- Ensure terminal supports ANSI colors (most modern terminals do)
- Some SSH sessions may not support colors
- Try connecting directly to the system

## Performance Considerations

- **Dashboard overhead**: <5% CPU impact from stats collection
- **Memory usage**: ~10-15 MB additional for dashboard process
- **IPC latency**: <10ms socket communication overhead
- **Refresh rate**: 1 update per second (configurable in code)

## Advanced Usage

### Custom Socket Path

For advanced use cases, specify a custom socket path:

```python
from pynetworkintel.dashboard import DashboardServer, StatsCollector

stats = StatsCollector()
stats.target = "192.168.1.0/24"

server = DashboardServer(stats, socket_path="/custom/path/stats.sock")
server.start()

# Run your scan while server collects stats
# ...

server.stop()
```

### Programmatic API

```python
from pynetworkintel.dashboard import StatsCollector, Dashboard

# Create stats collector
stats = StatsCollector()
stats.target = "192.168.1.0/24"
stats.devices_discovered = 10
stats.findings_critical = 2

# Display dashboard programmatically
dashboard = Dashboard()
dashboard.stats = stats.to_dict()
dashboard.run()  # Runs the display loop until interrupted
```

## Configuration

Dashboard settings in `pynetworkintel/dashboard.py`:

```python
# Refresh rate (updates per second)
refresh_rate = 1.0  # Default: 1 update per second

# Socket timeout
server.settimeout(1.0)  # Unix socket timeout

# Custom colors and styling (via Rich)
# Edit _build_summary(), _build_details() methods
```

## Integration with CI/CD

For CI/CD pipelines, disable the dashboard:

```bash
# Default: no dashboard (lightweight)
pynetworkintel scan 192.168.1.0/24

# Only use --dashboard for interactive terminal sessions
pynetworkintel scan 192.168.1.0/24 --dashboard
```

## See Also

- [README.md](../README.md) - Main documentation
- [CLI Documentation](CLI.md) - Command-line interface guide
- [Rich Library](https://rich.readthedocs.io/) - Terminal rendering library
