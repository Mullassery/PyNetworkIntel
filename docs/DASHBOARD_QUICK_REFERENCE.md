# Dashboard Quick Reference

## Quick Start

```bash
# Scan with live dashboard
pynetworkintel scan 192.168.1.0/24 --dashboard

# Analyze with dashboard
pynetworkintel analyze 192.168.1.0/24 --dashboard --summarize
```

## Dashboard Display

### Header
```
PyNetworkIntel Dashboard | Target: 192.168.1.0/24 | Status: Scanning | Phase: Device Discovery
```

### Summary Panel (Left)
| Metric | Description |
|--------|-------------|
| Elapsed Time | Time since scan started |
| Devices Discovered | Total devices found |
| Devices Online | Responsive devices |
| Configs Grabbed | SSH configs retrieved |

### Findings Panel (Right)
| Severity | Color | Meaning |
|----------|-------|---------|
| Critical | 🔴 Red | Immediate action required |
| High | 🟠 Yellow | Fix within 30 days |
| Medium | 🔵 Cyan | Track and plan |
| Low | 🟢 Green | Low priority |
| Info | 🔵 Blue | Informational only |

### Footer
- Error summary (if any)
- Last update timestamp
- Status indicator ✓ or ⚠️

## Commands

```bash
# Scan with dashboard
pynetworkintel scan <target> --dashboard

# Analyze with dashboard
pynetworkintel analyze <target> --dashboard

# View dashboard alone (advanced)
pynetworkintel dashboard --socket /tmp/pynetworkintel_stats_<PID>.sock

# Help
pynetworkintel scan --help
pynetworkintel analyze --help
pynetworkintel dashboard --help
```

## Platform Support

| OS | Terminal | Status |
|----|-----------| -------|
| macOS | Terminal.app | ✓ Auto-launch |
| Linux | GNOME / Konsole / Xterm / etc | ✓ Auto-detect |
| Windows | Command Prompt | ✓ Auto-launch |

## Common Issues

| Issue | Solution |
|-------|----------|
| Dashboard doesn't launch | Install Rich: `pip install rich` |
| Terminal not found (Linux) | Install: `apt install gnome-terminal` |
| Stats not updating | Check `/tmp/` permissions |
| Colors not showing | Terminal may not support ANSI colors |

## Programmatic Usage

```python
from pynetworkintel.dashboard import launch_stats_dashboard

# Launch dashboard
process, server = launch_stats_dashboard("192.168.1.0/24")

# Update stats
server.stats.devices_discovered = 42
server.stats.findings_critical = 2

# Stop server
server.stop()
```

## Dashboard Features

✓ Real-time stat updates (1Hz)  
✓ Cross-platform support  
✓ Auto-launching terminals  
✓ Color-coded severity  
✓ <5% CPU overhead  
✓ Independent terminal window  
✓ Automatic cleanup  

## See Also

- [Full Dashboard Docs](DASHBOARD.md)
- [PyNetworkIntel README](../README.md)
- [Implementation Details](../DASHBOARD_IMPLEMENTATION.md)
