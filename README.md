# containerrun - Container Runtime Security Monitor

[![Go](https://img.shields.io/badge/Go-1.21-blue)](https://go.dev/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

**Monitor container runtime security and detect anomalies in real-time.**

Protect your containerized applications from runtime attacks, resource abuse, and security violations.

## 🚀 Features

- **Runtime Event Monitoring**: Monitor container start, stop, exec, network events
- **Security Rule Engine**: Configure custom security rules for containers
- **Anomaly Detection**: Detect CPU, memory, network, and behavioral anomalies
- **Baseline Learning**: Learn normal container behavior for comparison
- **Alert System**: Generate security alerts on suspicious activity
- **Comprehensive Reporting**: Detailed security and anomaly reports

## 📦 Installation

### Build from Source

```bash
git clone https://github.com/hallucinaut/containerrun.git
cd containerrun
go build -o containerrun ./cmd/containerrun
sudo mv containerrun /usr/local/bin/
```

### Install via Go

```bash
go install github.com/hallucinaut/containerrun/cmd/containerrun@latest
```

## 🎯 Usage

### Monitor Container

```bash
# Monitor container runtime security
containerrun monitor mycontainer
```

### Detect Anomalies

```bash
# Detect runtime anomalies
containerrun detect mycontainer
```

### Learn Baseline

```bash
# Establish normal behavior baseline
containerrun baseline
```

### Check Security

```bash
# Check security posture
containerrun check
```

### Programmatic Usage

```go
package main

import (
    "fmt"
    "github.com/hallucinaut/containerrun/pkg/monitor"
    "github.com/hallucinaut/containerrun/pkg/detect"
)

func main() {
    // Create monitor
    m := monitor.NewMonitor()
    
    // Add security rules
    m.AddRule(monitor.SecurityRule{
        ID:          "rule-001",
        Name:        "Privilege Escalation",
        Description: "Privilege escalation detected",
        EventType:   monitor.EventPrivilegeEscalation,
        Severity:    "CRITICAL",
    })
    
    // Record event
    event := monitor.RuntimeEvent{
        ID:          "event-001",
        Type:        monitor.EventPrivilegeEscalation,
        ContainerID: "container-123",
        Timestamp:   time.Now(),
    }
    
    m.RecordEvent(event)
    
    // Get alerts
    alerts := m.GetAlerts()
    fmt.Printf("Alerts: %d\n", len(alerts))
    
    // Detect anomalies
    d := detect.NewDetector()
    baseline := detect.Baseline{
        ContainerID: "container-123",
        CPUAvg:      25.0,
        MemAvg:      512.0,
    }
    d.RecordBaseline("container-123", baseline)
    
    metrics := map[string]float64{"cpu": 85.0, "memory": 1024.0}
    anomalies := d.DetectAnomalies("container-123", metrics)
    
    fmt.Printf("Anomalies: %d\n", len(anomalies))
}
```

## 🔍 Monitored Events

| Event Type | Description | Security Impact |
|------------|-------------|-----------------|
| Container Start/Stop | Lifecycle events | Track container activity |
| Container Exec | Command execution | Detect suspicious commands |
| Network Connect/Disconnect | Network changes | Monitor network access |
| Filesystem Change | File modifications | Detect malicious files |
| Privilege Escalation | Permission changes | Critical security event |
| Process Anomaly | Process behavior | Detect malicious processes |
| Memory Anomaly | Memory usage | Detect memory exploits |
| CPU Throttling | CPU limits | Detect resource abuse |

## 🛡️ Security Rules

### Pre-configured Rules

1. **Privilege Escalation** - CRITICAL
2. **Suspicious Exec** - HIGH
3. **Network Anomaly** - MEDIUM
4. **Filesystem Modification** - MEDIUM
5. **Resource Abuse** - LOW

### Custom Rules

Create custom rules based on your security requirements:
- Define event types to monitor
- Set conditions for triggering
- Configure severity levels
- Specify alert actions

## 📊 Anomaly Detection

### Resource Anomalies

- **CPU**: Detect unusual CPU usage spikes
- **Memory**: Identify memory leaks or attacks
- **Network**: Monitor abnormal network activity

### Behavioral Anomalies

- Process pattern deviations
- Filesystem access anomalies
- Unusual command execution

## 🧪 Testing

```bash
# Run all tests
go test ./...

# Run with coverage
go test -cover ./...

# Run specific test
go test -v ./pkg/monitor -run TestRecordEvent
```

## 📋 Example Output

```
Monitoring container: mycontainer

=== Container Runtime Security Report ===

Total Events: 15
Total Alerts: 3
Monitored Containers: 1

Security Rules Configured: 2

Recent Alerts:
  [1] CRITICAL - Privilege escalation detected
      Container: container-123
      Time: 2024-02-25 16:30:00

  [2] HIGH - Suspicious process execution
      Container: container-123
      Time: 2024-02-25 16:29:00
```

## 🔒 Security Use Cases

- **Container Security**: Protect containerized applications
- **Runtime Defense**: Detect and respond to runtime attacks
- **Compliance Monitoring**: Ensure container security compliance
- **Threat Detection**: Identify malicious container activity
- **Resource Management**: Prevent resource abuse

## 🛡️ Best Practices

1. **Monitor all containers** in your environment
2. **Establish baselines** for normal behavior
3. **Configure alerts** for critical events
4. **Review alerts** regularly
5. **Update rules** based on new threats
6. **Integrate with SIEM** for centralized logging

## 🏗️ Architecture

```
containerrun/
├── cmd/
│   └── containerrun/
│       └── main.go          # CLI entry point
├── pkg/
│   ├── monitor/
│   │   ├── monitor.go      # Runtime monitoring
│   │   └── monitor_test.go # Unit tests
│   └── detect/
│       ├── detect.go       # Anomaly detection
│       └── detect_test.go  # Unit tests
└── README.md
```

## 📄 License

MIT License

## 🙏 Acknowledgments

- Container security research community
- Kubernetes security practitioners
- Open source security tools

## 🔗 Resources

- [Kubernetes Security](https://kubernetes.io/docs/concepts/security/)
- [Container Security Best Practices](https://www.cncf.io/blog/2021/03/02/container-security-best-practices/)
- [OWASP Container Security](https://owasp.org/www-project-container-security/)

---

**Built with ❤️ by [hallucinaut](https://github.com/hallucinaut)**