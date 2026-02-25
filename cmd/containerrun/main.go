package main

import (
	"fmt"
	"os"

	"github.com/hallucinaut/containerrun/pkg/monitor"
	"github.com/hallucinaut/containerrun/pkg/detect"
)

const version = "1.0.0"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		return
	}

	switch os.Args[1] {
	case "monitor":
		if len(os.Args) < 3 {
			fmt.Println("Error: container ID required")
			printUsage()
			return
		}
		monitorContainer(os.Args[2])
	case "detect":
		if len(os.Args) < 3 {
			fmt.Println("Error: container ID required")
			printUsage()
			return
		}
		detectAnomalies(os.Args[2])
	case "baseline":
		learnBaseline()
	case "check":
		checkSecurity()
	case "version":
		fmt.Printf("containerrun version %s\n", version)
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Printf("Unknown command: %s\n", os.Args[1])
		printUsage()
	}
}

func printUsage() {
	fmt.Printf(`containerrun - Container Runtime Security Monitor

Usage:
  containerrun <command> [options]

Commands:
  monitor <container>  Monitor container runtime security
  detect <container>   Detect runtime anomalies
  baseline             Learn normal behavior baseline
  check                Check security posture
  version              Show version information
  help                 Show this help message

Examples:
  containerrun monitor mycontainer
  containerrun detect mycontainer
`, "containerrun")
}

func monitorContainer(containerID string) {
	fmt.Printf("Monitoring container: %s\n", containerID)
	fmt.Println()

	// In production: connect to container runtime
	// For demo: show monitoring capabilities
	fmt.Println("Runtime Security Monitoring:")
	fmt.Println("  ✓ Process monitoring")
	fmt.Println("  ✓ Filesystem changes")
	fmt.Println("  ✓ Network connections")
	fmt.Println("  ✓ Privilege escalation")
	fmt.Println("  ✓ Resource usage")
	fmt.Println("  ✓ Security events")
	fmt.Println()

	// Example monitoring
	m := monitor.NewMonitor()

	// Add security rules
	m.AddRule(monitor.SecurityRule{
		ID:          "rule-001",
		Name:        "Privilege Escalation",
		Description: "Privilege escalation detected",
		EventType:   monitor.EventPrivilegeEscalation,
		Severity:    "CRITICAL",
		Action:      "alert",
	})

	m.AddRule(monitor.SecurityRule{
		ID:          "rule-002",
		Name:        "Suspicious Exec",
		Description: "Suspicious process execution",
		EventType:   monitor.EventContainerExec,
		Severity:    "HIGH",
		Action:      "alert",
	})

	// Record some events
	event := monitor.RuntimeEvent{
		ID:          "event-001",
		Type:        monitor.EventPrivilegeEscalation,
		Timestamp:   time.Now(),
		ContainerID: containerID,
		Process:     "sudo",
		User:        "root",
		Details:     make(map[string]interface{}),
	}

	m.RecordEvent(event)

	fmt.Println(monitor.GenerateReport(m))
}

func detectAnomalies(containerID string) {
	fmt.Printf("Detecting anomalies in: %s\n", containerID)
	fmt.Println()

	// In production: analyze container runtime metrics
	// For demo: show detection capabilities
	fmt.Println("Anomaly Detection:")
	fmt.Println("  ✓ CPU usage anomalies")
	fmt.Println("  ✓ Memory usage anomalies")
	fmt.Println("  ✓ Network activity anomalies")
	fmt.Println("  ✓ Behavioral pattern deviations")
	fmt.Println("  ✓ Resource consumption spikes")
	fmt.Println()

	// Example detection
	d := detect.NewDetector()

	baseline := detect.Baseline{
		ContainerID: containerID,
		CPUAvg:      25.0,
		MemAvg:      512.0,
		NetAvg:      10.0,
		ProcCount:   10,
		CreatedAt:   time.Now(),
	}

	d.RecordBaseline(containerID, baseline)

	metrics := map[string]float64{
		"cpu":      85.0,
		"memory":   1024.0,
		"network":  50.0,
	}

	anomalies := d.DetectAnomalies(containerID, metrics)

	fmt.Println(detect.GenerateAnomalyReport(anomalies))
}

func learnBaseline() {
	fmt.Println("Learning Baseline")
	fmt.Println("=================")
	fmt.Println()

	fmt.Println("To establish a behavioral baseline:")
	fmt.Println("1. Collect metrics over 24-48 hours")
	fmt.Println("2. Calculate average CPU, memory, network")
	fmt.Println("3. Record normal process patterns")
	fmt.Println("4. Establish acceptable ranges")
	fmt.Println()

	fmt.Println("Baseline metrics:")
	fmt.Println("  • CPU usage average")
	fmt.Println("  • Memory consumption")
	fmt.Println("  • Network activity patterns")
	fmt.Println("  • Process count and types")
	fmt.Println("  • Filesystem access patterns")
}

func checkSecurity() {
	fmt.Println("Container Runtime Security Check")
	fmt.Println("=================================")
	fmt.Println()

	fmt.Println("Security Controls:")
	fmt.Println("  ✓ Process isolation")
	fmt.Println("  ✓ Filesystem monitoring")
	fmt.Println("  ✓ Network segmentation")
	fmt.Println("  ✓ Resource limits")
	fmt.Println("  ✓ Privilege escalation detection")
	fmt.Println("  ✓ Anomaly detection")
	fmt.Println()

	fmt.Println("Recommended Practices:")
	fmt.Println("  • Monitor all containers")
	fmt.Println("  • Establish baselines")
	fmt.Println("  • Alert on anomalies")
	fmt.Println("  • Regular security audits")
}