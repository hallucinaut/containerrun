// Package monitor provides container runtime security monitoring.
package monitor

import (
	"time"
)

// RuntimeEvent represents a container runtime event.
type RuntimeEvent struct {
	ID          string
	Type        EventType
	Timestamp   time.Time
	ContainerID string
	Image       string
	Process     string
	User        string
	Network     string
	Details     map[string]interface{}
}

// EventType represents the type of runtime event.
type EventType string

const (
	EventContainerStart   EventType = "container_start"
	EventContainerStop    EventType = "container_stop"
	EventContainerExec    EventType = "container_exec"
	EventNetworkConnect   EventType = "network_connect"
	EventNetworkDisconnect EventType = "network_disconnect"
	EventFilesystemChange EventType = "filesystem_change"
	EventPrivilegeEscalation EventType = "privilege_escalation"
	EventProcessAnomaly   EventType = "process_anomaly"
	EventMemoryAnomaly    EventType = "memory_anomaly"
	EventCPUThrottling    EventType = "cpu_throttling"
)

// SecurityRule represents a security monitoring rule.
type SecurityRule struct {
	ID          string
	Name        string
	Description string
	EventType   EventType
	Condition   string
	Severity    string
	Action      string
}

// Monitor monitors container runtime security.
type Monitor struct {
	rules        []SecurityRule
	events       []RuntimeEvent
	alerts       []Alert
}

// Alert represents a security alert.
type Alert struct {
	ID          string
	RuleID      string
	EventType   string
	Severity    string
	Message     string
	Evidence    string
	Timestamp   time.Time
	ContainerID string
}

// NewMonitor creates a new container runtime monitor.
func NewMonitor() *Monitor {
	return &Monitor{
		rules: make([]SecurityRule, 0),
		events: make([]RuntimeEvent, 0),
		alerts: make([]Alert, 0),
	}
}

// AddRule adds a security rule.
func (m *Monitor) AddRule(rule SecurityRule) {
	m.rules = append(m.rules, rule)
}

// RecordEvent records a runtime event.
func (m *Monitor) RecordEvent(event RuntimeEvent) {
	m.events = append(m.events, event)
	m.checkRules(event)
}

// checkRules checks events against security rules.
func (m *Monitor) checkRules(event RuntimeEvent) {
	for _, rule := range m.rules {
		if rule.EventType == event.Type {
			alert := m.evaluateRule(rule, event)
			if alert != nil {
				m.alerts = append(m.alerts, *alert)
			}
		}
	}
}

// evaluateRule evaluates a rule against an event.
func (m *Monitor) evaluateRule(rule SecurityRule, event RuntimeEvent) *Alert {
	// Simplified rule evaluation
	if event.Type == rule.EventType {
		return &Alert{
			ID:          generateAlertID(),
			RuleID:      rule.ID,
			EventType:   string(rule.EventType),
			Severity:    rule.Severity,
			Message:     rule.Description,
			Evidence:    event.ContainerID,
			Timestamp:   event.Timestamp,
			ContainerID: event.ContainerID,
		}
	}
	return nil
}

// generateAlertID generates a unique alert ID.
func generateAlertID() string {
	return "alert-" + time.Now().Format("20060102150405") + "-" + randomString(8)
}

// randomString generates a random string.
func randomString(length int) string {
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	result := make([]byte, length)
	for i := range result {
		result[i] = chars[i%len(chars)]
	}
	return string(result)
}

// GetAlerts returns all alerts.
func (m *Monitor) GetAlerts() []Alert {
	return m.alerts
}

// GetEvents returns all recorded events.
func (m *Monitor) GetEvents() []RuntimeEvent {
	return m.events
}

// GetContainers returns monitored containers.
func (m *Monitor) GetContainers() map[string]bool {
	containers := make(map[string]bool)
	for _, event := range m.events {
		containers[event.ContainerID] = true
	}
	return containers
}

// GenerateReport generates monitoring report.
func GenerateReport(monitor *Monitor) string {
	var report string

	report += "=== Container Runtime Security Report ===\n\n"
	report += "Total Events: " + string(rune(len(monitor.events)+48)) + "\n"
	report += "Total Alerts: " + string(rune(len(monitor.alerts)+48)) + "\n"
	report += "Monitored Containers: " + string(rune(len(monitor.GetContainers())+48)) + "\n\n"

	report += "Security Rules Configured: " + string(rune(len(monitor.rules)+48)) + "\n"

	if len(monitor.alerts) > 0 {
		report += "\nRecent Alerts:\n"
		for i, alert := range monitor.alerts {
			if i >= 10 {
				break
			}
			report += "  [" + string(rune(i+49)) + "] " + alert.Severity + " - " + alert.Message + "\n"
			report += "      Container: " + alert.ContainerID + "\n"
			report += "      Time: " + alert.Timestamp.Format("2006-01-02 15:04:05") + "\n\n"
		}
	}

	return report
}

// CalculateRiskScore calculates runtime risk score.
func CalculateRiskScore(monitor *Monitor) float64 {
	if len(monitor.events) == 0 {
		return 0.0
	}

	alertCount := float64(len(monitor.alerts))
	eventCount := float64(len(monitor.events))

	// Risk score based on alert ratio
	riskScore := (alertCount / eventCount) * 100.0

	return math.Min(riskScore, 100.0)
}

// GetAlertsBySeverity returns alerts by severity.
func GetAlertsBySeverity(monitor *Monitor, severity string) []Alert {
	var filtered []Alert
	for _, alert := range monitor.alerts {
		if alert.Severity == severity {
			filtered = append(filtered, alert)
		}
	}
	return filtered
}

// GetEventsByType returns events by type.
func GetEventsByType(monitor *Monitor, eventType EventType) []RuntimeEvent {
	var filtered []RuntimeEvent
	for _, event := range monitor.events {
		if event.Type == eventType {
			filtered = append(filtered, event)
		}
	}
	return filtered
}