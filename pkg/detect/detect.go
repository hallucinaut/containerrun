// Package detect provides container runtime anomaly detection.
package detect

import (
	"math"
	"time"
)

// randomString generates a random string.
func randomString(length int) string {
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	result := make([]byte, length)
	for i := range result {
		result[i] = chars[i%len(chars)]
	}
	return string(result)
}

// AnomalyType represents a type of anomaly.
type AnomalyType string

const (
	TypeBehavioral      AnomalyType = "behavioral"
	TypeResource        AnomalyType = "resource"
	TypeNetwork         AnomalyType = "network"
	TypeFilesystem      AnomalyType = "filesystem"
	TypeProcess         AnomalyType = "process"
	TypeSecurity        AnomalyType = "security"
)

// ContainerAnomaly represents a detected container anomaly.
type ContainerAnomaly struct {
	ID           string
	ContainerID  string
	Type         AnomalyType
	Severity     string
	Description  string
	Evidence     string
	Confidence   float64
	Timestamp    time.Time
	Recommendation string
}

// Detector detects container runtime anomalies.
type Detector struct {
	baselines map[string]Baseline
}

// Baseline represents runtime behavior baseline.
type Baseline struct {
	ContainerID string
	CPUAvg      float64
	MemAvg      float64
	NetAvg      float64
	ProcCount   int
	CreatedAt   time.Time
}

// NewDetector creates a new anomaly detector.
func NewDetector() *Detector {
	return &Detector{
		baselines: make(map[string]Baseline),
	}
}

// RecordBaseline records baseline behavior.
func (d *Detector) RecordBaseline(containerID string, baseline Baseline) {
	d.baselines[containerID] = baseline
}

// DetectAnomalies detects anomalies in container runtime.
func (d *Detector) DetectAnomalies(containerID string, metrics map[string]float64) []ContainerAnomaly {
	var anomalies []ContainerAnomaly

	baseline, exists := d.baselines[containerID]
	if !exists {
		return anomalies
	}

	// Check CPU anomaly
	if cpu, ok := metrics["cpu"]; ok {
		anomaly := d.checkCPUAnomaly(containerID, cpu, baseline.CPUAvg)
		if anomaly != nil {
			anomalies = append(anomalies, *anomaly)
		}
	}

	// Check Memory anomaly
	if mem, ok := metrics["memory"]; ok {
		anomaly := d.checkMemoryAnomaly(containerID, mem, baseline.MemAvg)
		if anomaly != nil {
			anomalies = append(anomalies, *anomaly)
		}
	}

	// Check Network anomaly
	if net, ok := metrics["network"]; ok {
		anomaly := d.checkNetworkAnomaly(containerID, net, baseline.NetAvg)
		if anomaly != nil {
			anomalies = append(anomalies, *anomaly)
		}
	}

	return anomalies
}

// checkCPUAnomaly checks for CPU anomalies.
func (d *Detector) checkCPUAnomaly(containerID string, current, baseline float64) *ContainerAnomaly {
	if baseline == 0 {
		return nil
	}

	zScore := math.Abs(current-baseline) / baseline

	if zScore > 2.0 {
		return &ContainerAnomaly{
			ID:          "anomaly-" + randomString(12),
			ContainerID: containerID,
			Type:        TypeResource,
			Severity:    getSeverity(zScore),
			Description: "CPU usage anomaly detected",
			Evidence:    "Current: " + string(rune(int(current*100)+48)) + "%, Baseline: " + string(rune(int(baseline*100)+48)) + "%",
			Confidence:  math.Min(zScore/3.0, 1.0),
			Timestamp:   time.Now(),
			Recommendation: "Investigate high CPU usage",
		}
	}

	return nil
}

// checkMemoryAnomaly checks for memory anomalies.
func (d *Detector) checkMemoryAnomaly(containerID string, current, baseline float64) *ContainerAnomaly {
	if baseline == 0 {
		return nil
	}

	zScore := math.Abs(current-baseline) / baseline

	if zScore > 2.5 {
		return &ContainerAnomaly{
			ID:          "anomaly-" + randomString(12),
			ContainerID: containerID,
			Type:        TypeResource,
			Severity:    getSeverity(zScore),
			Description: "Memory usage anomaly detected",
			Evidence:    "Current: " + string(rune(int(current*100)+48)) + "MB, Baseline: " + string(rune(int(baseline*100)+48)) + "MB",
			Confidence:  math.Min(zScore/3.0, 1.0),
			Timestamp:   time.Now(),
			Recommendation: "Check for memory leaks",
		}
	}

	return nil
}

// checkNetworkAnomaly checks for network anomalies.
func (d *Detector) checkNetworkAnomaly(containerID string, current, baseline float64) *ContainerAnomaly {
	if baseline == 0 {
		return nil
	}

	zScore := math.Abs(current-baseline) / baseline

	if zScore > 3.0 {
		return &ContainerAnomaly{
			ID:          "anomaly-" + randomString(12),
			ContainerID: containerID,
			Type:        TypeNetwork,
			Severity:    getSeverity(zScore),
			Description: "Network activity anomaly detected",
			Evidence:    "Current: " + string(rune(int(current*100)+48)) + "MB/s, Baseline: " + string(rune(int(baseline*100)+48)) + "MB/s",
			Confidence:  math.Min(zScore/3.0, 1.0),
			Timestamp:   time.Now(),
			Recommendation: "Monitor network traffic for suspicious activity",
		}
	}

	return nil
}

// getSeverity returns severity from z-score.
func getSeverity(zScore float64) string {
	if zScore >= 4.0 {
		return "CRITICAL"
	} else if zScore >= 3.0 {
		return "HIGH"
	} else if zScore >= 2.0 {
		return "MEDIUM"
	}
	return "LOW"
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

// DetectBehavioralAnomalies detects behavioral anomalies.
func DetectBehavioralAnomalies(containerID string, behaviorHistory []BehaviorData) []ContainerAnomaly {
	var anomalies []ContainerAnomaly

	if len(behaviorHistory) < 3 {
		return anomalies
	}

	// Calculate behavioral patterns
	mean := calculateMean(behaviorHistory)
	stdDev := calculateStdDev(behaviorHistory, mean)

	for i, data := range behaviorHistory {
		if i < 2 {
			continue
		}

		zScore := math.Abs(data.Value-mean) / stdDev

		if zScore > 2.5 {
			anomalies = append(anomalies, ContainerAnomaly{
				ID:          "behavior-anomaly-" + randomString(12),
				ContainerID: containerID,
				Type:        TypeBehavioral,
				Severity:    getSeverity(zScore),
				Description: "Behavioral pattern deviation detected",
				Evidence:    "Deviation: " + string(rune(int(zScore*100)+48)) + "%",
				Confidence:  math.Min(zScore/3.0, 1.0),
				Timestamp:   time.Now(),
				Recommendation: "Review container behavior patterns",
			})
		}
	}

	return anomalies
}

// BehaviorData represents behavioral data.
type BehaviorData struct {
	Value float64
	Timestamp time.Time
}

// calculateMean calculates mean of behavior data.
func calculateMean(data []BehaviorData) float64 {
	if len(data) == 0 {
		return 0
	}

	sum := 0.0
	for _, d := range data {
		sum += d.Value
	}

	return sum / float64(len(data))
}

// calculateStdDev calculates standard deviation.
func calculateStdDev(data []BehaviorData, mean float64) float64 {
	if len(data) == 0 {
		return 0
	}

	sum := 0.0
	for _, d := range data {
		sum += (d.Value - mean) * (d.Value - mean)
	}

	return math.Sqrt(sum / float64(len(data)))
}

// GenerateAnomalyReport generates anomaly report.
func GenerateAnomalyReport(anomalies []ContainerAnomaly) string {
	var report string

	report += "=== Container Anomaly Report ===\n\n"
	report += "Total Anomalies: " + string(rune(len(anomalies)+48)) + "\n\n"

	if len(anomalies) > 0 {
		report += "Detected Anomalies:\n"
		for i, anomaly := range anomalies {
			report += "[" + string(rune(i+49)) + "] " + anomaly.Severity + " - " + anomaly.Description + "\n"
			report += "    Container: " + anomaly.ContainerID + "\n"
			report += "    Type: " + string(anomaly.Type) + "\n"
			report += "    Confidence: " + string(rune(int(anomaly.Confidence*100)+48)) + "%\n"
			report += "    Recommendation: " + anomaly.Recommendation + "\n\n"
		}
	}

	return report
}