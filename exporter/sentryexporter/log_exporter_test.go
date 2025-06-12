// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package sentryexporter

import (
	"context"
	"testing"
	"time"

	"github.com/getsentry/sentry-go"
	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/collector/exporter/exportertest"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	conventions "go.opentelemetry.io/otel/semconv/v1.18.0"

	"github.com/open-telemetry/opentelemetry-collector-contrib/exporter/sentryexporter/internal/metadata"
)

func createSimpleLogData(numberOfLogs int) plog.Logs {
	logs := plog.NewLogs()
	rl := logs.ResourceLogs().AppendEmpty()
	sl := rl.ScopeLogs().AppendEmpty()

	for i := 0; i < numberOfLogs; i++ {
		ts := pcommon.Timestamp(int64(i) * time.Millisecond.Nanoseconds())
		logRecord := sl.LogRecords().AppendEmpty()
		logRecord.Body().SetStr("Test log message")
		logRecord.Attributes().PutStr(string(conventions.ServiceNameKey), "test-service")
		logRecord.Attributes().PutStr("custom-key", "custom-value")
		logRecord.SetTimestamp(ts)
		logRecord.SetSeverityNumber(plog.SeverityNumberInfo)
		logRecord.SetSeverityText("INFO")
	}

	return logs
}

func createComplexLogData() plog.Logs {
	logs := plog.NewLogs()
	rl := logs.ResourceLogs().AppendEmpty()
	sl := rl.ScopeLogs().AppendEmpty()

	// Create a log record with various attributes and trace context
	logRecord := sl.LogRecords().AppendEmpty()
	logRecord.Body().SetStr("Complex log message")
	logRecord.SetTimestamp(pcommon.Timestamp(time.Now().UnixNano()))
	logRecord.SetSeverityNumber(plog.SeverityNumberError)
	logRecord.SetSeverityText("ERROR")
	logRecord.SetEventName("test.event")

	// Set trace context
	traceID := pcommon.TraceID([16]byte{1, 2, 3, 4, 5, 6, 7, 8, 8, 7, 6, 5, 4, 3, 2, 1})
	logRecord.SetTraceID(traceID)

	// Add various attribute types
	logRecord.Attributes().PutStr("string-attr", "string-value")
	logRecord.Attributes().PutBool("bool-attr", true)
	logRecord.Attributes().PutInt("int-attr", 42)
	logRecord.Attributes().PutDouble("double-attr", 3.14)

	return logs
}

func TestNewSentryLogsExporter(t *testing.T) {
	t.Run("with valid config", func(t *testing.T) {
		config := &Config{
			DSN:         "https://key@sentry.io/123",
			Environment: "test",
		}

		exporter, err := newSentryLogsExporter(config, exportertest.NewNopSettings(metadata.Type))
		assert.NoError(t, err)
		assert.NotNil(t, exporter)
	})

	t.Run("with insecure skip verify", func(t *testing.T) {
		config := &Config{
			DSN:                "https://key@sentry.io/123",
			Environment:        "test",
			InsecureSkipVerify: true,
		}

		exporter, err := newSentryLogsExporter(config, exportertest.NewNopSettings(metadata.Type))
		assert.NoError(t, err)
		assert.NotNil(t, exporter)
	})
}

type mockLogsTransport struct {
	events   []*sentry.Event
	called   bool
	sentLogs []sentry.Log
}

func (m *mockLogsTransport) SendEvent(event *sentry.Event) {
	m.events = append(m.events, event)
	m.called = true
	if event.Logs != nil {
		m.sentLogs = append(m.sentLogs, event.Logs...)
	}
}

func (m *mockLogsTransport) SendTransactionEvents(events []*sentry.Event) {
	m.events = append(m.events, events...)
	m.called = true
}

func (m *mockLogsTransport) Configure(_ sentry.ClientOptions) {}

func (m *mockLogsTransport) Flush(_ context.Context) bool {
	return true
}

func TestSentryLogsExporter_pushLogsData(t *testing.T) {
	testCases := []struct {
		name     string
		logData  plog.Logs
		expected bool
	}{
		{
			name:     "with empty logs",
			logData:  plog.NewLogs(),
			expected: true,
		},
		{
			name:     "with simple log data",
			logData:  createSimpleLogData(1),
			expected: true,
		},
		{
			name:     "with complex log data",
			logData:  createComplexLogData(),
			expected: true,
		},
		{
			name:     "with multiple logs",
			logData:  createSimpleLogData(3),
			expected: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockTransport := &mockLogsTransport{}
			exporter := &SentryLogsExporter{
				transport:   mockTransport,
				environment: "test",
			}

			err := exporter.pushLogsData(context.Background(), tc.logData)
			assert.NoError(t, err)
			assert.Equal(t, tc.expected, mockTransport.called)

			if tc.logData.LogRecordCount() > 0 {
				assert.NotEmpty(t, mockTransport.events)
				assert.Equal(t, "log", mockTransport.events[0].Type)
				assert.NotNil(t, mockTransport.events[0].Logs)
			}
		})
	}
}

func TestOtelLogsToSentryLogs(t *testing.T) {
	exporter := &SentryLogsExporter{environment: "test"}

	t.Run("with empty logs", func(t *testing.T) {
		logs := plog.NewLogs()
		result := exporter.otelLogsToSentryLogs(logs)
		assert.Nil(t, result)
	})

	t.Run("with single log", func(t *testing.T) {
		logs := createSimpleLogData(1)
		result := exporter.otelLogsToSentryLogs(logs)
		assert.Len(t, result, 1)
		assert.Equal(t, "Test log message", result[0].Body)
	})

	t.Run("with multiple logs", func(t *testing.T) {
		logs := createSimpleLogData(3)
		result := exporter.otelLogsToSentryLogs(logs)
		assert.Len(t, result, 3)
	})

	t.Run("with multiple resource logs", func(t *testing.T) {
		logs := plog.NewLogs()
		// First resource log
		rl1 := logs.ResourceLogs().AppendEmpty()
		sl1 := rl1.ScopeLogs().AppendEmpty()
		lr1 := sl1.LogRecords().AppendEmpty()
		lr1.Body().SetStr("Log 1")
		lr1.SetTimestamp(pcommon.Timestamp(time.Now().UnixNano()))

		// Second resource log
		rl2 := logs.ResourceLogs().AppendEmpty()
		sl2 := rl2.ScopeLogs().AppendEmpty()
		lr2 := sl2.LogRecords().AppendEmpty()
		lr2.Body().SetStr("Log 2")
		lr2.SetTimestamp(pcommon.Timestamp(time.Now().UnixNano()))

		result := exporter.otelLogsToSentryLogs(logs)
		assert.Len(t, result, 2)
		assert.Equal(t, "Log 1", result[0].Body)
		assert.Equal(t, "Log 2", result[1].Body)
	})
}

func TestConvertToSentryLog(t *testing.T) {
	exporter := &SentryLogsExporter{environment: "test-env"}

	t.Run("with full log record", func(t *testing.T) {
		logRecord := plog.NewLogRecord()
		logRecord.Body().SetStr("Test message")
		logRecord.SetTimestamp(pcommon.Timestamp(1234567890000000000))
		logRecord.SetSeverityNumber(plog.SeverityNumberError)
		logRecord.SetSeverityText("ERROR")
		logRecord.SetEventName("test.event")

		traceID := pcommon.TraceID([16]byte{1, 2, 3, 4, 5, 6, 7, 8, 8, 7, 6, 5, 4, 3, 2, 1})
		logRecord.SetTraceID(traceID)

		logRecord.Attributes().PutStr("custom-key", "custom-value")
		logRecord.Attributes().PutBool("bool-key", true)
		logRecord.Attributes().PutInt("int-key", 42)
		logRecord.Attributes().PutDouble("double-key", 3.14)

		// Create empty resource and scope for testing
		resource := pcommon.NewResource()
		scope := pcommon.NewInstrumentationScope()

		result := exporter.convertToSentryLog(logRecord, resource, scope)

		// EventName takes precedence over Body in getLogMessageFromLogRecord()
		assert.Equal(t, "test.event", result.Body)
		assert.Equal(t, time.Unix(1234567890, 0), result.Timestamp)
		assert.Equal(t, sentry.LogLevelError, result.Level)
		assert.Equal(t, int(plog.SeverityNumberError), result.Severity)
		assert.Equal(t, sentry.TraceID(traceID), result.TraceID)

		// Check standard attributes
		assert.Equal(t, "test-env", result.Attributes["sentry.environment"].Value)
		assert.Equal(t, otelSentryLogsExporterName, result.Attributes["sentry.sdk.name"].Value)
		assert.Equal(t, otelSentryLogsExporterVersion, result.Attributes["sentry.sdk.version"].Value)

		// Check custom attributes
		assert.Equal(t, "custom-value", result.Attributes["custom-key"].Value)
		assert.Equal(t, "test.event", result.Attributes["event.name"].Value)
		assert.Equal(t, true, result.Attributes["bool-key"].Value)
		assert.Equal(t, int64(42), result.Attributes["int-key"].Value)
		assert.Equal(t, 3.14, result.Attributes["double-key"].Value)
	})

	t.Run("with minimal log record", func(t *testing.T) {
		logRecord := plog.NewLogRecord()
		logRecord.Body().SetStr("Minimal message")

		// Create empty resource and scope for testing
		resource := pcommon.NewResource()
		scope := pcommon.NewInstrumentationScope()

		result := exporter.convertToSentryLog(logRecord, resource, scope)

		assert.Equal(t, "Minimal message", result.Body)
		assert.Equal(t, sentry.LogLevelInfo, result.Level) // Default level
		assert.Equal(t, int(plog.SeverityNumberUnspecified), result.Severity)
		assert.NotNil(t, result.Attributes)
	})
}

func TestLogRecordSeverityTextToSentryLogLevel(t *testing.T) {
	testCases := []struct {
		name           string
		severityNumber plog.SeverityNumber
		severityText   string
		expected       sentry.Level
	}{
		// Test severity numbers
		{"trace number", plog.SeverityNumber(1), "", sentry.LogLevelTrace},
		{"debug number", plog.SeverityNumber(5), "", sentry.LogLevelDebug},
		{"info number", plog.SeverityNumber(9), "", sentry.LogLevelInfo},
		{"warn number", plog.SeverityNumber(13), "", sentry.LogLevelWarn},
		{"error number", plog.SeverityNumber(17), "", sentry.LogLevelError},
		{"fatal number", plog.SeverityNumber(21), "", sentry.LogLevelFatal},

		// Test severity text
		{"trace text", plog.SeverityNumberUnspecified, "trace", sentry.LogLevelTrace},
		{"debug text", plog.SeverityNumberUnspecified, "debug", sentry.LogLevelDebug},
		{"info text", plog.SeverityNumberUnspecified, "info", sentry.LogLevelInfo},
		{"warn text", plog.SeverityNumberUnspecified, "warn", sentry.LogLevelWarn},
		{"error text", plog.SeverityNumberUnspecified, "error", sentry.LogLevelError},
		{"fatal text", plog.SeverityNumberUnspecified, "fatal", sentry.LogLevelFatal},

		// Test default case
		{"unknown", plog.SeverityNumberUnspecified, "unknown", sentry.LogLevelInfo},
		{"empty", plog.SeverityNumberUnspecified, "", sentry.LogLevelInfo},

		// Test that number takes precedence over text
		{"number precedence", plog.SeverityNumber(21), "debug", sentry.LogLevelFatal},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := logRecordSeverityTextToSentryLogLevel(tc.severityNumber, tc.severityText)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestGenerateSentryAttributesFromLogRecord(t *testing.T) {
	t.Run("with various attribute types", func(t *testing.T) {
		logRecord := plog.NewLogRecord()
		logRecord.SetEventName("test.event")
		logRecord.Attributes().PutStr("string-key", "string-value")
		logRecord.Attributes().PutBool("bool-key", true)
		logRecord.Attributes().PutInt("int-key", 42)
		logRecord.Attributes().PutDouble("double-key", 3.14)

		result := generateSentryAttributesFromLogRecord(logRecord, pcommon.NewResource(), pcommon.NewInstrumentationScope())

		assert.Equal(t, "test.event", result["event.name"].Value)
		assert.Equal(t, "string", result["event.name"].Type)

		assert.Equal(t, "string-value", result["string-key"].Value)
		assert.Equal(t, "string", result["string-key"].Type)

		assert.Equal(t, true, result["bool-key"].Value)
		assert.Equal(t, "boolean", result["bool-key"].Type)

		assert.Equal(t, int64(42), result["int-key"].Value)
		assert.Equal(t, "integer", result["int-key"].Type)

		assert.Equal(t, 3.14, result["double-key"].Value)
		assert.Equal(t, "double", result["double-key"].Type)
	})

	t.Run("with no event name", func(t *testing.T) {
		logRecord := plog.NewLogRecord()
		logRecord.Attributes().PutStr("custom-key", "custom-value")

		result := generateSentryAttributesFromLogRecord(logRecord, pcommon.NewResource(), pcommon.NewInstrumentationScope())

		_, hasEventName := result["event.name"]
		assert.False(t, hasEventName)
		assert.Equal(t, "custom-value", result["custom-key"].Value)
	})

	t.Run("with complex attribute types", func(t *testing.T) {
		logRecord := plog.NewLogRecord()

		// Add a slice attribute (should be converted to string)
		slice := logRecord.Attributes().PutEmpty("slice-key").SetEmptySlice()
		slice.AppendEmpty().SetStr("item1")
		slice.AppendEmpty().SetStr("item2")

		// Add a map attribute (should be converted to string)
		mapVal := logRecord.Attributes().PutEmpty("map-key").SetEmptyMap()
		mapVal.PutStr("nested-key", "nested-value")

		result := generateSentryAttributesFromLogRecord(logRecord, pcommon.NewResource(), pcommon.NewInstrumentationScope())

		// Complex types should be converted to string
		assert.Equal(t, "string", result["slice-key"].Type)
		assert.Equal(t, "string", result["map-key"].Type)
		assert.IsType(t, "", result["slice-key"].Value)
		assert.IsType(t, "", result["map-key"].Value)
	})

	t.Run("with empty log record", func(t *testing.T) {
		logRecord := plog.NewLogRecord()
		result := generateSentryAttributesFromLogRecord(logRecord, pcommon.NewResource(), pcommon.NewInstrumentationScope())
		assert.Empty(t, result)
	})
}

func TestGetLogMessageFromLogRecord(t *testing.T) {
	t.Run("with event name", func(t *testing.T) {
		logRecord := plog.NewLogRecord()
		logRecord.SetEventName("test.event")
		logRecord.Body().SetStr("log body")

		result := getLogMessageFromLogRecord(logRecord)
		assert.Equal(t, "test.event", result)
	})

	t.Run("with body only", func(t *testing.T) {
		logRecord := plog.NewLogRecord()
		logRecord.Body().SetStr("log body")

		result := getLogMessageFromLogRecord(logRecord)
		assert.Equal(t, "log body", result)
	})

	t.Run("with empty fields", func(t *testing.T) {
		logRecord := plog.NewLogRecord()

		result := getLogMessageFromLogRecord(logRecord)
		assert.Equal(t, "", result)
	})
}

// Integration test to verify the complete flow
func TestSentryLogsExporterIntegration(t *testing.T) {
	mockTransport := &mockLogsTransport{}
	exporter := &SentryLogsExporter{
		transport:   mockTransport,
		environment: "integration-test",
	}

	// Create test data with various log levels and attributes
	logs := plog.NewLogs()
	rl := logs.ResourceLogs().AppendEmpty()
	sl := rl.ScopeLogs().AppendEmpty()

	// Info log
	infoLog := sl.LogRecords().AppendEmpty()
	infoLog.Body().SetStr("Info message")
	infoLog.SetSeverityNumber(plog.SeverityNumberInfo)
	infoLog.SetTimestamp(pcommon.Timestamp(time.Now().UnixNano()))
	infoLog.Attributes().PutStr("level", "info")

	// Error log with trace context
	errorLog := sl.LogRecords().AppendEmpty()
	errorLog.Body().SetStr("Error message")
	errorLog.SetSeverityNumber(plog.SeverityNumberError)
	errorLog.SetTimestamp(pcommon.Timestamp(time.Now().UnixNano()))
	errorLog.SetTraceID(pcommon.TraceID([16]byte{1, 2, 3, 4, 5, 6, 7, 8, 8, 7, 6, 5, 4, 3, 2, 1}))
	errorLog.Attributes().PutStr("level", "error")
	errorLog.Attributes().PutStr("error.type", "RuntimeError")

	// Push the logs
	err := exporter.pushLogsData(context.Background(), logs)
	assert.NoError(t, err)
	assert.True(t, mockTransport.called)
	assert.Len(t, mockTransport.events, 1)

	// Verify the event structure
	event := mockTransport.events[0]
	assert.Equal(t, "log", event.Type)
	assert.Len(t, event.Logs, 2)

	// Verify info log
	infoSentryLog := event.Logs[0]
	assert.Equal(t, "Info message", infoSentryLog.Body)
	assert.Equal(t, sentry.LogLevelInfo, infoSentryLog.Level)
	assert.Equal(t, "integration-test", infoSentryLog.Attributes["sentry.environment"].Value)

	// Verify error log
	errorSentryLog := event.Logs[1]
	assert.Equal(t, "Error message", errorSentryLog.Body)
	assert.Equal(t, sentry.LogLevelError, errorSentryLog.Level)
	assert.NotEqual(t, sentry.TraceID{}, errorSentryLog.TraceID)
	assert.Equal(t, "RuntimeError", errorSentryLog.Attributes["error.type"].Value)
}
