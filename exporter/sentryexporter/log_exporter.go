// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package sentryexporter // import "github.com/open-telemetry/opentelemetry-collector-contrib/exporter/sentryexporter"

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"github.com/getsentry/sentry-go"
	"go.opentelemetry.io/collector/exporter"
	"go.opentelemetry.io/collector/exporter/exporterhelper"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
)

const (
	otelSentryLogsExporterVersion = "0.1.0"
	otelSentryLogsExporterName    = "sentry.opentelemetry.logs"
)

// SentryLogsExporter is the logs exporter for Sentry.
type SentryLogsExporter struct {
	transport   transport
	environment string
}

// createSentryLogsExporterInternal creates a new Sentry logs exporter.
func newSentryLogsExporter(config *Config, set exporter.Settings) (exporter.Logs, error) {
	if !config.EnableLogs {
		return nil, nil
	}

	transport := newSentryTransport()

	clientOptions := sentry.ClientOptions{
		Dsn:         config.DSN,
		Environment: config.Environment,
	}

	if config.InsecureSkipVerify {
		clientOptions.HTTPTransport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	}

	transport.Configure(clientOptions)

	s := &SentryLogsExporter{
		transport:   transport,
		environment: config.Environment,
	}

	return exporterhelper.NewLogs(
		context.TODO(),
		set,
		config,
		s.pushLogsData,
		exporterhelper.WithShutdown(func(ctx context.Context) error {
			allEventsFlushed := transport.Flush(ctx)

			if !allEventsFlushed {
				set.Logger.Warn("Could not flush all events, reached timeout")
			}

			return nil
		}),
	)
}

// pushLogsData pushes logs to Sentry.
func (s *SentryLogsExporter) pushLogsData(_ context.Context, ld plog.Logs) error {
	event := sentry.NewEvent()
	event.Timestamp = time.Now()
	event.Type = "log"
	event.Logs = s.otelLogsToSentryLogs(ld)

	s.transport.SendEvent(event)

	return nil
}

func (s *SentryLogsExporter) otelLogsToSentryLogs(ld plog.Logs) []sentry.Log {
	logs := make([]sentry.Log, 0)

	resourceLogs := ld.ResourceLogs()
	if resourceLogs.Len() == 0 {
		return nil
	}

	for i := 0; i < resourceLogs.Len(); i++ {
		resourceLog := resourceLogs.At(i)
		scopeLogs := resourceLog.ScopeLogs()
		resource := resourceLog.Resource()
		for j := 0; j < scopeLogs.Len(); j++ {
			scopeLog := scopeLogs.At(j)
			scope := scopeLog.Scope()
			logRecords := scopeLog.LogRecords()
			for k := 0; k < logRecords.Len(); k++ {
				logRecord := logRecords.At(k)
				logs = append(logs, s.convertToSentryLog(logRecord, resource, scope))
			}
		}
	}

	return logs
}

func (s *SentryLogsExporter) convertToSentryLog(logRecord plog.LogRecord, resource pcommon.Resource, scope pcommon.InstrumentationScope) sentry.Log {
	attributes := generateSentryAttributesFromLogRecord(logRecord, resource, scope)

	// https://develop.sentry.dev/sdk/telemetry/logs/#default-attributes
	attributes["sentry.environment"] = sentry.Attribute{
		Value: s.environment,
		Type:  "string",
	}

	attributes["sentry.sdk.name"] = sentry.Attribute{
		Value: otelSentryLogsExporterName,
		Type:  "string",
	}

	attributes["sentry.sdk.version"] = sentry.Attribute{
		Value: otelSentryLogsExporterVersion,
		Type:  "string",
	}

	var actualTraceId pcommon.TraceID
	logRecordTraceId := logRecord.TraceID()
	if !logRecordTraceId.IsEmpty() {
		actualTraceId = logRecordTraceId
	} else {
		// Generate a new random trace ID when none exists
		var r [16]byte
		_, err := rand.Read(r[:])
		if err != nil {
			// Fallback to empty trace ID if random generation fails
			actualTraceId = pcommon.NewTraceIDEmpty()
		} else {
			actualTraceId = pcommon.TraceID(r)
		}
	}

	log := sentry.Log{
		Timestamp:  time.Unix(0, int64(logRecord.Timestamp())),
		TraceID:    sentry.TraceID(actualTraceId),
		Level:      logRecordSeverityTextToSentryLogLevel(logRecord.SeverityNumber(), logRecord.SeverityText()),
		Severity:   int(logRecord.SeverityNumber()),
		Body:       getLogMessageFromLogRecord(logRecord),
		Attributes: attributes,
	}

	return log
}

// logRecordSeverityTextToSentryLogLevel converts the severity text to a Sentry log level.
// TODO: Switch to using the sentry.LogLevel type once it is supported.
func logRecordSeverityTextToSentryLogLevel(severityNumber plog.SeverityNumber, severityText string) sentry.Level {
	if severityNumber >= 1 && severityNumber <= 4 {
		return sentry.LogLevelTrace
	} else if severityNumber >= 5 && severityNumber <= 8 {
		return sentry.LogLevelDebug
	} else if severityNumber >= 9 && severityNumber <= 12 {
		return sentry.LogLevelInfo
	} else if severityNumber >= 13 && severityNumber <= 16 {
		return sentry.LogLevelWarn
	} else if severityNumber >= 17 && severityNumber <= 20 {
		return sentry.LogLevelError
	} else if severityNumber >= 21 && severityNumber <= 24 {
		return sentry.LogLevelFatal
	}

	if severityText == "trace" {
		return sentry.LogLevelTrace
	} else if severityText == "debug" {
		return sentry.LogLevelDebug
	} else if severityText == "info" {
		return sentry.LogLevelInfo
	} else if severityText == "warn" {
		return sentry.LogLevelWarn
	} else if severityText == "error" {
		return sentry.LogLevelError
	} else if severityText == "fatal" {
		return sentry.LogLevelFatal
	}

	return sentry.LogLevelInfo
}

func getLogMessageFromLogRecord(logRecord plog.LogRecord) string {
	eventName := logRecord.EventName()

	if eventName != "" {
		return eventName
	}

	message := logRecord.Body().AsString()

	if message != "" {
		return message
	}

	return ""
}

func generateSentryAttributesFromLogRecord(logRecord plog.LogRecord, resource pcommon.Resource, scope pcommon.InstrumentationScope) map[string]sentry.Attribute {
	sentryAttributes := make(map[string]sentry.Attribute)

	scopeName := scope.Name()
	if scopeName != "" {
		sentryAttributes["otel.instrumentation_scope.name"] = sentry.Attribute{
			Value: scopeName,
			Type:  "string",
		}
	}

	scopeVersion := scope.Version()
	if scopeVersion != "" {
		sentryAttributes["otel.instrumentation_scope.version"] = sentry.Attribute{
			Value: scopeVersion,
			Type:  "string",
		}
	}

	resource.Attributes().Range(func(k string, v pcommon.Value) bool {
		keyAttribute := fmt.Sprintf("resource.%s", k)
		sentryAttributes[keyAttribute] = logRecordAttributeToSentryAttribute(v)
		return true
	})

	if logRecord.EventName() != "" {
		sentryAttributes["event.name"] = sentry.Attribute{
			Value: logRecord.EventName(),
			Type:  "string",
		}
	}

	logRecord.Attributes().Range(func(k string, v pcommon.Value) bool {
		sentryAttributes[k] = logRecordAttributeToSentryAttribute(v)
		return true
	})

	return sentryAttributes
}

func logRecordAttributeToSentryAttribute(value pcommon.Value) sentry.Attribute {
	attributeType := value.Type()

	if attributeType == pcommon.ValueTypeStr {
		return sentry.Attribute{
			Value: value.AsString(),
			Type:  "string",
		}
	}

	if attributeType == pcommon.ValueTypeBool {
		return sentry.Attribute{
			Value: value.Bool(),
			Type:  "boolean",
		}
	}

	if attributeType == pcommon.ValueTypeInt {
		return sentry.Attribute{
			Value: value.Int(),
			Type:  "integer",
		}
	}

	if attributeType == pcommon.ValueTypeDouble {
		return sentry.Attribute{
			Value: value.Double(),
			Type:  "double",
		}
	}

	// TODO: Add support for other types
	return sentry.Attribute{
		Value: value.AsString(),
		Type:  "string",
	}
}
