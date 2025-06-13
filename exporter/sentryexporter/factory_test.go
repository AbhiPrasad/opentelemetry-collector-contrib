// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package sentryexporter

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/exporter/exportertest"

	"github.com/open-telemetry/opentelemetry-collector-contrib/exporter/sentryexporter/internal/metadata"
)

func TestCreateDefaultConfig(t *testing.T) {
	factory := NewFactory()
	cfg := factory.CreateDefaultConfig()
	assert.NotNil(t, cfg, "failed to create default config")
	assert.NoError(t, componenttest.CheckConfigStruct(cfg))
}

func TestCreateExporter(t *testing.T) {
	factory := NewFactory()
	assert.Equal(t, metadata.Type, factory.Type())

	cfg := factory.CreateDefaultConfig()
	eCfg := cfg.(*Config)
	params := exportertest.NewNopSettings(metadata.Type)

	// Test traces exporter creation
	te, err := factory.CreateTraces(context.Background(), params, eCfg)
	assert.NoError(t, err)
	assert.NotNil(t, te, "failed to create trace exporter")

	// Test logs exporter creation
	le, err := factory.CreateLogs(context.Background(), params, eCfg)
	assert.NoError(t, err)
	assert.NotNil(t, le, "failed to create logs exporter")

	// Test metrics exporter creation (should fail since not supported)
	me, err := factory.CreateMetrics(context.Background(), params, eCfg)
	assert.Error(t, err)
	assert.Nil(t, me)
}

func TestCreateTracesExporter(t *testing.T) {
	factory := NewFactory()
	cfg := factory.CreateDefaultConfig()
	eCfg := cfg.(*Config)
	params := exportertest.NewNopSettings(metadata.Type)

	t.Run("with valid config", func(t *testing.T) {
		eCfg.DSN = "https://key@sentry.io/123"
		te, err := factory.CreateTraces(context.Background(), params, eCfg)
		assert.NoError(t, err)
		assert.NotNil(t, te)
	})

	t.Run("with invalid config type", func(t *testing.T) {
		te, err := createTracesExporter(context.Background(), params, &struct{}{})
		assert.Error(t, err)
		assert.Nil(t, te)
		assert.Contains(t, err.Error(), "unexpected config type")
	})
}

func TestCreateLogsExporter(t *testing.T) {
	factory := NewFactory()
	cfg := factory.CreateDefaultConfig()
	eCfg := cfg.(*Config)
	params := exportertest.NewNopSettings(metadata.Type)

	t.Run("with valid config", func(t *testing.T) {
		eCfg.DSN = "https://key@sentry.io/123"
		le, err := factory.CreateLogs(context.Background(), params, eCfg)
		assert.NoError(t, err)
		assert.NotNil(t, le)
	})

	t.Run("with invalid config type", func(t *testing.T) {
		le, err := createSentryLogsExporter(context.Background(), params, &struct{}{})
		assert.Error(t, err)
		assert.Nil(t, le)
		assert.Contains(t, err.Error(), "unexpected config type")
	})
}
