// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package sentryexporter // import "github.com/open-telemetry/opentelemetry-collector-contrib/exporter/sentryexporter"

import (
	"context"
	"time"

	"github.com/getsentry/sentry-go"
)

// transport is used by exporter to send events to Sentry
type transport interface {
	SendEvent(event *sentry.Event)
	SendTransactionEvents(transactionEvents []*sentry.Event)
	Configure(options sentry.ClientOptions)
	Flush(ctx context.Context) bool
}

type sentryTransport struct {
	httpTransport *sentry.HTTPTransport
}

// newSentryTransport returns a new pre-configured instance of sentryTransport.
func newSentryTransport() *sentryTransport {
	transport := sentryTransport{
		httpTransport: sentry.NewHTTPTransport(),
	}
	return &transport
}

func (t *sentryTransport) Configure(options sentry.ClientOptions) {
	t.httpTransport.Configure(options)
}

func (t *sentryTransport) Flush(ctx context.Context) bool {
	deadline, ok := ctx.Deadline()
	if ok {
		return t.httpTransport.Flush(time.Until(deadline))
	}
	return t.httpTransport.Flush(time.Second)
}

// SendEvent uses a Sentry HTTPTransport to send an event to Sentry
func (t *sentryTransport) SendEvent(event *sentry.Event) {
	t.httpTransport.SendEvent(event)
}

// SendEvents uses a Sentry HTTPTransport to send transaction events to Sentry
func (t *sentryTransport) SendTransactionEvents(transactions []*sentry.Event) {
	bufferCounter := 0
	for _, transaction := range transactions {
		// We should flush all events when we send transactions equal to the transport
		// buffer size so we don't drop transactions.
		if bufferCounter == t.httpTransport.BufferSize {
			t.httpTransport.Flush(time.Second)
			bufferCounter = 0
		}

		t.httpTransport.SendEvent(transaction)
		bufferCounter++
	}
}
