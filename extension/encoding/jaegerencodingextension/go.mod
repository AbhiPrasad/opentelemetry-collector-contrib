module github.com/open-telemetry/opentelemetry-collector-contrib/extension/encoding/jaegerencodingextension

go 1.23.0

require (
	github.com/gogo/protobuf v1.3.2
	github.com/jaegertracing/jaeger-idl v0.5.0
	github.com/open-telemetry/opentelemetry-collector-contrib/extension/encoding v0.128.0
	github.com/open-telemetry/opentelemetry-collector-contrib/pkg/translator/jaeger v0.128.0
	github.com/stretchr/testify v1.10.0
	go.opentelemetry.io/collector/component v1.34.1-0.20250610090210-188191247685
	go.opentelemetry.io/collector/component/componenttest v0.128.1-0.20250610090210-188191247685
	go.opentelemetry.io/collector/confmap v1.34.1-0.20250610090210-188191247685
	go.opentelemetry.io/collector/extension v1.34.1-0.20250610090210-188191247685
	go.opentelemetry.io/collector/extension/extensiontest v0.128.1-0.20250610090210-188191247685
	go.opentelemetry.io/collector/pdata v1.34.1-0.20250610090210-188191247685
	go.uber.org/goleak v1.3.0
)

require (
	github.com/apache/thrift v0.21.0 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/go-logr/logr v1.4.2 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-viper/mapstructure/v2 v2.2.1 // indirect
	github.com/gobwas/glob v0.2.3 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/hashicorp/go-version v1.7.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/knadh/koanf/maps v0.1.2 // indirect
	github.com/knadh/koanf/providers/confmap v1.0.0 // indirect
	github.com/knadh/koanf/v2 v2.2.0 // indirect
	github.com/mitchellh/copystructure v1.2.0 // indirect
	github.com/mitchellh/reflectwalk v1.0.2 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/open-telemetry/opentelemetry-collector-contrib/internal/coreinternal v0.128.0 // indirect
	github.com/open-telemetry/opentelemetry-collector-contrib/pkg/core/xidutils v0.128.0 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	go.opentelemetry.io/auto/sdk v1.1.0 // indirect
	go.opentelemetry.io/collector/featuregate v1.34.1-0.20250610090210-188191247685 // indirect
	go.opentelemetry.io/collector/internal/telemetry v0.128.1-0.20250610090210-188191247685 // indirect
	go.opentelemetry.io/collector/pdata/pprofile v0.128.1-0.20250610090210-188191247685 // indirect
	go.opentelemetry.io/contrib/bridges/otelzap v0.11.0 // indirect
	go.opentelemetry.io/otel v1.36.0 // indirect
	go.opentelemetry.io/otel/log v0.12.2 // indirect
	go.opentelemetry.io/otel/metric v1.36.0 // indirect
	go.opentelemetry.io/otel/sdk v1.36.0 // indirect
	go.opentelemetry.io/otel/sdk/metric v1.36.0 // indirect
	go.opentelemetry.io/otel/trace v1.36.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.27.0 // indirect
	golang.org/x/net v0.39.0 // indirect
	golang.org/x/sys v0.33.0 // indirect
	golang.org/x/text v0.25.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250324211829-b45e905df463 // indirect
	google.golang.org/grpc v1.73.0 // indirect
	google.golang.org/protobuf v1.36.6 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	sigs.k8s.io/yaml v1.4.0 // indirect
)

replace github.com/open-telemetry/opentelemetry-collector-contrib/internal/coreinternal => ../../../internal/coreinternal

replace github.com/open-telemetry/opentelemetry-collector-contrib/pkg/core/xidutils => ../../../pkg/core/xidutils

replace github.com/open-telemetry/opentelemetry-collector-contrib/pkg/pdatautil => ../../../pkg/pdatautil

replace github.com/open-telemetry/opentelemetry-collector-contrib/pkg/pdatatest => ../../../pkg/pdatatest

replace github.com/open-telemetry/opentelemetry-collector-contrib/pkg/translator/jaeger => ../../../pkg/translator/jaeger

replace github.com/open-telemetry/opentelemetry-collector-contrib/pkg/golden => ../../../pkg/golden

replace github.com/open-telemetry/opentelemetry-collector-contrib/extension/encoding => ../
