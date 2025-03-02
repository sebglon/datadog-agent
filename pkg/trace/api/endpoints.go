// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package api

import (
	"net/http"

	"github.com/DataDog/datadog-agent/pkg/trace/config"
	"github.com/DataDog/datadog-agent/pkg/trace/config/features"
)

// endpoint specifies an API endpoint definition.
type endpoint struct {
	// Pattern specifies the API pattern, as registered by the HTTP handler.
	Pattern string

	// Handler specifies the http.Handler for this endpoint.
	Handler func(*HTTPReceiver) http.Handler

	// Hidden reports whether this endpoint should be hidden in the /info
	// discovery endpoint.
	Hidden bool

	// IsEnabled specifies a function which reports whether this endpoint should be enabled
	// based on the given config conf.
	IsEnabled func(conf *config.AgentConfig) bool
}

// endpoints specifies the list of endpoints registered for the trace-agent API.
var endpoints = []endpoint{
	{
		Pattern: "/spans",
		Handler: func(r *HTTPReceiver) http.Handler { return r.handleWithVersion(v01, r.handleTraces) },
		Hidden:  true,
	},
	{
		Pattern: "/services",
		Handler: func(r *HTTPReceiver) http.Handler { return r.handleWithVersion(v01, r.handleServices) },
		Hidden:  true,
	},
	{
		Pattern: "/v0.1/spans",
		Handler: func(r *HTTPReceiver) http.Handler { return r.handleWithVersion(v01, r.handleTraces) },
		Hidden:  true,
	},
	{
		Pattern: "/v0.1/services",
		Handler: func(r *HTTPReceiver) http.Handler { return r.handleWithVersion(v01, r.handleServices) },
		Hidden:  true,
	},
	{
		Pattern: "/v0.2/traces",
		Handler: func(r *HTTPReceiver) http.Handler { return r.handleWithVersion(v02, r.handleTraces) },
		Hidden:  true,
	},
	{
		Pattern: "/v0.2/services",
		Handler: func(r *HTTPReceiver) http.Handler { return r.handleWithVersion(v02, r.handleServices) },
		Hidden:  true,
	},
	{
		Pattern: "/v0.3/traces",
		Handler: func(r *HTTPReceiver) http.Handler { return r.handleWithVersion(v03, r.handleTraces) },
	},
	{
		Pattern: "/v0.3/services",
		Handler: func(r *HTTPReceiver) http.Handler { return r.handleWithVersion(v03, r.handleServices) },
	},
	{
		Pattern: "/v0.4/traces",
		Handler: func(r *HTTPReceiver) http.Handler { return r.handleWithVersion(v04, r.handleTraces) },
	},
	{
		Pattern: "/v0.4/services",
		Handler: func(r *HTTPReceiver) http.Handler { return r.handleWithVersion(v04, r.handleServices) },
	},
	{
		Pattern: "/v0.5/traces",
		Handler: func(r *HTTPReceiver) http.Handler { return r.handleWithVersion(v05, r.handleTraces) },
	},
	{
		Pattern: "/v0.7/traces",
		Handler: func(r *HTTPReceiver) http.Handler { return r.handleWithVersion(v07, r.handleTraces) },
	},
	{
		Pattern: "/profiling/v1/input",
		Handler: func(r *HTTPReceiver) http.Handler { return r.profileProxyHandler() },
	},
	{
		Pattern: "/telemetry/proxy/",
		Handler: func(r *HTTPReceiver) http.Handler {
			return http.StripPrefix("/telemetry/proxy", r.telemetryProxyHandler())
		},
		IsEnabled: func(cfg *config.AgentConfig) bool { return cfg.TelemetryConfig.Enabled },
	},
	{
		Pattern: "/v0.6/stats",
		Handler: func(r *HTTPReceiver) http.Handler { return http.HandlerFunc(r.handleStats) },
	},
	{
		Pattern: "/v0.1/pipeline_stats",
		Handler: func(r *HTTPReceiver) http.Handler { return r.pipelineStatsProxyHandler() },
	},
	{
		Pattern: "/appsec/proxy/",
		Handler: func(r *HTTPReceiver) http.Handler { return http.StripPrefix("/appsec/proxy", r.appsecHandler) },
	},
	{
		Pattern: "/debugger/v1/input",
		Handler: func(r *HTTPReceiver) http.Handler { return r.debuggerProxyHandler() },
	},
	{
		Pattern:   "/v0.6/config",
		Handler:   func(r *HTTPReceiver) http.Handler { return http.HandlerFunc(r.handleConfig) },
		IsEnabled: func(_ *config.AgentConfig) bool { return features.Has("config_endpoint") },
	},
}
