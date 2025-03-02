// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

/*
Package api implements the agent IPC api. Using HTTP
calls, it's possible to communicate with the agent,
sending commands and receiving infos.
*/
package api

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	stdLog "log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"

	"github.com/DataDog/datadog-agent/cmd/cluster-agent/api/agent"
	v1 "github.com/DataDog/datadog-agent/cmd/cluster-agent/api/v1"
	"github.com/DataDog/datadog-agent/pkg/api/security"
	"github.com/DataDog/datadog-agent/pkg/api/util"
	"github.com/DataDog/datadog-agent/pkg/config"
)

var (
	listener  net.Listener
	router    *mux.Router
	apiRouter *mux.Router
)

// StartServer creates the router and starts the HTTP server
func StartServer() error {
	// create the root HTTP router
	router = mux.NewRouter()
	apiRouter = router.PathPrefix("/api/v1").Subrouter()

	// IPC REST API server
	agent.SetupHandlers(router)

	// API V1 Metadata APIs
	v1.InstallMetadataEndpoints(apiRouter)

	// Validate token for every request
	router.Use(validateToken)

	// get the transport we're going to use under HTTP
	var err error
	listener, err = getListener()
	if err != nil {
		// we use the listener to handle commands for the agent, there's
		// no way we can recover from this error
		return fmt.Errorf("unable to create the api server: %v", err)
	}
	// Internal token
	util.CreateAndSetAuthToken() //nolint:errcheck

	// DCA client token
	util.InitDCAAuthToken() //nolint:errcheck

	// create cert
	hosts := []string{"127.0.0.1", "localhost"}
	_, rootCertPEM, rootKey, err := security.GenerateRootCert(hosts, 2048)
	if err != nil {
		return fmt.Errorf("unable to start TLS server")
	}

	// PEM encode the private key
	rootKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rootKey),
	})

	// Create a TLS cert using the private key and certificate
	rootTLSCert, err := tls.X509KeyPair(rootCertPEM, rootKeyPEM)
	if err != nil {
		return fmt.Errorf("invalid key pair: %v", err)
	}

	tlsConfig := tls.Config{
		Certificates: []tls.Certificate{rootTLSCert},
	}

	if config.Datadog.GetBool("force_tls_12") {
		tlsConfig.MinVersion = tls.VersionTLS12
	}

	srv := &http.Server{
		Handler: router,
		ErrorLog: stdLog.New(&config.ErrorLogWriter{
			AdditionalDepth: 4, // Use a stack depth of 4 on top of the default one to get a relevant filename in the stdlib
		}, "Error from the agent http API server: ", 0), // log errors to seelog,
		TLSConfig:    &tlsConfig,
		ReadTimeout:  config.Datadog.GetDuration("cluster_agent.server.read_timeout_seconds") * time.Second,
		WriteTimeout: config.Datadog.GetDuration("cluster_agent.server.write_timeout_seconds") * time.Second,
		IdleTimeout:  config.Datadog.GetDuration("cluster_agent.server.idle_timeout_seconds") * time.Second,
	}

	tlsListener := tls.NewListener(listener, &tlsConfig)

	go srv.Serve(tlsListener) //nolint:errcheck
	return nil
}

// ModifyAPIRouter allows to pass in a function to modify router used in server
func ModifyAPIRouter(f func(*mux.Router)) {
	f(apiRouter)
}

// StopServer closes the connection and the server
// stops listening to new commands.
func StopServer() {
	if listener != nil {
		listener.Close()
	}
}

// We only want to maintain 1 API and expose an external route to serve the cluster level metadata.
// As we have 2 different tokens for the validation, we need to validate accordingly.
func validateToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.String()
		var isValid bool
		if !isExternalPath(path) {
			if err := util.Validate(w, r); err == nil {
				isValid = true
			}
		}
		if !isValid {
			if err := util.ValidateDCARequest(w, r); err != nil {
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// isExternal returns whether the path is an endpoint used by Node Agents.
func isExternalPath(path string) bool {
	return strings.HasPrefix(path, "/api/v1/metadata/") && len(strings.Split(path, "/")) == 7 || // support for agents < 6.5.0
		path == "/version" ||
		strings.HasPrefix(path, "/api/v1/tags/pod/") && (len(strings.Split(path, "/")) == 6 || len(strings.Split(path, "/")) == 8) ||
		strings.HasPrefix(path, "/api/v1/tags/node/") && len(strings.Split(path, "/")) == 6 ||
		strings.HasPrefix(path, "/api/v1/tags/namespace/") && len(strings.Split(path, "/")) == 6 ||
		strings.HasPrefix(path, "/api/v1/annotations/node/") && len(strings.Split(path, "/")) == 6 ||
		strings.HasPrefix(path, "/api/v1/clusterchecks/") && len(strings.Split(path, "/")) == 6 ||
		strings.HasPrefix(path, "/api/v1/endpointschecks/") && len(strings.Split(path, "/")) == 6 ||
		strings.HasPrefix(path, "/api/v1/tags/cf/apps/") && len(strings.Split(path, "/")) == 7 ||
		strings.HasPrefix(path, "/api/v1/cluster/id") && len(strings.Split(path, "/")) == 5
}
