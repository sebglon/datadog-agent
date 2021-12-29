// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build containerd
// +build containerd

package containerd

import (
	"context"

	"github.com/DataDog/datadog-agent/pkg/config"
)

// NamespacesToWatch returns the namespaces to watch. If the
// "containerd_namespace" option has been set, it returns that namespace.
// Otherwise, it returns all of them.
func NamespacesToWatch(containerdClient ContainerdItf) ([]string, error) {
	return NamespacesToWatchWithContext(context.Background(), containerdClient)
}

func NamespacesToWatchWithContext(ctx context.Context, containerdClient ContainerdItf) ([]string, error) {
	if namespace := config.Datadog.GetString("containerd_namespace"); namespace != "" {
		return []string{namespace}, nil
	}

	return containerdClient.Namespaces(ctx)
}
