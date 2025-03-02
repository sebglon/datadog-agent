// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package checks

import (
	"context"
	"sync"
	"time"

	model "github.com/DataDog/agent-payload/v5/process"
	"github.com/DataDog/datadog-agent/pkg/process/config"
	"github.com/DataDog/datadog-agent/pkg/process/statsd"
	"github.com/DataDog/datadog-agent/pkg/process/util"
	"github.com/DataDog/datadog-agent/pkg/tagger"
	"github.com/DataDog/datadog-agent/pkg/tagger/collectors"
	"github.com/DataDog/datadog-agent/pkg/util/cloudproviders"
	"github.com/DataDog/datadog-agent/pkg/util/containers"
	containercollectors "github.com/DataDog/datadog-agent/pkg/util/containers/collectors"
	"github.com/DataDog/datadog-agent/pkg/util/containers/metrics"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/DataDog/datadog-agent/pkg/util/system"
)

// Container is a singleton ContainerCheck.
var Container = &ContainerCheck{}

// ContainerCheck is a check that returns container metadata and stats.
type ContainerCheck struct {
	sync.Mutex

	sysInfo         *model.SystemInfo
	lastRates       map[string]util.ContainerRateMetrics
	lastRun         time.Time
	lastCtrIDForPID map[int32]string
	networkID       string

	containerFailedLogLimit *util.LogLimit
}

// Init initializes a ContainerCheck instance.
func (c *ContainerCheck) Init(cfg *config.AgentConfig, info *model.SystemInfo) {
	c.sysInfo = info

	networkID, err := cloudproviders.GetNetworkID(context.TODO())
	if err != nil {
		log.Infof("no network ID detected: %s", err)
	}
	c.networkID = networkID

	c.containerFailedLogLimit = util.NewLogLimit(10, time.Minute*10)
}

// Name returns the name of the ProcessCheck.
func (c *ContainerCheck) Name() string { return config.ContainerCheckName }

// RealTime indicates if this check only runs in real-time mode.
func (c *ContainerCheck) RealTime() bool { return false }

// Run runs the ContainerCheck to collect a list of running ctrList and the
// stats for each container.
func (c *ContainerCheck) Run(cfg *config.AgentConfig, groupID int32) ([]model.MessageBody, error) {
	c.Lock()
	defer c.Unlock()

	start := time.Now()
	ctrList, err := util.GetContainers()
	// We ignore certain errors when a container runtime environment isn't available.
	if err == containercollectors.ErrPermaFail || err == containercollectors.ErrNothingYet {
		if c.containerFailedLogLimit.ShouldLog() {
			log.Debug("container collector was not detected, container check will not return any data. This message will logged for the first ten occurrences, and then every ten minutes")
		}
		return nil, nil
	}

	if err != nil {
		return nil, err
	}

	if len(ctrList) == 0 {
		log.Trace("no containers found")
		return nil, nil
	}

	// Keep track of containers addresses
	LocalResolver.LoadAddrs(ctrList)

	// End check early if this is our first run.
	if c.lastRates == nil {
		c.lastRates = util.ExtractContainerRateMetric(ctrList)
		c.lastRun = time.Now()
		c.lastCtrIDForPID = ctrIDForPID(ctrList)
		return nil, nil
	}

	groupSize := len(ctrList) / cfg.MaxPerMessage
	if len(ctrList)%cfg.MaxPerMessage != 0 {
		groupSize++
	}
	chunked := chunkContainers(ctrList, c.lastRates, c.lastRun, groupSize, cfg.MaxPerMessage)
	messages := make([]model.MessageBody, 0, groupSize)
	totalContainers := float64(0)
	for i := 0; i < groupSize; i++ {
		totalContainers += float64(len(chunked[i]))
		messages = append(messages, &model.CollectorContainer{
			HostName:          cfg.HostName,
			NetworkId:         c.networkID,
			Info:              c.sysInfo,
			Containers:        chunked[i],
			GroupId:           groupID,
			GroupSize:         int32(groupSize),
			ContainerHostType: cfg.ContainerHostType,
		})
	}

	c.lastRates = util.ExtractContainerRateMetric(ctrList)
	c.lastRun = time.Now()
	c.lastCtrIDForPID = ctrIDForPID(ctrList)

	statsd.Client.Gauge("datadog.process.containers.host_count", totalContainers, []string{}, 1) //nolint:errcheck
	log.Debugf("collected %d containers in %s", int(totalContainers), time.Now().Sub(start))
	return messages, nil
}

// fmtContainers loops through container list and converts them to a list of container objects
func fmtContainers(ctrList []*containers.Container, lastRates map[string]util.ContainerRateMetrics, lastRun time.Time) []*model.Container {
	containersList := make([]*model.Container, 0, len(ctrList))
	for _, ctr := range ctrList {
		lastCtr, ok := lastRates[ctr.ID]
		if !ok {
			// Set to an empty container so rate calculations work and use defaults.
			lastCtr = util.NullContainerRates
		}

		// Just in case the container is found, but refs are nil.
		// Note some CPU values are set to -1, to be skipped on the backend, because they are reported cumulatively
		ctr = fillNilContainer(ctr)
		lastCtr = fillNilRates(lastCtr)

		// Retrieves metadata tags
		tags, err := tagger.Tag(ctr.EntityID, collectors.HighCardinality)
		if err != nil {
			log.Errorf("unable to retrieve tags for container: %s", err)
			tags = []string{}
		}

		if ctr.Type == containers.RuntimeNameGarden && len(tags) == 0 {
			// If there is an error retrieving tags, don't send the container for garden. It means it hasn't yet been
			// discovered by the cluster agent, so avoid sending something with no tags, i.e. no container name, ...
			log.Debugf("No tags found for app %s, it has probably not been discovered by the DCA, skipping.", ctr.ID)
			continue
		}

		ifStats := ctr.Network.SumInterfaces()
		cpus := system.HostCPUCount()
		sys2, sys1 := ctr.CPU.SystemUsage, lastCtr.CPU.SystemUsage

		userPct := calculateCtrPct(ctr.CPU.User, lastCtr.CPU.User, sys2, sys1, cpus, lastRun)
		systemPct := calculateCtrPct(ctr.CPU.System, lastCtr.CPU.System, sys2, sys1, cpus, lastRun)
		var totalPct float32
		if userPct == -1 || systemPct == -1 {
			totalPct = -1
		} else {
			totalPct = calculateCtrPct(ctr.CPU.User+ctr.CPU.System, lastCtr.CPU.User+lastCtr.CPU.System, sys2, sys1, cpus, lastRun)
		}

		containersList = append(containersList, &model.Container{
			Id:          ctr.ID,
			Type:        ctr.Type,
			CpuLimit:    float32(ctr.Limits.CPULimit),
			UserPct:     userPct,
			SystemPct:   systemPct,
			TotalPct:    totalPct,
			MemoryLimit: ctr.Limits.MemLimit,
			MemRss:      ctr.Memory.RSS,
			MemCache:    ctr.Memory.Cache,
			Created:     ctr.Created,
			State:       model.ContainerState(model.ContainerState_value[ctr.State]),
			Health:      model.ContainerHealth(model.ContainerHealth_value[ctr.Health]),
			Rbps:        calculateRate(ctr.IO.ReadBytes, lastCtr.IO.ReadBytes, lastRun),
			Wbps:        calculateRate(ctr.IO.WriteBytes, lastCtr.IO.WriteBytes, lastRun),
			NetRcvdPs:   calculateRate(ifStats.PacketsRcvd, lastCtr.NetworkSum.PacketsRcvd, lastRun),
			NetSentPs:   calculateRate(ifStats.PacketsSent, lastCtr.NetworkSum.PacketsSent, lastRun),
			NetRcvdBps:  calculateRate(ifStats.BytesRcvd, lastCtr.NetworkSum.BytesRcvd, lastRun),
			NetSentBps:  calculateRate(ifStats.BytesSent, lastCtr.NetworkSum.BytesSent, lastRun),
			ThreadCount: ctr.CPU.ThreadCount,
			ThreadLimit: ctr.Limits.ThreadLimit,
			Addresses:   convertAddressList(ctr),
			Started:     ctr.StartedAt,
			Tags:        tags,
		})
	}
	return containersList
}

// chunkContainers formats and chunks the ctrList into a slice of chunks using a specific number of chunks.
func chunkContainers(ctrList []*containers.Container, lastRates map[string]util.ContainerRateMetrics, lastRun time.Time, chunks, perChunk int) [][]*model.Container {
	chunked := make([][]*model.Container, 0, chunks)
	chunk := make([]*model.Container, 0, perChunk)

	containers := fmtContainers(ctrList, lastRates, lastRun)

	for _, ctr := range containers {
		chunk = append(chunk, ctr)
		if len(chunk) == perChunk {
			chunked = append(chunked, chunk)
			chunk = make([]*model.Container, 0, perChunk)
		}
	}
	if len(chunk) > 0 {
		chunked = append(chunked, chunk)
	}
	return chunked
}

// convertAddressList converts AddressList into process-agent ContainerNetworkAddress objects
func convertAddressList(ctr *containers.Container) []*model.ContainerAddr {
	addrs := make([]*model.ContainerAddr, 0, len(ctr.AddressList))
	for _, a := range ctr.AddressList {
		protocol := model.ConnectionType_tcp
		if a.Protocol == "udp" {
			protocol = model.ConnectionType_udp
		}
		addrs = append(addrs, &model.ContainerAddr{
			Ip:       a.IP.String(),
			Port:     int32(a.Port),
			Protocol: protocol,
		})
	}
	return addrs
}

func fillNilContainer(ctr *containers.Container) *containers.Container {
	if ctr.CPU == nil {
		ctr.CPU = util.NullContainerRates.CPU
	}
	if ctr.IO == nil {
		ctr.IO = util.NullContainerRates.IO
	}
	if ctr.Network == nil {
		ctr.Network = util.NullContainerRates.Network
	}
	if ctr.Memory == nil {
		ctr.Memory = &metrics.ContainerMemStats{}
	}
	return ctr
}

func fillNilRates(rates util.ContainerRateMetrics) util.ContainerRateMetrics {
	r := &rates
	if rates.CPU == nil {
		r.CPU = util.NullContainerRates.CPU
	}
	if rates.IO == nil {
		r.IO = util.NullContainerRates.IO
	}
	if rates.NetworkSum == nil {
		r.NetworkSum = util.NullContainerRates.NetworkSum
	}
	return *r
}
