// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf
// +build linux_bpf

package kprobe

import (
	"os"

	"github.com/DataDog/datadog-agent/pkg/ebpf"
	"github.com/DataDog/datadog-agent/pkg/network/ebpf/probes"
	"github.com/DataDog/ebpf/manager"
)

const (
	// maxActive configures the maximum number of instances of the kretprobe-probed functions handled simultaneously.
	// This value should be enough for typical workloads (e.g. some amount of processes blocked on the `accept` syscall).
	maxActive = 128
)

func newManager(closedHandler *ebpf.PerfHandler, runtimeTracer bool) *manager.Manager {
	mgr := &manager.Manager{
		Maps: []*manager.Map{
			{Name: string(probes.ConnMap)},
			{Name: string(probes.TcpStatsMap)},
			{Name: string(probes.ConnCloseBatchMap)},
			{Name: "udp_recv_sock"},
			{Name: string(probes.PortBindingsMap)},
			{Name: string(probes.UdpPortBindingsMap)},
			{Name: "pending_bind"},
			{Name: string(probes.TelemetryMap)},
			{Name: string(probes.SockByPidFDMap)},
			{Name: string(probes.PidFDBySockMap)},
			{Name: string(probes.SockFDLookupArgsMap)},
			{Name: string(probes.DoSendfileArgsMap)},
		},
		PerfMaps: []*manager.PerfMap{
			{
				Map: manager.Map{Name: string(probes.ConnCloseEventMap)},
				PerfMapOptions: manager.PerfMapOptions{
					PerfRingBufferSize: 8 * os.Getpagesize(),
					Watermark:          1,
					DataHandler:        closedHandler.DataHandler,
					LostHandler:        closedHandler.LostHandler,
				},
			},
		},
		Probes: []*manager.Probe{
			{Section: string(probes.TCPSendMsg)},
			{Section: string(probes.TCPCleanupRBuf)},
			{Section: string(probes.TCPClose)},
			{Section: string(probes.TCPCloseReturn), KProbeMaxActive: maxActive},
			{Section: string(probes.TCPSetState)},
			{Section: string(probes.IPMakeSkb)},
			{Section: string(probes.IP6MakeSkb)},
			{Section: string(probes.UDPRecvMsg)},
			{Section: string(probes.UDPRecvMsgReturn), KProbeMaxActive: maxActive},
			{Section: string(probes.TCPRetransmit)},
			{Section: string(probes.InetCskAcceptReturn), KProbeMaxActive: maxActive},
			{Section: string(probes.InetCskListenStop)},
			{Section: string(probes.UDPDestroySock)},
			{Section: string(probes.UDPDestroySockReturn), KProbeMaxActive: maxActive},
			{Section: string(probes.InetBind)},
			{Section: string(probes.Inet6Bind)},
			{Section: string(probes.InetBindRet), KProbeMaxActive: maxActive},
			{Section: string(probes.Inet6BindRet), KProbeMaxActive: maxActive},
			{Section: string(probes.IPRouteOutputFlow)},
			{Section: string(probes.IPRouteOutputFlowReturn), KProbeMaxActive: maxActive},
			{Section: string(probes.SockFDLookup)},
			{Section: string(probes.SockFDLookupRet), KProbeMaxActive: maxActive},
			{Section: string(probes.DoSendfile)},
			{Section: string(probes.DoSendfileRet), KProbeMaxActive: maxActive},
		},
	}

	// the runtime compiled tracer has no need for separate probes targeting specific kernel versions, since it can
	// do that with #ifdefs inline. Thus, the following probes should only be declared as existing in the prebuilt
	// tracer.
	if !runtimeTracer {
		mgr.Probes = append(mgr.Probes,
			&manager.Probe{Section: string(probes.TCPRetransmitPre470), MatchFuncName: "^tcp_retransmit_skb$"},
			&manager.Probe{Section: string(probes.IP6MakeSkbPre470), MatchFuncName: "^ip6_make_skb$"},
			&manager.Probe{Section: string(probes.UDPRecvMsgPre410), MatchFuncName: "^udp_recvmsg$"},
			&manager.Probe{Section: string(probes.TCPSendMsgPre410), MatchFuncName: "^tcp_sendmsg$"},
		)
	}

	return mgr
}
