// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package workloadmeta

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/imdario/mergo"
	"github.com/mohae/deepcopy"

	"github.com/DataDog/datadog-agent/pkg/util/containers"
)

// Kind is the kind of an entity.
type Kind string

// Defined Kinds
const (
	KindContainer       Kind = "container"
	KindKubernetesPod   Kind = "kubernetes_pod"
	KindECSTask         Kind = "ecs_task"
	KindGardenContainer Kind = "garden_container"
)

// Source is the source name of an entity.
type Source string

// Defined Sources
const (
	SourceDocker       Source = "docker"
	SourceContainerd   Source = "containerd"
	SourceECS          Source = "ecs"
	SourceECSFargate   Source = "ecs_fargate"
	SourceKubelet      Source = "kubelet"
	SourceKubeMetadata Source = "kube_metadata"
	SourcePodman       Source = "podman"
	SourceCloudfoundry Source = "cloudfoundry"
)

// ContainerRuntime is the container runtime used by a container.
type ContainerRuntime string

// Defined ContainerRuntimes
const (
	ContainerRuntimeDocker     ContainerRuntime = "docker"
	ContainerRuntimeContainerd ContainerRuntime = "containerd"
	ContainerRuntimePodman     ContainerRuntime = "podman"
	ContainerRuntimeCRIO       ContainerRuntime = "cri-o"
)

// ECSLaunchType is the launch type of an ECS task.
type ECSLaunchType string

// Defined ECSLaunchTypes
const (
	ECSLaunchTypeEC2     ECSLaunchType = "ec2"
	ECSLaunchTypeFargate ECSLaunchType = "fargate"
)

// EventType is the type of an event (set or unset).
type EventType int

const (
	// EventTypeSet indicates that an entity has been added or updated.
	EventTypeSet EventType = iota

	// EventTypeUnset indicates that an entity has been removed, or that one
	// source of several sources provided information about an entity has
	// stopped providing such information.
	EventTypeUnset
)

// Entity represents a single unit of work being done that is of interest to
// the agent.
//
// This interface is implemented by several concrete types, and is typically
// cast to that concrete type to get detailed information.  The concrete type
// typically corresponds to the entity's type (GetID().Kind), except that
// sometimes an EntityID itself is used as an Entity, especially when an entity
// has been deleted and the information required to construct a full concrete
// type is no longer available. Callers should always check the result of the
// cast operation.
type Entity interface {
	// GetID gets the EntityID for this entity.
	GetID() EntityID

	// Merge merges this entity with another of the same kind.  This is used
	// to generate a composite entity representing data from several sources.
	Merge(Entity) error

	// DeepCopy copies an entity such that modifications of the copy will not
	// affet the original.
	DeepCopy() Entity

	// String provides a summary of the entity.  The string may span several lines,
	// especially if verbose.
	String(verbose bool) string
}

// EntityID represents the ID of an Entity.  Note that entities from different sources
// may have the same EntityID.
type EntityID struct {
	// Kind identifies the kind of entity.  This typically corresponds to the concrete
	// type of the Entity, but this is not always the case; see Entity for details.
	Kind Kind

	// ID is the ID for this entity, in a format specific to the entity Kind.
	ID string
}

// EntityID satisfies the Entity interface for EntityID to allow a standalone
// EntityID to be passed in events of type EventTypeUnset without the need to
// build a full, concrete entity.
var _ Entity = EntityID{}

// GetID implements Entity#GetID.
func (i EntityID) GetID() EntityID {
	return i
}

// Merge implements Entity#Merge.
func (i EntityID) Merge(e Entity) error {
	// Merge returns an error because EntityID is not expected to be merged
	// with another Entity, because it's used as an identifier.
	return errors.New("cannot merge EntityID with another entity")
}

// DeepCopy implements Entity#DeepCopy.
func (i EntityID) DeepCopy() Entity {
	return i
}

// String implements Entity#String.
func (i EntityID) String(_ bool) string {
	return fmt.Sprintln("Kind:", i.Kind, "ID:", i.ID)
}

// EntityMeta represents generic metadata about an Entity.
type EntityMeta struct {
	Name        string
	Namespace   string
	Annotations map[string]string
	Labels      map[string]string
}

// String returns a string representation of EntityMeta.
func (e EntityMeta) String(verbose bool) string {
	var sb strings.Builder
	_, _ = fmt.Fprintln(&sb, "Name:", e.Name)
	_, _ = fmt.Fprintln(&sb, "Namespace:", e.Namespace)

	if verbose {
		_, _ = fmt.Fprintln(&sb, "Annotations:", mapToString(e.Annotations))
		_, _ = fmt.Fprintln(&sb, "Labels:", mapToString(e.Labels))
	}

	return sb.String()
}

// ContainerImage is the an image used by a container.
type ContainerImage struct {
	ID        string
	RawName   string
	Name      string
	ShortName string
	Tag       string
}

// NewContainerImage builds a ContainerImage from an image name
func NewContainerImage(imageName string) (ContainerImage, error) {
	image := ContainerImage{
		RawName: imageName,
		Name:    imageName,
	}

	name, shortName, tag, err := containers.SplitImageName(imageName)
	if err != nil {
		return image, err
	}

	if tag == "" {
		tag = "latest"
	}

	image.Name = name
	image.ShortName = shortName
	image.Tag = tag

	return image, nil
}

// String returns a string representation of ContainerImage.
func (c ContainerImage) String(verbose bool) string {
	var sb strings.Builder
	_, _ = fmt.Fprintln(&sb, "Name:", c.Name)
	_, _ = fmt.Fprintln(&sb, "Tag:", c.Tag)

	if verbose {
		_, _ = fmt.Fprintln(&sb, "ID:", c.ID)
		_, _ = fmt.Fprintln(&sb, "Raw Name:", c.RawName)
		_, _ = fmt.Fprintln(&sb, "Short Name:", c.ShortName)
	}

	return sb.String()
}

// ContainerState is the state of a container.
type ContainerState struct {
	Running    bool
	StartedAt  time.Time
	FinishedAt time.Time
	ExitCode   *uint32
}

// String returns a string representation of ContainerState.
func (c ContainerState) String(verbose bool) string {
	var sb strings.Builder
	_, _ = fmt.Fprintln(&sb, "Running:", c.Running)

	if verbose {
		_, _ = fmt.Fprintln(&sb, "Started At:", c.StartedAt)
		_, _ = fmt.Fprintln(&sb, "Finished At:", c.FinishedAt)
		if c.ExitCode != nil {
			_, _ = fmt.Fprintln(&sb, "Exit Code:", *c.ExitCode)
		}
	}

	return sb.String()
}

// ContainerPort is a port open in the container.
type ContainerPort struct {
	Name     string
	Port     int
	Protocol string
}

// String returns a string representation of ContainerPort.
func (c ContainerPort) String(verbose bool) string {
	var sb strings.Builder
	_, _ = fmt.Fprintln(&sb, "Port:", c.Port)

	if verbose {
		_, _ = fmt.Fprintln(&sb, "Name:", c.Name)
		_, _ = fmt.Fprintln(&sb, "Protocol:", c.Protocol)
	}

	return sb.String()
}

// OrchestratorContainer is a reference to a Container with
// orchestrator-specific data attached to it.
type OrchestratorContainer struct {
	ID    string
	Name  string
	Image ContainerImage
}

// String returns a string representation of OrchestratorContainer.
func (o OrchestratorContainer) String(_ bool) string {
	return fmt.Sprintln("Name:", o.Name, "ID:", o.ID)
}

// Container is an Entity representing a containerized workload.
type Container struct {
	EntityID
	EntityMeta
	EnvVars    map[string]string
	Hostname   string
	Image      ContainerImage
	NetworkIPs map[string]string
	PID        int
	Ports      []ContainerPort
	Runtime    ContainerRuntime
	State      ContainerState
}

// GetID implements Entity#GetID.
func (c Container) GetID() EntityID {
	return c.EntityID
}

// Merge implements Entity#Merge.
func (c *Container) Merge(e Entity) error {
	cc, ok := e.(*Container)
	if !ok {
		return fmt.Errorf("cannot merge Container with different kind %T", e)
	}

	return mergo.Merge(c, cc)
}

// DeepCopy implements Entity#DeepCopy.
func (c Container) DeepCopy() Entity {
	cp := deepcopy.Copy(c).(Container)
	return &cp
}

// String implements Entity#String.
func (c Container) String(verbose bool) string {
	var sb strings.Builder

	_, _ = fmt.Fprintln(&sb, "----------- Entity ID -----------")
	_, _ = fmt.Fprint(&sb, c.EntityID.String(verbose))

	_, _ = fmt.Fprintln(&sb, "----------- Entity Meta -----------")
	_, _ = fmt.Fprint(&sb, c.EntityMeta.String(verbose))

	_, _ = fmt.Fprintln(&sb, "----------- Image -----------")
	_, _ = fmt.Fprint(&sb, c.Image.String(verbose))

	_, _ = fmt.Fprintln(&sb, "----------- Container Info -----------")
	_, _ = fmt.Fprintln(&sb, "Runtime:", c.Runtime)
	_, _ = fmt.Fprint(&sb, c.State.String(verbose))

	if verbose {
		_, _ = fmt.Fprintln(&sb, "Env Variables:", mapToString(c.EnvVars))
		_, _ = fmt.Fprintln(&sb, "Hostname:", c.Hostname)
		_, _ = fmt.Fprintln(&sb, "Network IPs:", mapToString(c.NetworkIPs))
		_, _ = fmt.Fprintln(&sb, "PID:", c.PID)
	}

	if len(c.Ports) > 0 && verbose {
		_, _ = fmt.Fprintln(&sb, "----------- Ports -----------")
		for _, p := range c.Ports {
			_, _ = fmt.Fprint(&sb, p.String(verbose))
		}
	}

	return sb.String()
}

var _ Entity = &Container{}

// KubernetesPod is an Entity representing a Kubernetes Pod.
type KubernetesPod struct {
	EntityID
	EntityMeta
	Owners                     []KubernetesPodOwner
	PersistentVolumeClaimNames []string
	Containers                 []OrchestratorContainer
	Ready                      bool
	Phase                      string
	IP                         string
	PriorityClass              string
	KubeServices               []string
	NamespaceLabels            map[string]string
}

// GetID implements Entity#GetID.
func (p KubernetesPod) GetID() EntityID {
	return p.EntityID
}

// Merge implements Entity#Merge.
func (p *KubernetesPod) Merge(e Entity) error {
	pp, ok := e.(*KubernetesPod)
	if !ok {
		return fmt.Errorf("cannot merge KubernetesPod with different kind %T", e)
	}

	return mergo.Merge(p, pp)
}

// DeepCopy implements Entity#DeepCopy.
func (p KubernetesPod) DeepCopy() Entity {
	cp := deepcopy.Copy(p).(KubernetesPod)
	return &cp
}

// String implements Entity#String.
func (p KubernetesPod) String(verbose bool) string {
	var sb strings.Builder
	_, _ = fmt.Fprintln(&sb, "----------- Entity ID -----------")
	_, _ = fmt.Fprintln(&sb, p.EntityID.String(verbose))

	_, _ = fmt.Fprintln(&sb, "----------- Entity Meta -----------")
	_, _ = fmt.Fprint(&sb, p.EntityMeta.String(verbose))

	if len(p.Owners) > 0 {
		_, _ = fmt.Fprintln(&sb, "----------- Owners -----------")
		for _, o := range p.Owners {
			_, _ = fmt.Fprint(&sb, o.String(verbose))
		}
	}

	if len(p.Containers) > 0 {
		_, _ = fmt.Fprintln(&sb, "----------- Containers -----------")
		for _, c := range p.Containers {
			_, _ = fmt.Fprint(&sb, c.String(verbose))
		}
	}

	_, _ = fmt.Fprintln(&sb, "----------- Pod Info -----------")
	_, _ = fmt.Fprintln(&sb, "Ready:", p.Ready)
	_, _ = fmt.Fprintln(&sb, "Phase:", p.Phase)
	_, _ = fmt.Fprintln(&sb, "IP:", p.IP)

	if verbose {
		_, _ = fmt.Fprintln(&sb, "Priority Class:", p.PriorityClass)
		_, _ = fmt.Fprintln(&sb, "PVCs:", sliceToString(p.PersistentVolumeClaimNames))
		_, _ = fmt.Fprintln(&sb, "Kube Services:", sliceToString(p.KubeServices))
		_, _ = fmt.Fprintln(&sb, "Namespace Labels:", mapToString(p.NamespaceLabels))
	}

	return sb.String()
}

var _ Entity = &KubernetesPod{}

// KubernetesPodOwner is extracted from a pod's owner references.
type KubernetesPodOwner struct {
	Kind string
	Name string
	ID   string
}

// String returns a string representation of KubernetesPodOwner.
func (o KubernetesPodOwner) String(verbose bool) string {
	var sb strings.Builder
	_, _ = fmt.Fprintln(&sb, "Kind:", o.Kind, "Name:", o.Name)

	if verbose {
		_, _ = fmt.Fprintln(&sb, "ID:", o.ID)

	}

	return sb.String()
}

// ECSTask is an Entity representing an ECS Task.
type ECSTask struct {
	EntityID
	EntityMeta
	Tags                  map[string]string
	ContainerInstanceTags map[string]string
	ClusterName           string
	Region                string
	AvailabilityZone      string
	Family                string
	Version               string
	LaunchType            ECSLaunchType
	Containers            []OrchestratorContainer
}

// GetID implements Entity#GetID.
func (t ECSTask) GetID() EntityID {
	return t.EntityID
}

// Merge implements Entity#Merge.
func (t *ECSTask) Merge(e Entity) error {
	tt, ok := e.(*ECSTask)
	if !ok {
		return fmt.Errorf("cannot merge ECSTask with different kind %T", e)
	}

	return mergo.Merge(t, tt)
}

// DeepCopy implements Entity#DeepCopy.
func (t ECSTask) DeepCopy() Entity {
	cp := deepcopy.Copy(t).(ECSTask)
	return &cp
}

// String implements Entity#String.
func (t ECSTask) String(verbose bool) string {
	var sb strings.Builder
	_, _ = fmt.Fprintln(&sb, "----------- Entity ID -----------")
	_, _ = fmt.Fprint(&sb, t.EntityID.String(verbose))

	_, _ = fmt.Fprintln(&sb, "----------- Entity Meta -----------")
	_, _ = fmt.Fprint(&sb, t.EntityMeta.String(verbose))

	_, _ = fmt.Fprintln(&sb, "----------- Containers -----------")
	for _, c := range t.Containers {
		_, _ = fmt.Fprint(&sb, c.String(verbose))
	}

	if verbose {
		_, _ = fmt.Fprintln(&sb, "----------- Task Info -----------")
		_, _ = fmt.Fprintln(&sb, "Tags:", mapToString(t.Tags))
		_, _ = fmt.Fprintln(&sb, "Container Instance Tags:", mapToString(t.ContainerInstanceTags))
		_, _ = fmt.Fprintln(&sb, "Cluster Name:", t.ClusterName)
		_, _ = fmt.Fprintln(&sb, "Region:", t.Region)
		_, _ = fmt.Fprintln(&sb, "Availability Zone:", t.AvailabilityZone)
		_, _ = fmt.Fprintln(&sb, "Family:", t.Family)
		_, _ = fmt.Fprintln(&sb, "Version:", t.Version)
		_, _ = fmt.Fprintln(&sb, "Launch Type:", t.LaunchType)
	}

	return sb.String()
}

var _ Entity = &ECSTask{}

// GardenContainer is an Entity representing a CloudFoundry Garden Container
type GardenContainer struct {
	EntityID
	EntityMeta
	Tags []string
}

// GetID returns a GardenContainer's EntityID.
func (c GardenContainer) GetID() EntityID {
	return c.EntityID
}

// Merge merges a GardenContainer with another. Returns an error if trying to
// merge with another kind.
func (c *GardenContainer) Merge(e Entity) error {
	cc, ok := e.(*GardenContainer)
	if !ok {
		return fmt.Errorf("cannot merge GardenContainer with different kind %T", e)
	}

	return mergo.Merge(c, cc)
}

// DeepCopy returns a deep copy of the container.
func (c GardenContainer) DeepCopy() Entity {
	cp := deepcopy.Copy(c).(GardenContainer)
	return &cp
}

// String returns a string representation of a GardenContainer.
func (c GardenContainer) String(verbose bool) string {
	var sb strings.Builder
	_, _ = fmt.Fprintln(&sb, "----------- Entity ID -----------")
	_, _ = fmt.Fprint(&sb, c.EntityID.String(verbose))

	_, _ = fmt.Fprintln(&sb, "----------- Entity Meta -----------")
	_, _ = fmt.Fprint(&sb, c.EntityMeta.String(verbose))

	_, _ = fmt.Fprintln(&sb, "----------- Container Info -----------")
	_, _ = fmt.Fprintln(&sb, "Tags:", sliceToString(c.Tags))

	return sb.String()
}

var _ Entity = &GardenContainer{}

// CollectorEvent is an event generated by a metadata collector, to be handled
// by the metadata store.
type CollectorEvent struct {
	Type   EventType
	Source Source
	Entity Entity
}

// Event represents a change to an entity.
type Event struct {
	// Type gives the type of this event.
	//
	// When Type is EventTypeSet, this represents an added or updated entity.
	// Multiple set events may be sent for a single entity.
	//
	// When Type is EventTypeUnset, this represents either a removed entity or
	// a single source removing its information about an entity.  Multiple
	// unset events may be sent for a single entity, if multiple sources
	// provided information about it.
	Type EventType

	// Sources gives the sources providing the information in the Entity field.
	Sources []Source

	// Entity is the entity involved in this event.  For a set event, this may
	// contain information "merged" from multiple sources, as listed in the
	// Sources field.  For an unset event, it may contain incomplete information,
	// perhaps only an EntityID.
	//
	// This field is typically cast to a concrete type corresponding to its kind
	// (Entity.GetID().Kind).
	Entity Entity
}

// EventBundle is a collection of events sent to Store subscribers.
//
// Subscribers are expected to respond to EventBundles quickly.  The Store will
// not move on to notify the next subscriber until the included channel Ch is
// closed.  Subscribers which need to update their state before other
// subscribers are notified should close this channel once those updates are
// complete.  Other subscribers should close the channel immediately.
// See the example for Store#Subscribe for details.
type EventBundle struct {
	Events []Event
	Ch     chan struct{}
}
