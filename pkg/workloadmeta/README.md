# Workloadmeta Store

This package is responsible for gathering information about workloads and disseminating that to other components.

## Entities

An _Entity_ represents a single unit of work being done by a piece of software, like a process, a container, a kubernetes pod, or a task in any cloud provider, that the agent would like to observe.
The current workload of a host or cluster is represented by the current set of entities.

Each _Entity_ has a unique _EntityID_, composed of a _Kind_ and an ID.
Supported kinds include container, pod, and task.

## Sources

The service monitors information from many external _sources_, such as Kubelet or Podman.
Multiple sources may report information about the same entity.

## Store

The _Store_ is the central component of the package, storing the set of entities.
A store has a set of _collectors_ responsible for notifying the store of workload changes.
Each collector is specialized to a particular external service such as Kuberntes or ECS, roughly corresponding to a source.
Collectors can either poll for updates, or translate a stream of events from the external service, as appropriate.

The store provides information to other components either through subscriptions or by querying the current state.

Subscription provides a channel containing event bundles.
Each event in a bundle is either a "set" or "unset".
A "set" event indicates new information about an entity -- either a new entity, or an update to an existing enityt.
An "unset" event indicates that an entity no longer exists.
The first event bundle to each subscriber contains a "set" event for each existing entity at that time.
It's safe to assume that this first bundle corresponds to entities that existed before the agent started.
