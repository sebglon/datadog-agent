// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2017-present Datadog, Inc.

// +build clusterchecks,!kubeapiserver

package v1

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/DataDog/datadog-agent/pkg/util/cloudproviders/cloudfoundry"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/gorilla/mux"
)

func installCloudFoundryMetadataEndpoints(r *mux.Router) {
	r.HandleFunc("/tags/cf/apps/{nodeName}", getCFAppsMetadataForNode).Methods("GET")
	r.HandleFunc("/cf/apps", listCFApplications).Methods("GET")
	r.HandleFunc("/cf/spaces", listCFSpaces).Methods("GET")
	r.HandleFunc("/cf/orgs", listCFOrgs).Methods("GET")
	r.HandleFunc("/cf/processes", listCFProcesses).Methods("GET")
}

func installKubernetesMetadataEndpoints(r *mux.Router) {}

// getCFAppsMetadataForNode is only used when the node agent hits the DCA for the list of cloudfoundry applications tags
// It return a list of tags for each application that can be directly used in the tagger
func getCFAppsMetadataForNode(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	nodename := vars["nodeName"]
	bbsCache, err := cloudfoundry.GetGlobalBBSCache()
	if err != nil {
		log.Errorf("Could not retrieve BBS cache: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		apiRequests.Inc("getCFAppsMetadataForNode", strconv.Itoa(http.StatusInternalServerError))
		return
	}

	tags, err := bbsCache.GetTagsForNode(nodename)
	if err != nil {
		log.Errorf("Error getting tags for node %s: %v", nodename, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		apiRequests.Inc(
			"getCFAppsMetadataForNode",
			strconv.Itoa(http.StatusInternalServerError),
		)
		return
	}

	tagsBytes, err := json.Marshal(tags)
	if err != nil {
		log.Errorf("Could not process tags for CF applications: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		apiRequests.Inc(
			"getCFAppsMetadataForNode",
			strconv.Itoa(http.StatusInternalServerError),
		)
		return
	}
	if len(tagsBytes) > 0 {
		w.WriteHeader(http.StatusOK)
		w.Write(tagsBytes)
		apiRequests.Inc(
			"getCFAppsMetadataForNode",
			strconv.Itoa(http.StatusOK),
		)
		return
	}
}

// listCFApplications is only used when the PCF firehose nozzle hits the DCA for the list of cloudfoundry applications
// It return a list of V3 cloudfoundry applications
func listCFApplications(w http.ResponseWriter, r *http.Request) {
	ccCache, err := cloudfoundry.GetGlobalCCCache()
	if err != nil {
		log.Errorf("Could not retrieve CC cache: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		apiRequests.Inc("listCFApplications", strconv.Itoa(http.StatusInternalServerError))
		return
	}

	apps, err := ccCache.GetApps()
	if err != nil {
		log.Errorf("Error getting applications: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		apiRequests.Inc(
			"listCFApplications",
			strconv.Itoa(http.StatusInternalServerError),
		)
		return
	}

	appsBytes, err := json.Marshal(apps)
	if err != nil {
		log.Errorf("Could not process CF applications: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		apiRequests.Inc(
			"listCFApplications",
			strconv.Itoa(http.StatusInternalServerError),
		)
		return
	}
	if len(appsBytes) > 0 {
		fmt.Printf("Sending CF Applications\n")
		w.WriteHeader(http.StatusOK)
		w.Write(appsBytes)
		apiRequests.Inc(
			"listCFApplications",
			strconv.Itoa(http.StatusOK),
		)
		return
	}
}

// listCFSpaces is only used when the PCF firehose nozzle hits the DCA for the list of cloudfoundry spaces
// It return a list of V3 cloudfoundry spaces
func listCFSpaces(w http.ResponseWriter, r *http.Request) {
	ccCache, err := cloudfoundry.GetGlobalCCCache()
	if err != nil {
		log.Errorf("Could not retrieve CC cache: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		apiRequests.Inc("listCFSpaces", strconv.Itoa(http.StatusInternalServerError))
		return
	}

	spaces, err := ccCache.GetSpaces()
	if err != nil {
		log.Errorf("Error getting spaces: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		apiRequests.Inc(
			"listCFSpaces",
			strconv.Itoa(http.StatusInternalServerError),
		)
		return
	}

	spacesBytes, err := json.Marshal(spaces)
	if err != nil {
		log.Errorf("Could not process CF spaces: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		apiRequests.Inc(
			"listCFSpaces",
			strconv.Itoa(http.StatusInternalServerError),
		)
		return
	}
	if len(spacesBytes) > 0 {
		w.WriteHeader(http.StatusOK)
		w.Write(spacesBytes)
		apiRequests.Inc(
			"listCFSpaces",
			strconv.Itoa(http.StatusOK),
		)
		return
	}
}

// listCFOrgs is only used when the PCF firehose nozzle hits the DCA for the list of cloudfoundry orgs
// It return a list of V3 cloudfoundry orgs
func listCFOrgs(w http.ResponseWriter, r *http.Request) {
	ccCache, err := cloudfoundry.GetGlobalCCCache()
	if err != nil {
		log.Errorf("Could not retrieve CC cache: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		apiRequests.Inc("listCFOrgs", strconv.Itoa(http.StatusInternalServerError))
		return
	}

	orgs, err := ccCache.GetOrgs()
	if err != nil {
		log.Errorf("Error getting organizations: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		apiRequests.Inc(
			"listCFOrgs",
			strconv.Itoa(http.StatusInternalServerError),
		)
		return
	}

	orgsBytes, err := json.Marshal(orgs)
	if err != nil {
		log.Errorf("Could not process CF organizations: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		apiRequests.Inc(
			"listCFOrgs",
			strconv.Itoa(http.StatusInternalServerError),
		)
		return
	}
	if len(orgsBytes) > 0 {
		w.WriteHeader(http.StatusOK)
		w.Write(orgsBytes)
		apiRequests.Inc(
			"listCFOrgs",
			strconv.Itoa(http.StatusOK),
		)
		return
	}
}

// listCFProcesses is only used when the PCF firehose nozzle hits the DCA for the list of cloudfoundry processes
// It return a list of cloudfoundry processes
func listCFProcesses(w http.ResponseWriter, r *http.Request) {
	ccCache, err := cloudfoundry.GetGlobalCCCache()
	if err != nil {
		log.Errorf("Could not retrieve CC cache: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		apiRequests.Inc("listCFProcesses", strconv.Itoa(http.StatusInternalServerError))
		return
	}

	processes, err := ccCache.GetProcesses()
	if err != nil {
		log.Errorf("Error getting processes: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		apiRequests.Inc(
			"listCFProcesses",
			strconv.Itoa(http.StatusInternalServerError),
		)
		return
	}

	processesBytes, err := json.Marshal(processes)
	if err != nil {
		log.Errorf("Could not process CF processes: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		apiRequests.Inc(
			"listCFProcesses",
			strconv.Itoa(http.StatusInternalServerError),
		)
		return
	}
	if len(processesBytes) > 0 {
		w.WriteHeader(http.StatusOK)
		w.Write(processesBytes)
		apiRequests.Inc(
			"listCFProcesses",
			strconv.Itoa(http.StatusOK),
		)
		return
	}
}
