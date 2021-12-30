// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2017-present Datadog, Inc.

// +build clusterchecks,!kubeapiserver

package v1

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/DataDog/datadog-agent/pkg/util/cloudproviders/cloudfoundry"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/gorilla/mux"
)

type CFApplication struct {
	GUID           string
	Name           string
	SpaceGUID      string
	SpaceName      string
	OrgName        string
	OrgGUID        string
	Instances      int
	Buildpacks     []string
	DiskQuota      int
	TotalDiskQuota int
	Memory         int
	TotalMemory    int
	Labels         map[string]string
	Annotations    map[string]string
}

func installCloudFoundryMetadataEndpoints(r *mux.Router) {
	r.HandleFunc("/tags/cf/apps/{nodeName}", getCFAppsMetadataForNode).Methods("GET")
	r.HandleFunc("/cf/apps/{guid}", getCFApplication).Methods("GET")
	r.HandleFunc("/cf/apps", getCFApplications).Methods("GET")
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

// getCFApplications is only used when the PCF firehose nozzle hits the DCA for the list of cloudfoundry applications
// It return a list of CFApplications
func getCFApplications(w http.ResponseWriter, r *http.Request) {
	ccCache, err := cloudfoundry.GetGlobalCCCache()
	if err != nil {
		log.Errorf("Could not retrieve CC cache: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		apiRequests.Inc("getCFApplications", strconv.Itoa(http.StatusInternalServerError))
		return
	}

	apps, err := ccCache.GetCFApplications()
	if err != nil {
		log.Errorf("Error getting applications: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		apiRequests.Inc(
			"getCFApplications",
			strconv.Itoa(http.StatusInternalServerError),
		)
		return
	}

	appsBytes, err := json.Marshal(apps)
	if err != nil {
		log.Errorf("Could not process CF applications: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		apiRequests.Inc(
			"getCFApplications",
			strconv.Itoa(http.StatusInternalServerError),
		)
		return
	}
	if len(appsBytes) > 0 {
		w.WriteHeader(http.StatusOK)
		w.Write(appsBytes)
		apiRequests.Inc(
			"getCFApplications",
			strconv.Itoa(http.StatusOK),
		)
		return
	}
}

// getCFApplication is only used when the PCF firehose nozzle hits the DCA for the list of cloudfoundry applications
// It return a list of CFApplications
func getCFApplication(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	guid := vars["guid"]
	ccCache, err := cloudfoundry.GetGlobalCCCache()
	if err != nil {
		log.Errorf("Could not retrieve CC cache: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		apiRequests.Inc("getCFApplication", strconv.Itoa(http.StatusInternalServerError))
		return
	}

	app, err := ccCache.GetCFApplication(guid)
	if err != nil {
		log.Errorf("Error getting application: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		apiRequests.Inc(
			"getCFApplication",
			strconv.Itoa(http.StatusInternalServerError),
		)
		return
	}

	appBytes, err := json.Marshal(app)
	if err != nil {
		log.Errorf("Could not process CF application: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		apiRequests.Inc(
			"getCFApplication",
			strconv.Itoa(http.StatusInternalServerError),
		)
		return
	}
	if len(appBytes) > 0 {
		w.WriteHeader(http.StatusOK)
		w.Write(appBytes)
		apiRequests.Inc(
			"getCFApplication",
			strconv.Itoa(http.StatusOK),
		)
		return
	}
}
