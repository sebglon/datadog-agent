// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// +build clusterchecks

package cloudfoundry

import (
	"context"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/cloudfoundry-community/go-cfclient"
)

// CCCacheI is an interface for a structure that caches and automatically refreshes data from Cloud Foundry API
// it's useful mostly to be able to mock CCCache during unit tests
type CCCacheI interface {
	// LastUpdated return the last time the cache was updated
	LastUpdated() time.Time

	// UpdatedOnce returns a channel that is closed once the cache has been updated
	// successfully at least once.  Successive calls to UpdatedOnce return the
	// same channel.  If the cache's context ends before an update occurs, this channel
	// will never close.
	UpdatedOnce() <-chan struct{}

	// GetApp looksf or an app with the given GUID in the cache
	GetApp(string) (*cfclient.V3App, error)
}

// CCCache is a simple structure that caches and automatically refreshes data from Cloud Foundry API
type CCCache struct {
	sync.RWMutex
	cancelContext   context.Context
	configured      bool
	ccAPIClient     CCClientI
	pollInterval    time.Duration
	lastUpdated     time.Time
	updatedOnce     chan struct{}
	appsByGUID      map[string]*cfclient.V3App
	orgsByGUID      map[string]*cfclient.V3Organization
	spacesByGUID    map[string]*cfclient.V3Space
	processesByGUID map[string]*cfclient.Process
	appsBatchSize   int
}

type CCClientI interface {
	ListV3AppsByQuery(url.Values) ([]cfclient.V3App, error)
	ListV3OrganizationsByQuery(url.Values) ([]cfclient.V3Organization, error)
	ListV3SpacesByQuery(url.Values) ([]cfclient.V3Space, error)
	ListAllProcessesByQuery(query url.Values) ([]cfclient.Process, error)
}

var globalCCCache = &CCCache{}

// ConfigureGlobalCCCache configures the global instance of CCCache from provided config
func ConfigureGlobalCCCache(ctx context.Context, ccURL, ccClientID, ccClientSecret string, skipSSLValidation bool, pollInterval time.Duration, appsBatchSize int, testing CCClientI) (*CCCache, error) {
	globalCCCache.Lock()
	defer globalCCCache.Unlock()

	if globalCCCache.configured {
		return globalCCCache, nil
	}

	if testing != nil {
		globalCCCache.ccAPIClient = testing
	} else {
		clientConfig := &cfclient.Config{
			ApiAddress:        ccURL,
			ClientID:          ccClientID,
			ClientSecret:      ccClientSecret,
			SkipSslValidation: skipSSLValidation,
		}
		var err error
		globalCCCache.ccAPIClient, err = cfclient.NewClient(clientConfig)
		if err != nil {
			return nil, err
		}
	}

	globalCCCache.pollInterval = pollInterval
	globalCCCache.appsBatchSize = appsBatchSize
	globalCCCache.lastUpdated = time.Time{} // zero time
	globalCCCache.updatedOnce = make(chan struct{})
	globalCCCache.cancelContext = ctx
	globalCCCache.configured = true

	go globalCCCache.start()

	return globalCCCache, nil
}

// GetGlobalCCCache returns the global instance of CCCache (or error if the instance is not configured yet)
func GetGlobalCCCache() (*CCCache, error) {
	globalCCCache.Lock()
	defer globalCCCache.Unlock()
	if !globalCCCache.configured {
		return nil, fmt.Errorf("global CC Cache not configured")
	}
	return globalCCCache, nil
}

// LastUpdated return the last time the cache was updated
func (ccc *CCCache) LastUpdated() time.Time {
	ccc.RLock()
	defer ccc.RUnlock()
	return ccc.lastUpdated
}

// UpdatedOnce returns a channel that is closed once the cache has been updated
// successfully at least once.  Successive calls to UpdatedOnce return the
// same channel.  If the cache's context ends before an update occurs, this channel
// will never close.
func (ccc *CCCache) UpdatedOnce() <-chan struct{} {
	return ccc.updatedOnce
}

// GetApp looksf or an app with the given GUID in the cache
func (ccc *CCCache) GetApps() ([]*cfclient.V3App, error) {
	ccc.RLock()
	defer ccc.RUnlock()

	var apps []*cfclient.V3App
	for _, app := range ccc.appsByGUID {
		apps = append(apps, app)
	}

	return apps, nil
}

// GetSpaces TODO
func (ccc *CCCache) GetSpaces() ([]*cfclient.V3Space, error) {
	ccc.RLock()
	defer ccc.RUnlock()

	var spaces []*cfclient.V3Space
	for _, app := range ccc.spacesByGUID {
		spaces = append(spaces, app)
	}

	return spaces, nil
}

// GetOrgs TODO
func (ccc *CCCache) GetOrgs() ([]*cfclient.V3Organization, error) {
	ccc.RLock()
	defer ccc.RUnlock()

	var orgs []*cfclient.V3Organization
	for _, app := range ccc.orgsByGUID {
		orgs = append(orgs, app)
	}

	return orgs, nil
}

// GetProcesses TODO
func (ccc *CCCache) GetProcesses() ([]*cfclient.Process, error) {
	ccc.RLock()
	defer ccc.RUnlock()

	var processes []*cfclient.Process
	for _, app := range ccc.processesByGUID {
		processes = append(processes, app)
	}

	return processes, nil
}

// GetApp looksf or an app with the given GUID in the cache
func (ccc *CCCache) GetApp(guid string) (*cfclient.V3App, error) {
	ccc.RLock()
	defer ccc.RUnlock()

	app, ok := ccc.appsByGUID[guid]
	if !ok {
		return nil, fmt.Errorf("could not find app %s in cloud controller cache", guid)
	}
	return app, nil
}

func (ccc *CCCache) GetSpace(guid string) (*cfclient.V3Space, error) {
	ccc.RLock()
	defer ccc.RUnlock()
	space, ok := ccc.spacesByGUID[guid]
	if !ok {
		return nil, fmt.Errorf("could not find space %s in cloud controller cache", guid)
	}
	return space, nil
}

func (ccc *CCCache) GetOrg(guid string) (*cfclient.V3Organization, error) {
	ccc.RLock()
	defer ccc.RUnlock()
	org, ok := ccc.orgsByGUID[guid]
	if !ok {
		return nil, fmt.Errorf("could not find org %s in cloud controller cache", guid)
	}
	return org, nil
}

func (ccc *CCCache) GetProcess(guid string) (*cfclient.Process, error) {
	ccc.RLock()
	defer ccc.RUnlock()
	process, ok := ccc.processesByGUID[guid]
	if !ok {
		return nil, fmt.Errorf("could not find process %s in cloud controller cache", guid)
	}
	return process, nil
}

func (ccc *CCCache) start() {
	ccc.readData()
	dataRefreshTicker := time.NewTicker(ccc.pollInterval)
	for {
		select {
		case <-dataRefreshTicker.C:
			ccc.readData()
		case <-ccc.cancelContext.Done():
			dataRefreshTicker.Stop()
			return
		}
	}
}

func (ccc *CCCache) readData() {
	log.Debug("Reading data from CC API")
	var wg sync.WaitGroup

	// List applications
	wg.Add(1)
	var appsByGUID map[string]*cfclient.V3App
	go func() {
		defer wg.Done()
		query := url.Values{}
		query.Add("per_page", fmt.Sprintf("%d", ccc.appsBatchSize))
		apps, err := ccc.ccAPIClient.ListV3AppsByQuery(query)
		if err != nil {
			log.Errorf("Failed listing apps from cloud controller: %v", err)
			return
		}
		appsByGUID = make(map[string]*cfclient.V3App, len(apps))
		for _, app := range apps {
			appsByGUID[app.GUID] = &app
		}
	}()

	// List spaces
	wg.Add(1)
	var spacesByGUID map[string]*cfclient.V3Space
	go func() {
		defer wg.Done()
		query := url.Values{}
		query.Add("per_page", fmt.Sprintf("%d", ccc.appsBatchSize))
		spaces, err := ccc.ccAPIClient.ListV3SpacesByQuery(query)
		if err != nil {
			log.Errorf("Failed listing spaces from cloud controller: %v", err)
			return
		}
		spacesByGUID = make(map[string]*cfclient.V3Space, len(spaces))
		for _, space := range spaces {
			spacesByGUID[space.GUID] = &space
		}
	}()

	// List orgs
	wg.Add(1)
	var orgsByGUID map[string]*cfclient.V3Organization
	go func() {
		defer wg.Done()
		query := url.Values{}
		query.Add("per_page", fmt.Sprintf("%d", ccc.appsBatchSize))
		orgs, err := ccc.ccAPIClient.ListV3OrganizationsByQuery(query)
		if err != nil {
			log.Errorf("Failed listing orgs from cloud controller: %v", err)
			return
		}
		orgsByGUID = make(map[string]*cfclient.V3Organization, len(orgs))
		for _, org := range orgs {
			orgsByGUID[org.GUID] = &org
		}
	}()

	// List processes
	wg.Add(1)
	var processesByGUID map[string]*cfclient.Process
	go func() {
		defer wg.Done()
		query := url.Values{}
		query.Add("per_page", fmt.Sprintf("%d", ccc.appsBatchSize))
		processes, err := ccc.ccAPIClient.ListAllProcessesByQuery(query)
		if err != nil {
			log.Errorf("Failed listing orgs from cloud controller: %v", err)
			return
		}
		processesByGUID = make(map[string]*cfclient.Process, len(processes))
		for _, process := range processes {
			processesByGUID[process.GUID] = &process
		}
	}()

	// put new data in cache
	wg.Wait()
	ccc.Lock()
	defer ccc.Unlock()
	ccc.appsByGUID = appsByGUID
	ccc.spacesByGUID = spacesByGUID
	ccc.orgsByGUID = orgsByGUID
	ccc.processesByGUID = processesByGUID
	firstUpdate := ccc.lastUpdated.IsZero()
	ccc.lastUpdated = time.Now()
	if firstUpdate {
		close(ccc.updatedOnce)
	}
}
