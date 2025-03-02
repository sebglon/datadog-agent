// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package uptane

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"testing"
	"time"

	"github.com/DataDog/datadog-agent/pkg/config"
	"github.com/DataDog/datadog-agent/pkg/config/remote/meta"
	"github.com/DataDog/datadog-agent/pkg/proto/pbgo"
	"github.com/stretchr/testify/assert"
	"github.com/theupdateframework/go-tuf/data"
	"github.com/theupdateframework/go-tuf/sign"
)

func TestClientState(t *testing.T) {
	testRepository1 := newTestRepository(1, nil, nil, nil)
	config.Datadog.Set("remote_configuration.director_root", testRepository1.directorRoot)
	config.Datadog.Set("remote_configuration.config_root", testRepository1.configRoot)

	db := getTestDB()
	client1, err := NewClient(db, "testcachekey", 2)
	assert.NoError(t, err)

	// Testing default state
	expectedDefaultState := State{
		ConfigSnapshotVersion: 0,
		ConfigRootVersion:     meta.RootsConfig().LastVersion(),
		DirectorRootVersion:   meta.RootsDirector().LastVersion(),
	}
	clientState, err := client1.State()
	assert.NoError(t, err)
	assert.Equal(t, expectedDefaultState, clientState)
	_, err = client1.TargetsMeta()
	assert.Error(t, err)

	// Testing state for a simple valid repository
	err = client1.Update(testRepository1.toUpdate())
	assert.NoError(t, err)
	expectedUpdate1State := State{
		ConfigSnapshotVersion: uint64(testRepository1.configSnapshotVersion),
		ConfigRootVersion:     uint64(testRepository1.configRootVersion),
		DirectorRootVersion:   uint64(testRepository1.directorRootVersion),
	}
	clientState, err = client1.State()
	assert.NoError(t, err)
	assert.Equal(t, expectedUpdate1State, clientState)
	targets1, err := client1.TargetsMeta()
	assert.NoError(t, err)
	assert.Equal(t, string(testRepository1.directorTargets), string(targets1))

	// Testing state is maintained between runs
	client2, err := NewClient(db, "testcachekey", 2)
	assert.NoError(t, err)
	clientState, err = client2.State()
	assert.NoError(t, err)
	assert.Equal(t, expectedUpdate1State, clientState)
	targets1, err = client2.TargetsMeta()
	assert.NoError(t, err)
	assert.Equal(t, string(testRepository1.directorTargets), string(targets1))

	// Testing state is isolated by cache key
	client3, err := NewClient(db, "testcachekey2", 2)
	assert.NoError(t, err)
	clientState, err = client3.State()
	assert.NoError(t, err)
	assert.Equal(t, expectedDefaultState, clientState)
	_, err = client3.TargetsMeta()
	assert.Error(t, err)
}

func TestClientVerifyTUF(t *testing.T) {
	testRepository1 := newTestRepository(1, nil, nil, nil)
	config.Datadog.Set("remote_configuration.director_root", testRepository1.directorRoot)
	config.Datadog.Set("remote_configuration.config_root", testRepository1.configRoot)

	db := getTestDB()

	previousConfigTargets := testRepository1.configTargets
	client1, err := NewClient(db, "testcachekey1", 2)
	assert.NoError(t, err)
	testRepository1.configTargets = generateTargets(generateKey(), testRepository1.configTargetsVersion, nil)
	err = client1.Update(testRepository1.toUpdate())
	assert.Error(t, err)

	testRepository1.configTargets = previousConfigTargets
	client2, err := NewClient(db, "testcachekey2", 2)
	assert.NoError(t, err)
	testRepository1.directorTargets = generateTargets(generateKey(), testRepository1.directorTargetsVersion, nil)
	err = client2.Update(testRepository1.toUpdate())
	assert.Error(t, err)
}

func TestClientVerifyUptane(t *testing.T) {
	db := getTestDB()

	target1content, target1 := generateTarget()
	target2content, target2 := generateTarget()
	configTargets1 := data.TargetFiles{
		"2/APM_SAMPLING/1": target1,
		"2/APM_SAMPLING/2": target2,
	}
	directorTargets1 := data.TargetFiles{
		"2/APM_SAMPLING/1": target1,
	}
	configTargets2 := data.TargetFiles{
		"2/APM_SAMPLING/1": target1,
	}
	directorTargets2 := data.TargetFiles{
		"2/APM_SAMPLING/1": target1,
		"2/APM_SAMPLING/2": target2,
	}
	target3content, target3 := generateTarget()
	configTargets3 := data.TargetFiles{
		"2/APM_SAMPLING/1": target1,
		"2/APM_SAMPLING/2": target2,
	}
	directorTargets3 := data.TargetFiles{
		"2/APM_SAMPLING/1": target3,
	}
	testRepositoryValid := newTestRepository(1, configTargets1, directorTargets1, []*pbgo.File{{Path: "2/APM_SAMPLING/1", Raw: target1content}})
	testRepositoryInvalid1 := newTestRepository(1, configTargets2, directorTargets2, []*pbgo.File{{Path: "2/APM_SAMPLING/1", Raw: target1content}, {Path: "2/APM_SAMPLING/2", Raw: target2content}})
	testRepositoryInvalid2 := newTestRepository(1, configTargets3, directorTargets3, []*pbgo.File{{Path: "2/APM_SAMPLING/1", Raw: target3content}})

	config.Datadog.Set("remote_configuration.director_root", testRepositoryValid.directorRoot)
	config.Datadog.Set("remote_configuration.config_root", testRepositoryValid.configRoot)
	client1, err := NewClient(db, "testcachekey1", 2)
	assert.NoError(t, err)
	err = client1.Update(testRepositoryValid.toUpdate())
	assert.NoError(t, err)
	targetFile, err := client1.TargetFile("2/APM_SAMPLING/1")
	assert.NoError(t, err)
	assert.Equal(t, target1content, targetFile)

	config.Datadog.Set("remote_configuration.director_root", testRepositoryInvalid1.directorRoot)
	config.Datadog.Set("remote_configuration.config_root", testRepositoryInvalid1.configRoot)
	client2, err := NewClient(db, "testcachekey2", 2)
	assert.NoError(t, err)
	err = client2.Update(testRepositoryInvalid1.toUpdate())
	assert.Error(t, err)
	_, err = client1.TargetFile("2/APM_SAMPLING/2")
	assert.Error(t, err)

	config.Datadog.Set("remote_configuration.director_root", testRepositoryInvalid2.directorRoot)
	config.Datadog.Set("remote_configuration.config_root", testRepositoryInvalid2.configRoot)
	client3, err := NewClient(db, "testcachekey3", 2)
	assert.NoError(t, err)
	err = client3.Update(testRepositoryInvalid2.toUpdate())
	assert.Error(t, err)
	_, err = client3.TargetFile("2/APM_SAMPLING/1")
	assert.Error(t, err)
}

func TestClientVerifyOrgID(t *testing.T) {
	db := getTestDB()

	target1content, target1 := generateTarget()
	_, target2 := generateTarget()
	configTargets1 := data.TargetFiles{
		"2/APM_SAMPLING/1": target1,
		"2/APM_SAMPLING/2": target2,
	}
	directorTargets1 := data.TargetFiles{
		"2/APM_SAMPLING/1": target1,
	}
	configTargets2 := data.TargetFiles{
		"3/APM_SAMPLING/1": target1,
		"3/APM_SAMPLING/2": target2,
	}
	directorTargets2 := data.TargetFiles{
		"3/APM_SAMPLING/1": target1,
	}
	testRepositoryValid := newTestRepository(1, configTargets1, directorTargets1, []*pbgo.File{{Path: "2/APM_SAMPLING/1", Raw: target1content}})
	testRepositoryInvalid := newTestRepository(1, configTargets2, directorTargets2, []*pbgo.File{{Path: "3/APM_SAMPLING/1", Raw: target1content}})

	config.Datadog.Set("remote_configuration.director_root", testRepositoryValid.directorRoot)
	config.Datadog.Set("remote_configuration.config_root", testRepositoryValid.configRoot)
	client1, err := NewClient(db, "testcachekey1", 2)
	assert.NoError(t, err)
	err = client1.Update(testRepositoryValid.toUpdate())
	assert.NoError(t, err)

	config.Datadog.Set("remote_configuration.director_root", testRepositoryInvalid.directorRoot)
	config.Datadog.Set("remote_configuration.config_root", testRepositoryInvalid.configRoot)
	client2, err := NewClient(db, "testcachekey2", 2)
	assert.NoError(t, err)
	err = client2.Update(testRepositoryInvalid.toUpdate())
	assert.Error(t, err)
}

func generateKey() *sign.PrivateKey {
	key, _ := sign.GenerateEd25519Key()
	return key
}

type testRepositories struct {
	configTimestampKey   *sign.PrivateKey
	configTargetsKey     *sign.PrivateKey
	configSnapshotKey    *sign.PrivateKey
	configRootKey        *sign.PrivateKey
	directorTimestampKey *sign.PrivateKey
	directorTargetsKey   *sign.PrivateKey
	directorSnapshotKey  *sign.PrivateKey
	directorRootKey      *sign.PrivateKey

	configTimestampVersion   int
	configTargetsVersion     int
	configSnapshotVersion    int
	configRootVersion        int
	directorTimestampVersion int
	directorTargetsVersion   int
	directorSnapshotVersion  int
	directorRootVersion      int

	configTimestamp   []byte
	configTargets     []byte
	configSnapshot    []byte
	configRoot        []byte
	directorTimestamp []byte
	directorTargets   []byte
	directorSnapshot  []byte
	directorRoot      []byte

	targetFiles []*pbgo.File
}

func newTestRepository(version int, configTargets data.TargetFiles, directorTargets data.TargetFiles, targetFiles []*pbgo.File) testRepositories {
	repos := testRepositories{
		configTimestampKey:   generateKey(),
		configTargetsKey:     generateKey(),
		configSnapshotKey:    generateKey(),
		configRootKey:        generateKey(),
		directorTimestampKey: generateKey(),
		directorTargetsKey:   generateKey(),
		directorSnapshotKey:  generateKey(),
		directorRootKey:      generateKey(),
		targetFiles:          targetFiles,
	}
	repos.configRootVersion = version
	repos.configTimestampVersion = 10 + version
	repos.configTargetsVersion = 100 + version
	repos.configSnapshotVersion = 1000 + version
	repos.directorRootVersion = version
	repos.directorTimestampVersion = 20 + version
	repos.directorTargetsVersion = 200 + version
	repos.directorSnapshotVersion = 2000 + version
	repos.configRoot = generateRoot(repos.configRootKey, version, repos.configTimestampKey, repos.configTargetsKey, repos.configSnapshotKey)
	repos.configTargets = generateTargets(repos.configTargetsKey, 100+version, configTargets)
	repos.configSnapshot = generateSnapshot(repos.configSnapshotKey, 1000+version, repos.configTargetsVersion)
	repos.configTimestamp = generateTimestamp(repos.configTimestampKey, 10+version, repos.configSnapshotVersion, repos.configSnapshot)
	repos.directorRoot = generateRoot(repos.directorRootKey, version, repos.directorTimestampKey, repos.directorTargetsKey, repos.directorSnapshotKey)
	repos.directorTargets = generateTargets(repos.directorTargetsKey, 200+version, directorTargets)
	repos.directorSnapshot = generateSnapshot(repos.directorSnapshotKey, 2000+version, repos.directorTargetsVersion)
	repos.directorTimestamp = generateTimestamp(repos.directorTimestampKey, 20+version, repos.directorSnapshotVersion, repos.directorSnapshot)
	return repos
}

func (r testRepositories) toUpdate() *pbgo.LatestConfigsResponse {
	return &pbgo.LatestConfigsResponse{
		ConfigMetas: &pbgo.ConfigMetas{
			Roots:      []*pbgo.TopMeta{{Version: uint64(r.configRootVersion), Raw: r.configRoot}},
			Timestamp:  &pbgo.TopMeta{Version: uint64(r.configTimestampVersion), Raw: r.configTimestamp},
			Snapshot:   &pbgo.TopMeta{Version: uint64(r.configSnapshotVersion), Raw: r.configSnapshot},
			TopTargets: &pbgo.TopMeta{Version: uint64(r.configTargetsVersion), Raw: r.configTargets},
		},
		DirectorMetas: &pbgo.DirectorMetas{
			Roots:     []*pbgo.TopMeta{{Version: uint64(r.directorRootVersion), Raw: r.directorRoot}},
			Timestamp: &pbgo.TopMeta{Version: uint64(r.directorTimestampVersion), Raw: r.directorTimestamp},
			Snapshot:  &pbgo.TopMeta{Version: uint64(r.directorSnapshotVersion), Raw: r.directorSnapshot},
			Targets:   &pbgo.TopMeta{Version: uint64(r.directorTargetsVersion), Raw: r.directorTargets},
		},
		TargetFiles: r.targetFiles,
	}
}

func generateRoot(key *sign.PrivateKey, version int, timestampKey *sign.PrivateKey, targetsKey *sign.PrivateKey, snapshotKey *sign.PrivateKey) []byte {
	root := data.NewRoot()
	root.Version = version
	root.Expires = time.Now().Add(1 * time.Hour)
	root.AddKey(key.PublicData())
	root.AddKey(timestampKey.PublicData())
	root.AddKey(targetsKey.PublicData())
	root.AddKey(snapshotKey.PublicData())
	root.Roles["root"] = &data.Role{
		KeyIDs:    key.PublicData().IDs(),
		Threshold: 1,
	}
	root.Roles["timestamp"] = &data.Role{
		KeyIDs:    timestampKey.PublicData().IDs(),
		Threshold: 1,
	}
	root.Roles["targets"] = &data.Role{
		KeyIDs:    targetsKey.PublicData().IDs(),
		Threshold: 1,
	}
	root.Roles["snapshot"] = &data.Role{
		KeyIDs:    snapshotKey.PublicData().IDs(),
		Threshold: 1,
	}
	signedRoot, _ := sign.Marshal(&root, key.Signer())
	serializedRoot, _ := json.Marshal(signedRoot)
	return serializedRoot
}

func generateTimestamp(key *sign.PrivateKey, version int, snapshotVersion int, snapshot []byte) []byte {
	meta := data.NewTimestamp()
	meta.Expires = time.Now().Add(1 * time.Hour)
	meta.Version = version
	meta.Meta["snapshot.json"] = data.TimestampFileMeta{Version: snapshotVersion, FileMeta: data.FileMeta{Length: int64(len(snapshot)), Hashes: data.Hashes{
		"sha256": hashSha256(snapshot),
	}}}
	signed, _ := sign.Marshal(&meta, key.Signer())
	serialized, _ := json.Marshal(signed)
	return serialized
}

func generateTargets(key *sign.PrivateKey, version int, targets data.TargetFiles) []byte {
	meta := data.NewTargets()
	meta.Expires = time.Now().Add(1 * time.Hour)
	meta.Version = version
	meta.Targets = targets
	signed, _ := sign.Marshal(&meta, key.Signer())
	serialized, _ := json.Marshal(signed)
	return serialized
}

func generateSnapshot(key *sign.PrivateKey, version int, targetsVersion int) []byte {
	meta := data.NewSnapshot()
	meta.Expires = time.Now().Add(1 * time.Hour)
	meta.Version = version
	meta.Meta["targets.json"] = data.SnapshotFileMeta{Version: targetsVersion}

	signed, _ := sign.Marshal(&meta, key.Signer())
	serialized, _ := json.Marshal(signed)
	return serialized
}

func hashSha256(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

func generateTarget() ([]byte, data.TargetFileMeta) {
	file := make([]byte, 128)
	rand.Read(file)
	return file, data.TargetFileMeta{
		FileMeta: data.FileMeta{
			Length: int64(len(file)),
			Hashes: data.Hashes{
				"sha256": hashSha256(file),
			},
		},
	}
}
