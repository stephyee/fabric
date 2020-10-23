/*
Copyright IBM Corp. 2016 All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package fileledger

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hyperledger/fabric/common/ledger/blockledger/fileledger/mock"
	"github.com/hyperledger/fabric/common/metrics/disabled"
	"github.com/hyperledger/fabric/orderer/common/filerepo"
	"github.com/stretchr/testify/require"
)

//go:generate counterfeiter -o mock/file_ledger_block_store.go --fake-name FileLedgerBlockStore . fileLedgerBlockStore

type fileLedgerBlockStore interface {
	FileLedgerBlockStore
}

func TestBlockStoreProviderErrors(t *testing.T) {
	setup := func() (*fileLedgerFactory, *mock.BlockStoreProvider) {
		m := &mock.BlockStoreProvider{}

		f := &fileLedgerFactory{
			blkstorageProvider: m,
			ledgers:            map[string]*FileLedger{},
		}
		return f, m
	}

	t.Run("list", func(t *testing.T) {
		f, mockBlockStoreProvider := setup()
		mockBlockStoreProvider.ListReturns(nil, errors.New("boogie"))
		require.PanicsWithValue(
			t,
			"boogie",
			func() { f.ChannelIDs() },
			"Expected ChannelIDs to panic if storage provider cannot list channel IDs",
		)
	})

	t.Run("open", func(t *testing.T) {
		f, mockBlockStoreProvider := setup()
		mockBlockStoreProvider.OpenReturns(nil, errors.New("woogie"))
		_, err := f.GetOrCreate("foo")
		require.EqualError(t, err, "woogie")
		require.Empty(t, f.ledgers, "Expected no new ledger is created")
	})
}

func TestMultiReinitialization(t *testing.T) {
	metricsProvider := &disabled.Provider{}

	dir, err := ioutil.TempDir("", "fileledger")
	require.NoError(t, err, "Error creating temp dir: %s", err)
	defer os.RemoveAll(dir)

	f, err := New(dir, metricsProvider)
	require.NoError(t, err)
	_, err = f.GetOrCreate("testchannelid")
	require.NoError(t, err, "Error GetOrCreate channel")
	require.Equal(t, 1, len(f.ChannelIDs()), "Expected 1 channel")
	f.Close()

	f, err = New(dir, metricsProvider)
	require.NoError(t, err)
	_, err = f.GetOrCreate("foo")
	require.NoError(t, err, "Error creating channel")
	require.Equal(t, 2, len(f.ChannelIDs()), "Expected channel to be recovered")
	f.Close()

	f, err = New(dir, metricsProvider)
	require.NoError(t, err)
	_, err = f.GetOrCreate("bar")
	require.NoError(t, err, "Error creating channel")
	require.Equal(t, 3, len(f.ChannelIDs()), "Expected channel to be recovered")
	f.Close()
}

func TestNewErrors(t *testing.T) {
	metricsProvider := &disabled.Provider{}

	t.Run("creation of filerepo fails", func(t *testing.T) {
		dir, err := ioutil.TempDir("", "fileledger")
		require.NoError(t, err, "Error creating temp dir: %s", err)
		defer os.RemoveAll(dir)

		fileRepoDir := filepath.Join(dir, "filerepo", "remove")
		err = os.MkdirAll(fileRepoDir, 0700)
		require.NoError(t, err, "Error creating temp dir: %s", err)
		removeFile := filepath.Join(fileRepoDir, "rojo.remove")
		_, err = os.Create(removeFile)
		require.NoError(t, err, "Error creating temp file: %s", err)
		err = os.Chmod(removeFile, 0444)
		err = os.Chmod(filepath.Join(dir, "filerepo", "remove"), 0444)
		require.NoError(t, err, "Error changing permissions of temp file: %s", err)

		_, err = New(dir, metricsProvider)
		require.EqualError(t, err, fmt.Sprintf("error checking if dir [%s] is empty: lstat %s: permission denied", fileRepoDir, removeFile))
	})
}

func TestRemove(t *testing.T) {
	dir, err := ioutil.TempDir("", "fileledger")
	require.NoError(t, err, "Error creating temp dir: %s", err)
	defer os.RemoveAll(dir)

	metricsProvider := &disabled.Provider{}
	f, err := New(dir, metricsProvider)
	require.NoError(t, err)
	defer f.Close()

	t.Run("success", func(t *testing.T) {
		_, err = f.GetOrCreate("foo")
		require.NoError(t, err, "Error creating channel")
		require.Equal(t, 1, len(f.ChannelIDs()), "Expected 1 channel to exist")
		dest := filepath.Join(dir, "filerepo", "remove", "foo.remove")
		err = f.Remove("foo", func(string) {})
		require.NoError(t, err, "Error removing channel")

		_, err = os.Stat(dest)
		require.EqualError(t, err, fmt.Sprintf("stat %s: no such file or directory", dest))
	})

	t.Run("ledger doesn't exist", func(t *testing.T) {
		err := f.Remove("ree", func(string) {})
		require.NoError(t, err)

		require.NotContains(t, f.ChannelIDs(), "ree")
	})
}

func TestRemoveErrors(t *testing.T) {
	mockBlockStore := &mock.BlockStoreProvider{}
	dir, err := ioutil.TempDir("", "fileledger")
	require.NoError(t, err, "Error creating temp dir: %s", err)
	defer os.RemoveAll(dir)

	fileRepo, err := filerepo.New(filepath.Join(dir, "filerepo"), "remove")
	require.NoError(t, err, "Error creating temp file repo: %s", err)
	f := &fileLedgerFactory{
		blkstorageProvider: mockBlockStore,
		ledgers:            map[string]*FileLedger{},
		removeFileRepo:     fileRepo,
	}
	defer f.Close()

	t.Run("drop the blockstore fails", func(t *testing.T) {
		mockBlockStore.DropReturns(errors.New("oogie"))
		err = f.Remove("foo", func(string) {})
		require.NoError(t, err, "Expected no error")
		require.Eventually(t, func() bool { return mockBlockStore.DropCallCount() == 1 }, time.Minute, time.Second)
	})

	t.Run("saving to file repo fails", func(t *testing.T) {
		os.RemoveAll(dir)
		err = f.Remove("foo", func(string) {})
		require.EqualError(t, err, fmt.Sprintf("error while creating file:%s/filerepo/remove/foo.remove~: open %s/filerepo/remove/foo.remove~: no such file or directory", dir, dir))
	})
}
