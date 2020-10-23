// Code generated by counterfeiter. DO NOT EDIT.
package mocks

import (
	"sync"

	"github.com/hyperledger/fabric/common/ledger/blockledger"
)

type Factory struct {
	GetOrCreateStub        func(channelID string) (blockledger.ReadWriter, error)
	getOrCreateMutex       sync.RWMutex
	getOrCreateArgsForCall []struct {
		channelID string
	}
	getOrCreateReturns struct {
		result1 blockledger.ReadWriter
		result2 error
	}
	getOrCreateReturnsOnCall map[int]struct {
		result1 blockledger.ReadWriter
		result2 error
	}
	RemoveStub        func(channelID string, finishRemove func(string, bool)) error
	removeMutex       sync.RWMutex
	removeArgsForCall []struct {
		channelID    string
		finishRemove func(string, bool)
	}
	removeReturns struct {
		result1 error
	}
	removeReturnsOnCall map[int]struct {
		result1 error
	}
	ChannelIDsStub        func() []string
	channelIDsMutex       sync.RWMutex
	channelIDsArgsForCall []struct{}
	channelIDsReturns     struct {
		result1 []string
	}
	channelIDsReturnsOnCall map[int]struct {
		result1 []string
	}
	CloseStub        func()
	closeMutex       sync.RWMutex
	closeArgsForCall []struct{}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *Factory) GetOrCreate(channelID string) (blockledger.ReadWriter, error) {
	fake.getOrCreateMutex.Lock()
	ret, specificReturn := fake.getOrCreateReturnsOnCall[len(fake.getOrCreateArgsForCall)]
	fake.getOrCreateArgsForCall = append(fake.getOrCreateArgsForCall, struct {
		channelID string
	}{channelID})
	fake.recordInvocation("GetOrCreate", []interface{}{channelID})
	fake.getOrCreateMutex.Unlock()
	if fake.GetOrCreateStub != nil {
		return fake.GetOrCreateStub(channelID)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	return fake.getOrCreateReturns.result1, fake.getOrCreateReturns.result2
}

func (fake *Factory) GetOrCreateCallCount() int {
	fake.getOrCreateMutex.RLock()
	defer fake.getOrCreateMutex.RUnlock()
	return len(fake.getOrCreateArgsForCall)
}

func (fake *Factory) GetOrCreateArgsForCall(i int) string {
	fake.getOrCreateMutex.RLock()
	defer fake.getOrCreateMutex.RUnlock()
	return fake.getOrCreateArgsForCall[i].channelID
}

func (fake *Factory) GetOrCreateReturns(result1 blockledger.ReadWriter, result2 error) {
	fake.GetOrCreateStub = nil
	fake.getOrCreateReturns = struct {
		result1 blockledger.ReadWriter
		result2 error
	}{result1, result2}
}

func (fake *Factory) GetOrCreateReturnsOnCall(i int, result1 blockledger.ReadWriter, result2 error) {
	fake.GetOrCreateStub = nil
	if fake.getOrCreateReturnsOnCall == nil {
		fake.getOrCreateReturnsOnCall = make(map[int]struct {
			result1 blockledger.ReadWriter
			result2 error
		})
	}
	fake.getOrCreateReturnsOnCall[i] = struct {
		result1 blockledger.ReadWriter
		result2 error
	}{result1, result2}
}

func (fake *Factory) Remove(channelID string, finishRemove func(string, bool)) error {
	fake.removeMutex.Lock()
	ret, specificReturn := fake.removeReturnsOnCall[len(fake.removeArgsForCall)]
	fake.removeArgsForCall = append(fake.removeArgsForCall, struct {
		channelID    string
		finishRemove func(string, bool)
	}{channelID, finishRemove})
	fake.recordInvocation("Remove", []interface{}{channelID, finishRemove})
	fake.removeMutex.Unlock()
	if fake.RemoveStub != nil {
		return fake.RemoveStub(channelID, finishRemove)
	}
	if specificReturn {
		return ret.result1
	}
	return fake.removeReturns.result1
}

func (fake *Factory) RemoveCallCount() int {
	fake.removeMutex.RLock()
	defer fake.removeMutex.RUnlock()
	return len(fake.removeArgsForCall)
}

func (fake *Factory) RemoveArgsForCall(i int) (string, func(string, bool)) {
	fake.removeMutex.RLock()
	defer fake.removeMutex.RUnlock()
	return fake.removeArgsForCall[i].channelID, fake.removeArgsForCall[i].finishRemove
}

func (fake *Factory) RemoveReturns(result1 error) {
	fake.RemoveStub = nil
	fake.removeReturns = struct {
		result1 error
	}{result1}
}

func (fake *Factory) RemoveReturnsOnCall(i int, result1 error) {
	fake.RemoveStub = nil
	if fake.removeReturnsOnCall == nil {
		fake.removeReturnsOnCall = make(map[int]struct {
			result1 error
		})
	}
	fake.removeReturnsOnCall[i] = struct {
		result1 error
	}{result1}
}

func (fake *Factory) ChannelIDs() []string {
	fake.channelIDsMutex.Lock()
	ret, specificReturn := fake.channelIDsReturnsOnCall[len(fake.channelIDsArgsForCall)]
	fake.channelIDsArgsForCall = append(fake.channelIDsArgsForCall, struct{}{})
	fake.recordInvocation("ChannelIDs", []interface{}{})
	fake.channelIDsMutex.Unlock()
	if fake.ChannelIDsStub != nil {
		return fake.ChannelIDsStub()
	}
	if specificReturn {
		return ret.result1
	}
	return fake.channelIDsReturns.result1
}

func (fake *Factory) ChannelIDsCallCount() int {
	fake.channelIDsMutex.RLock()
	defer fake.channelIDsMutex.RUnlock()
	return len(fake.channelIDsArgsForCall)
}

func (fake *Factory) ChannelIDsReturns(result1 []string) {
	fake.ChannelIDsStub = nil
	fake.channelIDsReturns = struct {
		result1 []string
	}{result1}
}

func (fake *Factory) ChannelIDsReturnsOnCall(i int, result1 []string) {
	fake.ChannelIDsStub = nil
	if fake.channelIDsReturnsOnCall == nil {
		fake.channelIDsReturnsOnCall = make(map[int]struct {
			result1 []string
		})
	}
	fake.channelIDsReturnsOnCall[i] = struct {
		result1 []string
	}{result1}
}

func (fake *Factory) Close() {
	fake.closeMutex.Lock()
	fake.closeArgsForCall = append(fake.closeArgsForCall, struct{}{})
	fake.recordInvocation("Close", []interface{}{})
	fake.closeMutex.Unlock()
	if fake.CloseStub != nil {
		fake.CloseStub()
	}
}

func (fake *Factory) CloseCallCount() int {
	fake.closeMutex.RLock()
	defer fake.closeMutex.RUnlock()
	return len(fake.closeArgsForCall)
}

func (fake *Factory) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.getOrCreateMutex.RLock()
	defer fake.getOrCreateMutex.RUnlock()
	fake.removeMutex.RLock()
	defer fake.removeMutex.RUnlock()
	fake.channelIDsMutex.RLock()
	defer fake.channelIDsMutex.RUnlock()
	fake.closeMutex.RLock()
	defer fake.closeMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *Factory) recordInvocation(key string, args []interface{}) {
	fake.invocationsMutex.Lock()
	defer fake.invocationsMutex.Unlock()
	if fake.invocations == nil {
		fake.invocations = map[string][][]interface{}{}
	}
	if fake.invocations[key] == nil {
		fake.invocations[key] = [][]interface{}{}
	}
	fake.invocations[key] = append(fake.invocations[key], args)
}
