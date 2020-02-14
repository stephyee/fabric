/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package config

import (
	"fmt"
	"io/ioutil"
	"time"

	"github.com/golang/protobuf/proto"
	cb "github.com/hyperledger/fabric-protos-go/common"
	mb "github.com/hyperledger/fabric-protos-go/msp"
	ob "github.com/hyperledger/fabric-protos-go/orderer"
	eb "github.com/hyperledger/fabric-protos-go/orderer/etcdraft"
)

// Orderer encodes the orderer-level configuration needed in config
// transactions
type Orderer struct {
	OrdererType   string
	Addresses     []string
	BatchTimeout  time.Duration
	BatchSize     BatchSize
	Kafka         Kafka
	EtcdRaft      *eb.ConfigMetadata
	Organizations []*Organization
	MaxChannels   uint64
	Capabilities  map[string]bool
	Policies      map[string]*Policy
}

// NewOrdererGroup returns the orderer component of the channel configuration
// It defines parameters of the ordering service about how large blocks should be,
// how frequently they should be emitted, etc. as well as the organizations of the ordering network
// It sets the mod_policy of all elements to "Admins"
// This group is always present in any channel configuration
func NewOrdererGroup(conf *Orderer, mspConfig *mb.MSPConfig) (*cb.ConfigGroup, error) {
	var (
		err               error
		consensusMetadata []byte
	)

	ordererGroup := newConfigGroup()
	ordererGroup.ModPolicy = AdminsPolicyKey

	if err = addPolicies(ordererGroup, conf.Policies, AdminsPolicyKey); err != nil {
		return nil, fmt.Errorf("error adding policies: %v", err)
	}

	ordererGroup.Policies[BlockValidationPolicyKey] = &cb.ConfigPolicy{
		Policy:    implicitMetaAnyPolicy(WritersPolicyKey).Value(),
		ModPolicy: AdminsPolicyKey,
	}
	addValue(ordererGroup, batchSizeValue(
		conf.BatchSize.MaxMessageCount,
		conf.BatchSize.AbsoluteMaxBytes,
		conf.BatchSize.PreferredMaxBytes,
	), AdminsPolicyKey)
	addValue(ordererGroup, batchTimeoutValue(conf.BatchTimeout.String()), AdminsPolicyKey)
	addValue(ordererGroup, channelRestrictionsValue(conf.MaxChannels), AdminsPolicyKey)

	if len(conf.Capabilities) > 0 {
		addValue(ordererGroup, capabilitiesValue(conf.Capabilities), AdminsPolicyKey)
	}

	switch conf.OrdererType {
	case ConsensusTypeSolo:
	case ConsensusTypeKafka:
		addValue(ordererGroup, kafkaBrokersValue(conf.Kafka.Brokers), AdminsPolicyKey)
	case ConsensusTypeEtcdRaft:
		if conf.EtcdRaft == nil {
			return nil, fmt.Errorf("missing etcdraft metadata for orderer type %s", ConsensusTypeEtcdRaft)
		}

		if consensusMetadata, err = marshalEtcdRaftMetadata(conf.EtcdRaft); err != nil {
			return nil, fmt.Errorf("cannot marshal etcdraft metadata for orderer type %s: %v", ConsensusTypeEtcdRaft, err)
		}
	default:
		return nil, fmt.Errorf("unknown orderer type %s", conf.OrdererType)
	}

	addValue(ordererGroup, consensusTypeValue(conf.OrdererType, consensusMetadata), AdminsPolicyKey)

	for _, org := range conf.Organizations {
		ordererGroup.Groups[org.Name], err = newOrdererOrgGroup(org, mspConfig)
		if err != nil {
			return nil, fmt.Errorf("could not create orderer org group %s: %v", org.Name, err)
		}
	}

	return ordererGroup, nil
}

// newOrdererOrgGroup returns an orderer org component of the channel configuration
// It defines the crypto material for the organization (its MSP)
// It sets the mod_policy of all elements to "Admins"
func newOrdererOrgGroup(conf *Organization, mspConfig *mb.MSPConfig) (*cb.ConfigGroup, error) {
	ordererOrgGroup := newConfigGroup()
	ordererOrgGroup.ModPolicy = AdminsPolicyKey

	if conf.SkipAsForeign {
		return ordererOrgGroup, nil
	}

	if err := addPolicies(ordererOrgGroup, conf.Policies, AdminsPolicyKey); err != nil {
		return nil, fmt.Errorf("error adding policies: %v", err)
	}

	addValue(ordererOrgGroup, mspValue(mspConfig), AdminsPolicyKey)

	if len(conf.OrdererEndpoints) > 0 {
		addValue(ordererOrgGroup, endpointsValue(conf.OrdererEndpoints), AdminsPolicyKey)
	}

	return ordererOrgGroup, nil
}

// batchSizeValue returns the config definition for the orderer batch size
// It is a value for the /Channel/Orderer group
func batchSizeValue(maxMessages, absoluteMaxBytes, preferredMaxBytes uint32) *StandardConfigValue {
	return &StandardConfigValue{
		key: BatchSizeKey,
		value: &ob.BatchSize{
			MaxMessageCount:   maxMessages,
			AbsoluteMaxBytes:  absoluteMaxBytes,
			PreferredMaxBytes: preferredMaxBytes,
		},
	}
}

// batchTimeoutValue returns the config definition for the orderer batch timeout
// It is a value for the /Channel/Orderer group
func batchTimeoutValue(timeout string) *StandardConfigValue {
	return &StandardConfigValue{
		key: BatchTimeoutKey,
		value: &ob.BatchTimeout{
			Timeout: timeout,
		},
	}
}

// endpointsValue returns the config definition for the orderer addresses at an org scoped level
// It is a value for the /Channel/Orderer/<OrgName> group
func endpointsValue(addresses []string) *StandardConfigValue {
	return &StandardConfigValue{
		key: EndpointsKey,
		value: &cb.OrdererAddresses{
			Addresses: addresses,
		},
	}
}

// channelRestrictionsValue returns the config definition for the orderer channel restrictions
// It is a value for the /Channel/Orderer group
func channelRestrictionsValue(maxChannelCount uint64) *StandardConfigValue {
	return &StandardConfigValue{
		key: ChannelRestrictionsKey,
		value: &ob.ChannelRestrictions{
			MaxCount: maxChannelCount,
		},
	}
}

// kafkaBrokersValue returns the config definition for the addresses of the ordering service's Kafka brokers
// It is a value for the /Channel/Orderer group
func kafkaBrokersValue(brokers []string) *StandardConfigValue {
	return &StandardConfigValue{
		key: KafkaBrokersKey,
		value: &ob.KafkaBrokers{
			Brokers: brokers,
		},
	}
}

// marshalEtcdRaftMetadata serializes etcd RAFT metadata
func marshalEtcdRaftMetadata(md *eb.ConfigMetadata) ([]byte, error) {
	var (
		data []byte
		err  error
	)

	copyMd := proto.Clone(md).(*eb.ConfigMetadata)
	for _, c := range copyMd.Consenters {
		// Expect the user to set the config value for client/server certs to the
		// path where they are persisted locally, then load these files to memory.
		clientCert, err := ioutil.ReadFile(string(c.GetClientTlsCert()))
		if err != nil {
			return nil, fmt.Errorf("cannot load client cert for consenter %s:%d: %v", c.GetHost(), c.GetPort(), err)
		}
		c.ClientTlsCert = clientCert

		serverCert, err := ioutil.ReadFile(string(c.GetServerTlsCert()))
		if err != nil {
			return nil, fmt.Errorf("cannot load server cert for consenter %s:%d: %v", c.GetHost(), c.GetPort(), err)
		}
		c.ServerTlsCert = serverCert
	}

	data, err = proto.Marshal(copyMd)
	if err != nil {
		return nil, fmt.Errorf("failed marshalling: %v", err)
	}

	return data, nil
}

// consensusTypeValue returns the config definition for the orderer consensus type
// It is a value for the /Channel/Orderer group
func consensusTypeValue(consensusType string, consensusMetadata []byte) *StandardConfigValue {
	return &StandardConfigValue{
		key: ConsensusTypeKey,
		value: &ob.ConsensusType{
			Type:     consensusType,
			Metadata: consensusMetadata,
		},
	}
}
