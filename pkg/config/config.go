/*
Copyright IBM Corp. All Rights Reserved

SPDX-License-Identifier: Apache-2.0
*/

package config

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes/timestamp"

	cb "github.com/hyperledger/fabric-protos-go/common"
	mb "github.com/hyperledger/fabric-protos-go/msp"
)

// Profile encapsulates basic information for a channel config profile
type Profile struct {
	Consortium   string
	Application  *Application
	Orderer      *Orderer
	Consortiums  map[string]*Consortium
	Capabilities map[string]bool
	Policies     map[string]*Policy
	ChannelID    string
}

// Policy encodes a channel config policy
type Policy struct {
	Type string
	Rule string
}

// Resources encodes the application-level resources configuration needed to
// seed the resource tree
type Resources struct {
	DefaultModPolicy string
}

// Organization encodes the organization-level configuration needed in
// config transactions
type Organization struct {
	Name     string
	ID       string
	MSPDir   string
	MSPType  string
	Policies map[string]*Policy

	AnchorPeers      []*AnchorPeer
	OrdererEndpoints []string

	// SkipAsForeign indicates that this org definition is actually unknown to this
	// instance of the tool, so, parsing of this org's parameters should be ignored
	SkipAsForeign bool
}

type BatchSize struct {
	MaxMessageCount   uint32
	AbsoluteMaxBytes  uint32
	PreferredMaxBytes uint32
}

// Kafka contains configuration for the Kafka-based orderer
type Kafka struct {
	Brokers []string
}

// StandardConfigPolicy ...
type StandardConfigPolicy struct {
	key   string
	value *cb.Policy
}

// Key is the key this value should be stored in the *cb.ConfigGroup.Values map
func (scv *StandardConfigPolicy) Key() string {
	return scv.key
}

// Value is the *cb.Policy which should be stored as the *cb.ConfigPolicy.Policy
func (scv *StandardConfigPolicy) Value() *cb.Policy {
	return scv.value
}

// CreateChannelTx creates a create channel tx using the provided config
func CreateChannelTx(profile *Profile, mspConfig *mb.FabricMSPConfig) (*cb.Envelope, error) {
	var err error

	if profile == nil {
		return nil, errors.New("profile is empty")
	}

	channelID := profile.ChannelID

	if channelID == "" {
		return nil, errors.New("channel ID is empty")
	}

	// mspconf defaults type to FABRIC which implements an X.509 based provider
	mspconf := &mb.MSPConfig{
		Config: protoMarshalOrPanic(mspConfig),
	}

	ct, err := defaultConfigTemplate(profile, mspconf)
	if err != nil {
		return nil, fmt.Errorf("failed to create default config template: %v", err)
	}

	newChannelConfigUpdate, err := newChannelCreateConfigUpdate(channelID, profile, ct, mspconf)
	if err != nil {
		return nil, fmt.Errorf("failed to create channel create config update: %v", err)
	}

	newConfigUpdateEnv := &cb.ConfigUpdateEnvelope{
		ConfigUpdate: protoMarshalOrPanic(newChannelConfigUpdate),
	}

	env, err := createEnvelope(cb.HeaderType_CONFIG_UPDATE, channelID, newConfigUpdateEnv)
	if err != nil {
		return nil, fmt.Errorf("failed to create envelope: %v", err)
	}

	return env, nil
}

// protoMarshalOrPanic serializes a protobuf message and panics if this
// operation fails
func protoMarshalOrPanic(pb proto.Message) []byte {
	data, err := proto.Marshal(pb)
	if err != nil {
		panic(err)
	}

	return data
}

// makeChannelHeader creates a ChannelHeader
func makeChannelHeader(headerType cb.HeaderType, version int32, channelID string, epoch uint64) *cb.ChannelHeader {
	return &cb.ChannelHeader{
		Type:    int32(headerType),
		Version: version,
		Timestamp: &timestamp.Timestamp{
			Seconds: time.Now().Unix(),
			Nanos:   0,
		},
		ChannelId: channelID,
		Epoch:     epoch,
	}
}

// makePayloadHeader creates a Payload Header
func makePayloadHeader(ch *cb.ChannelHeader, sh *cb.SignatureHeader) *cb.Header {
	return &cb.Header{
		ChannelHeader:   protoMarshalOrPanic(ch),
		SignatureHeader: protoMarshalOrPanic(sh),
	}
}

// newConfigGroup creates an empty *cb.ConfigGroup
func newConfigGroup() *cb.ConfigGroup {
	return &cb.ConfigGroup{
		Groups:   make(map[string]*cb.ConfigGroup),
		Values:   make(map[string]*cb.ConfigValue),
		Policies: make(map[string]*cb.ConfigPolicy),
	}
}

// StandardConfigValue implements the ConfigValue interface
type StandardConfigValue struct {
	key   string
	value proto.Message
}

// Key is the key this value should be stored in the *cb.ConfigGroup.Values map
func (scv *StandardConfigValue) Key() string {
	return scv.key
}

// Value is the message which should be marshaled to opaque bytes for the *cb.ConfigValue.value
func (scv *StandardConfigValue) Value() proto.Message {
	return scv.value
}

// newChannelGroup defines the root of the channel configuration
func newChannelGroup(conf *Profile, mspConfig *mb.MSPConfig) (*cb.ConfigGroup, error) {
	var err error

	channelGroup := newConfigGroup()

	if err = addPolicies(channelGroup, conf.Policies, AdminsPolicyKey); err != nil {
		return nil, fmt.Errorf("error adding policies: %v", err)
	}

	addValue(channelGroup, hashingAlgorithmValue(), AdminsPolicyKey)
	addValue(channelGroup, blockDataHashingStructureValue(), AdminsPolicyKey)
	if conf.Orderer != nil && len(conf.Orderer.Addresses) > 0 {
		addValue(channelGroup, ordererAddressesValue(conf.Orderer.Addresses), ordererAdminsPolicyName)
	}

	if conf.Consortium != "" {
		addValue(channelGroup, consortiumValue(conf.Consortium), AdminsPolicyKey)
	}

	if len(conf.Capabilities) > 0 {
		addValue(channelGroup, capabilitiesValue(conf.Capabilities), AdminsPolicyKey)
	}

	if conf.Orderer != nil {
		channelGroup.Groups[OrdererGroupKey], err = NewOrdererGroup(conf.Orderer, mspConfig)
		if err != nil {
			return nil, fmt.Errorf("could not create orderer group: %v", err)
		}
	}

	if conf.Application != nil {
		channelGroup.Groups[ApplicationGroupKey], err = NewApplicationGroup(conf.Application, mspConfig)
		if err != nil {
			return nil, fmt.Errorf("could not create application group: %v", err)
		}
	}

	if conf.Consortiums != nil {
		channelGroup.Groups[ConsortiumsGroupKey], err = NewConsortiumsGroup(conf.Consortiums, mspConfig)
		if err != nil {
			return nil, fmt.Errorf("could not create consortiums group: %v", err)
		}
	}

	channelGroup.ModPolicy = AdminsPolicyKey

	return channelGroup, nil
}

// hashingAlgorithmValue returns the only currently valid hashing algorithm
// It is a value for the /Channel group
func hashingAlgorithmValue() *StandardConfigValue {
	return &StandardConfigValue{
		key: HashingAlgorithmKey,
		value: &cb.HashingAlgorithm{
			Name: defaultHashingAlgorithm,
		},
	}
}

// blockDataHashingStructureValue returns the only currently valid block data hashing structure
// It is a value for the /Channel group
func blockDataHashingStructureValue() *StandardConfigValue {
	return &StandardConfigValue{
		key: BlockDataHashingStructureKey,
		value: &cb.BlockDataHashingStructure{
			Width: defaultBlockDataHashingStructureWidth,
		},
	}
}

// addValue adds a *cb.ConfigValue to the passed *cb.ConfigGroup's Values map
func addValue(cg *cb.ConfigGroup, value *StandardConfigValue, modPolicy string) {
	cg.Values[value.Key()] = &cb.ConfigValue{
		Value:     protoMarshalOrPanic(value.Value()),
		ModPolicy: modPolicy,
	}
}

// addPolicies adds *cb.ConfigPolicies to the passed *cb.ConfigGroup's Policies map
func addPolicies(cg *cb.ConfigGroup, policyMap map[string]*Policy, modPolicy string) error {
	switch {
	case policyMap == nil:
		return errors.New("no policies defined")
	case policyMap[AdminsPolicyKey] == nil:
		return errors.New("no Admins policy defined")
	case policyMap[ReadersPolicyKey] == nil:
		return errors.New("no Readers policy defined")
	case policyMap[WritersPolicyKey] == nil:
		return errors.New("no Writers policy defined")
	}

	for policyName, policy := range policyMap {
		switch policy.Type {
		case ImplicitMetaPolicyType:
			imp, err := implicitMetaFromString(policy.Rule)
			if err != nil {
				return fmt.Errorf("invalid implicit meta policy rule: '%s' error: %v", policy.Rule, err)
			}

			cg.Policies[policyName] = &cb.ConfigPolicy{
				ModPolicy: modPolicy,
				Policy: &cb.Policy{
					Type:  int32(cb.Policy_IMPLICIT_META),
					Value: protoMarshalOrPanic(imp),
				},
			}
		case SignaturePolicyType:
			sp, err := FromString(policy.Rule)
			if err != nil {
				return fmt.Errorf("invalid signature policy rule '%s' error: %v", policy.Rule, err)
			}

			cg.Policies[policyName] = &cb.ConfigPolicy{
				ModPolicy: modPolicy,
				Policy: &cb.Policy{
					Type:  int32(cb.Policy_SIGNATURE),
					Value: protoMarshalOrPanic(sp),
				},
			}
		default:
			return fmt.Errorf("unknown policy type: %s", policy.Type)
		}
	}

	return nil
}

// implicitMetaFromString parses a *cb.ImplicitMetaPolicy from an input string
func implicitMetaFromString(input string) (*cb.ImplicitMetaPolicy, error) {
	args := strings.Split(input, " ")
	if len(args) != 2 {
		return nil, fmt.Errorf("expected two space separated tokens, but got %d", len(args))
	}

	res := &cb.ImplicitMetaPolicy{
		SubPolicy: args[1],
	}

	switch args[0] {
	case cb.ImplicitMetaPolicy_ANY.String():
		res.Rule = cb.ImplicitMetaPolicy_ANY
	case cb.ImplicitMetaPolicy_ALL.String():
		res.Rule = cb.ImplicitMetaPolicy_ALL
	case cb.ImplicitMetaPolicy_MAJORITY.String():
		res.Rule = cb.ImplicitMetaPolicy_MAJORITY
	default:
		return nil, fmt.Errorf("unknown rule type '%s', expected ALL, ANY, or MAJORITY", args[0])
	}

	return res, nil
}

// ordererAddressesValue returns the a config definition for the orderer addresses
// It is a value for the /Channel group
func ordererAddressesValue(addresses []string) *StandardConfigValue {
	return &StandardConfigValue{
		key: OrdererAddressesKey,
		value: &cb.OrdererAddresses{
			Addresses: addresses,
		},
	}
}

// capabilitiesValue returns the config definition for a a set of capabilities
// It is a value for the /Channel/Orderer, Channel/Application/, and /Channel groups
func capabilitiesValue(capabilities map[string]bool) *StandardConfigValue {
	c := &cb.Capabilities{
		Capabilities: make(map[string]*cb.Capability),
	}

	for capability, required := range capabilities {
		if !required {
			continue
		}

		c.Capabilities[capability] = &cb.Capability{}
	}

	return &StandardConfigValue{
		key:   CapabilitiesKey,
		value: c,
	}
}

// mspValue returns the config definition for an MSP
// It is a value for the /Channel/Orderer/*, /Channel/Application/*, and /Channel/Consortiums/*/*/* groups
func mspValue(mspDef *mb.MSPConfig) *StandardConfigValue {
	return &StandardConfigValue{
		key:   MSPKey,
		value: mspDef,
	}
}

// makeImplicitMetaPolicy creates a new *cb.Policy of cb.Policy_IMPLICIT_META type
func makeImplicitMetaPolicy(subPolicyName string, rule cb.ImplicitMetaPolicy_Rule) *cb.Policy {
	return &cb.Policy{
		Type: int32(cb.Policy_IMPLICIT_META),
		Value: protoMarshalOrPanic(&cb.ImplicitMetaPolicy{
			Rule:      rule,
			SubPolicy: subPolicyName,
		}),
	}
}

// implicitMetaAnyPolicy defines an implicit meta policy whose sub_policy and key is policyname with rule ANY
func implicitMetaAnyPolicy(policyName string) *StandardConfigPolicy {
	return &StandardConfigPolicy{
		key:   policyName,
		value: makeImplicitMetaPolicy(policyName, cb.ImplicitMetaPolicy_ANY),
	}
}

// defaultConfigTemplate generates a config template based on the assumption that
// the input profile is a channel creation template and no system channel context
// is available
func defaultConfigTemplate(conf *Profile, mspConfig *mb.MSPConfig) (*cb.ConfigGroup, error) {
	channelGroup, err := newChannelGroup(conf, mspConfig)
	if err != nil {
		return nil, fmt.Errorf("could not create new channel group: %v", err)
	}

	if _, ok := channelGroup.Groups[ApplicationGroupKey]; !ok {
		return nil, errors.New("channel template config must contain an application section")
	}

	channelGroup.Groups[ApplicationGroupKey].Values = nil
	channelGroup.Groups[ApplicationGroupKey].Policies = nil

	return channelGroup, nil
}

// newChannelCreateConfigUpdate generates a ConfigUpdate which can be sent to the orderer to create a new channel
// Optionally, the channel group of the ordering system channel may be passed in, and the resulting ConfigUpdate
// will extract the appropriate versions from this file
func newChannelCreateConfigUpdate(channelID string, conf *Profile, templateConfig *cb.ConfigGroup, mspConfig *mb.MSPConfig) (*cb.ConfigUpdate, error) {
	newChannelGroup, err := newChannelGroup(conf, mspConfig)
	if err != nil {
		return nil, fmt.Errorf("could not create new channel group: %v", err)
	}

	updt, err := Compute(&cb.Config{ChannelGroup: templateConfig}, &cb.Config{ChannelGroup: newChannelGroup})
	if err != nil {
		return nil, fmt.Errorf("could not compute update: %v", err)
	}

	// Add the consortium name to create the channel for into the write set as required
	updt.ChannelId = channelID
	updt.ReadSet.Values[ConsortiumKey] = &cb.ConfigValue{Version: 0}
	updt.WriteSet.Values[ConsortiumKey] = &cb.ConfigValue{
		Version: 0,
		Value: protoMarshalOrPanic(&cb.Consortium{
			Name: conf.Consortium,
		}),
	}

	return updt, nil
}

// createEnvelope creates an unsigned envelope of type txType using with the marshalled
// cb.ConfigGroupEnvelope proto message
func createEnvelope(
	txType cb.HeaderType,
	channelID string,
	dataMsg proto.Message,
) (*cb.Envelope, error) {
	payloadChannelHeader := makeChannelHeader(txType, msgVersion, channelID, epoch)
	payloadSignatureHeader := &cb.SignatureHeader{}

	data, err := proto.Marshal(dataMsg)
	if err != nil {
		return nil, fmt.Errorf("failed marshalling: %v", err)
	}

	paylBytes := protoMarshalOrPanic(
		&cb.Payload{
			Header: makePayloadHeader(payloadChannelHeader, payloadSignatureHeader),
			Data:   data,
		},
	)

	env := &cb.Envelope{
		Payload: paylBytes,
	}

	return env, nil
}
