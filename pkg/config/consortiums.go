/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package config

import (
	"fmt"

	"github.com/hyperledger/fabric-protos-go/common"
	"github.com/hyperledger/fabric-protos-go/msp"
)

// AcceptAllPolicy always evaluates to true
var AcceptAllPolicy *common.SignaturePolicyEnvelope

// Consortium represents a group of organizations which may create channels
// with each other
type Consortium struct {
	Organizations []*Organization
}

// ConfigPolicy defines a common representation for different ConfigPolicy values
type ConfigPolicy interface {
	// Key is the key this value should be stored in the *common.ConfigGroup.Policies map.
	Key() string

	// Value is the backing policy implementation for this ConfigPolicy
	Value() *common.Policy
}

// Consortiums

// NewConsortiumsGroup returns the consortiums component of the channel configuration.  This element is only defined for the ordering system channel.
// It sets the mod_policy for all elements to "/Channel/Orderer/Admins".
func NewConsortiumsGroup(conf map[string]*Consortium, mspConfig *msp.MSPConfig) (*common.ConfigGroup, error) {
	consortiumsGroup := newConfigGroup()

	// QUESTION: How should we set this? the original impl did it globally...
	AcceptAllPolicy = envelope(nOutOf(0, []*common.SignaturePolicy{}), [][]byte{})
	// This policy is not referenced anywhere, it is only used as part of the implicit meta policy rule at the channel level, so this setting
	// effectively degrades control of the ordering system channel to the ordering admins
	addPolicy(consortiumsGroup, signaturePolicy(AdminsPolicyKey, AcceptAllPolicy), ordererAdminsPolicyName)

	for consortiumName, consortium := range conf {
		var err error
		consortiumsGroup.Groups[consortiumName], err = newConsortiumGroup(consortium, mspConfig)
		if err != nil {
			return nil, err
		}
	}

	consortiumsGroup.ModPolicy = ordererAdminsPolicyName
	return consortiumsGroup, nil
}

// NewConsortiumGroup returns a consortiums component of the channel configuration.
func newConsortiumGroup(conf *Consortium, mspConfig *msp.MSPConfig) (*common.ConfigGroup, error) {
	consortiumGroup := newConfigGroup()

	for _, org := range conf.Organizations {
		var err error
		consortiumGroup.Groups[org.Name], err = newConsortiumOrgGroup(org, mspConfig)
		if err != nil {
			return nil, err
		}
	}

	addValue(consortiumGroup, channelCreationPolicyValue(implicitMetaAnyPolicy(AdminsPolicyKey).Value()), ordererAdminsPolicyName)

	consortiumGroup.ModPolicy = ordererAdminsPolicyName
	return consortiumGroup, nil
}

// NewConsortiumOrgGroup returns an org component of the channel configuration.  It defines the crypto material for the
// organization (its MSP).  It sets the mod_policy of all elements to "Admins".
func newConsortiumOrgGroup(conf *Organization, mspConfig *msp.MSPConfig) (*common.ConfigGroup, error) {
	consortiumOrgGroup := newConfigGroup()
	consortiumOrgGroup.ModPolicy = AdminsPolicyKey

	if conf.SkipAsForeign {
		return consortiumOrgGroup, nil
	}

	if err := addPolicies(consortiumOrgGroup, conf.Policies, AdminsPolicyKey); err != nil {
		return nil, fmt.Errorf("error adding policies to consortium org group %s: %v", conf.Name, err)
	}

	addValue(consortiumOrgGroup, mspValue(mspConfig), AdminsPolicyKey)

	return consortiumOrgGroup, nil
}

// ConsortiumValue returns the config definition for the consortium name.
// It is a value for the channel group.
func consortiumValue(name string) *StandardConfigValue {
	return &StandardConfigValue{
		key: ConsortiumKey,
		value: &common.Consortium{
			Name: name,
		},
	}
}

// ChannelCreationPolicyValue returns the config definition for a consortium's channel creation policy
// It is a value for the /Channel/Consortiums/*/*.
func channelCreationPolicyValue(policy *common.Policy) *StandardConfigValue {
	return &StandardConfigValue{
		key:   ChannelCreationPolicyKey,
		value: policy,
	}
}

// Envelope builds an envelope message embedding a SignaturePolicy
func envelope(policy *common.SignaturePolicy, identities [][]byte) *common.SignaturePolicyEnvelope {
	ids := make([]*msp.MSPPrincipal, len(identities))
	for i := range ids {
		ids[i] = &msp.MSPPrincipal{PrincipalClassification: msp.MSPPrincipal_IDENTITY, Principal: identities[i]}
	}

	return &common.SignaturePolicyEnvelope{
		Version:    0,
		Rule:       policy,
		Identities: ids,
	}
}

// nOutOf creates a policy which requires N out of the slice of policies to evaluate to true
func nOutOf(n int32, policies []*common.SignaturePolicy) *common.SignaturePolicy {
	return &common.SignaturePolicy{
		Type: &common.SignaturePolicy_NOutOf_{
			NOutOf: &common.SignaturePolicy_NOutOf{
				N:     n,
				Rules: policies,
			},
		},
	}
}

func addPolicy(cg *common.ConfigGroup, policy ConfigPolicy, modPolicy string) {
	cg.Policies[policy.Key()] = &common.ConfigPolicy{
		Policy:    policy.Value(),
		ModPolicy: modPolicy,
	}
}

// SignaturePolicy defines a policy with key policyName and the given signature policy.
func signaturePolicy(policyName string, sigPolicy *common.SignaturePolicyEnvelope) *StandardConfigPolicy {
	return &StandardConfigPolicy{
		key: policyName,
		value: &common.Policy{
			Type:  int32(common.Policy_SIGNATURE),
			Value: protoMarshalOrPanic(sigPolicy),
		},
	}
}
