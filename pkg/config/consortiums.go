/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package config

import (
	"fmt"

	cb "github.com/hyperledger/fabric-protos-go/common"
	mb "github.com/hyperledger/fabric-protos-go/msp"
)

// Consortium represents a group of organizations which may create channels
// with each other
type Consortium struct {
	Organizations []*Organization
}

// ConfigPolicy defines a common representation for different ConfigPolicy values
type ConfigPolicy interface {
	// Key is the key this value should be stored in the *cb.ConfigGroup.Policies map
	Key() string

	// Value is the backing policy implementation for this ConfigPolicy
	Value() *cb.Policy
}

// NewConsortiumsGroup returns the consortiums component of the channel configuration.  This element is only defined for the ordering system channel
// It sets the mod_policy for all elements to "/Channel/Orderer/Admins"
func NewConsortiumsGroup(conf map[string]*Consortium, mspConfig *mb.MSPConfig) (*cb.ConfigGroup, error) {
	var err error

	consortiumsGroup := newConfigGroup()

	// acceptAllPolicy always evaluates to true
	acceptAllPolicy := envelope(nOutOf(0, []*cb.SignaturePolicy{}), [][]byte{})
	// This policy is not referenced anywhere, it is only used as part of the implicit meta policy rule at the channel level, so this setting
	// effectively degrades control of the ordering system channel to the ordering admins
	addPolicy(consortiumsGroup, signaturePolicy(AdminsPolicyKey, acceptAllPolicy), ordererAdminsPolicyName)

	for consortiumName, consortium := range conf {
		consortiumsGroup.Groups[consortiumName], err = newConsortiumGroup(consortium, mspConfig)
		if err != nil {
			return nil, fmt.Errorf("could not create consortium group: %v", err)
		}
	}

	consortiumsGroup.ModPolicy = ordererAdminsPolicyName

	return consortiumsGroup, nil
}

// newConsortiumGroup returns a consortiums component of the channel configuration
func newConsortiumGroup(conf *Consortium, mspConfig *mb.MSPConfig) (*cb.ConfigGroup, error) {
	var err error

	consortiumGroup := newConfigGroup()

	for _, org := range conf.Organizations {
		consortiumGroup.Groups[org.Name], err = newConsortiumOrgGroup(org, mspConfig)
		if err != nil {
			return nil, fmt.Errorf("could not create consortium org group %s: %v", org.Name, err)
		}
	}

	addValue(consortiumGroup, channelCreationPolicyValue(implicitMetaAnyPolicy(AdminsPolicyKey).Value()), ordererAdminsPolicyName)

	consortiumGroup.ModPolicy = ordererAdminsPolicyName

	return consortiumGroup, nil
}

// newConsortiumOrgGroup returns an org component of the channel configuration
// It defines the crypto material for the organization (its MSP)
// It sets the mod_policy of all elements to "Admins"
func newConsortiumOrgGroup(conf *Organization, mspConfig *mb.MSPConfig) (*cb.ConfigGroup, error) {
	consortiumOrgGroup := newConfigGroup()
	consortiumOrgGroup.ModPolicy = AdminsPolicyKey

	if conf.SkipAsForeign {
		return consortiumOrgGroup, nil
	}

	if err := addPolicies(consortiumOrgGroup, conf.Policies, AdminsPolicyKey); err != nil {
		return nil, fmt.Errorf("error adding policies: %v", err)
	}

	addValue(consortiumOrgGroup, mspValue(mspConfig), AdminsPolicyKey)

	return consortiumOrgGroup, nil
}

// consortiumValue returns the config definition for the consortium name
// It is a value for the channel group
func consortiumValue(name string) *StandardConfigValue {
	return &StandardConfigValue{
		key: ConsortiumKey,
		value: &cb.Consortium{
			Name: name,
		},
	}
}

// channelCreationPolicyValue returns the config definition for a consortium's channel creation policy
// It is a value for the /Channel/Consortiums/*/*
func channelCreationPolicyValue(policy *cb.Policy) *StandardConfigValue {
	return &StandardConfigValue{
		key:   ChannelCreationPolicyKey,
		value: policy,
	}
}

// envelope builds an envelope message embedding a SignaturePolicy
func envelope(policy *cb.SignaturePolicy, identities [][]byte) *cb.SignaturePolicyEnvelope {
	ids := make([]*mb.MSPPrincipal, len(identities))
	for i := range ids {
		ids[i] = &mb.MSPPrincipal{PrincipalClassification: mb.MSPPrincipal_IDENTITY, Principal: identities[i]}
	}

	return &cb.SignaturePolicyEnvelope{
		Version:    0,
		Rule:       policy,
		Identities: ids,
	}
}

// nOutOf creates a policy which requires N out of the slice of policies to evaluate to true
func nOutOf(n int32, policies []*cb.SignaturePolicy) *cb.SignaturePolicy {
	return &cb.SignaturePolicy{
		Type: &cb.SignaturePolicy_NOutOf_{
			NOutOf: &cb.SignaturePolicy_NOutOf{
				N:     n,
				Rules: policies,
			},
		},
	}
}

// addPolicy adds a *cb.ConfigPolicy to the passed *cb.ConfigGroup's Policies map
func addPolicy(cg *cb.ConfigGroup, policy ConfigPolicy, modPolicy string) {
	cg.Policies[policy.Key()] = &cb.ConfigPolicy{
		Policy:    policy.Value(),
		ModPolicy: modPolicy,
	}
}

// signaturePolicy defines a policy with key policyName and the given signature policy
func signaturePolicy(policyName string, sigPolicy *cb.SignaturePolicyEnvelope) *StandardConfigPolicy {
	return &StandardConfigPolicy{
		key: policyName,
		value: &cb.Policy{
			Type:  int32(cb.Policy_SIGNATURE),
			Value: protoMarshalOrPanic(sigPolicy),
		},
	}
}
