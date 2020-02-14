/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package config

import (
	"fmt"

	"github.com/hyperledger/fabric-protos-go/common"
	"github.com/hyperledger/fabric-protos-go/msp"
	pb "github.com/hyperledger/fabric-protos-go/peer"
)

// Application encodes the application-level configuration needed in config
// transactions.
type Application struct {
	Organizations []*Organization
	Capabilities  map[string]bool
	Resources     *Resources
	Policies      map[string]*Policy
	ACLs          map[string]string
}

// AnchorPeer encodes the necessary fields to identify an anchor peer.
type AnchorPeer struct {
	Host string
	Port int
}

// Application Group

// NewApplicationGroup returns the application component of the channel configuration.  It defines the organizations which are involved
// in application logic like chaincodes, and how these members may interact with the orderer.  It sets the mod_policy of all elements to "Admins".
func NewApplicationGroup(conf *Application, mspConfig *msp.MSPConfig) (*common.ConfigGroup, error) {
	applicationGroup := newConfigGroup()
	if err := addPolicies(applicationGroup, conf.Policies, AdminsPolicyKey); err != nil {
		return nil, fmt.Errorf("error adding policies to application group: %v", err)
	}

	if len(conf.ACLs) > 0 {
		addValue(applicationGroup, aclValues(conf.ACLs), AdminsPolicyKey)
	}

	if len(conf.Capabilities) > 0 {
		addValue(applicationGroup, capabilitiesValue(conf.Capabilities), AdminsPolicyKey)
	}

	for _, org := range conf.Organizations {
		var err error
		applicationGroup.Groups[org.Name], err = newApplicationOrgGroup(org, mspConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create application org %s: %v", org.Name, err)
		}
	}

	applicationGroup.ModPolicy = AdminsPolicyKey
	return applicationGroup, nil
}

// NewApplicationOrgGroup returns an application org component of the channel configuration.  It defines the crypto material for the organization
// (its MSP) as well as its anchor peers for use by the gossip network.  It sets the mod_policy of all elements to "Admins".
func newApplicationOrgGroup(conf *Organization, mspConfig *msp.MSPConfig) (*common.ConfigGroup, error) {
	applicationOrgGroup := newConfigGroup()
	applicationOrgGroup.ModPolicy = AdminsPolicyKey

	if conf.SkipAsForeign {
		return applicationOrgGroup, nil
	}

	if err := addPolicies(applicationOrgGroup, conf.Policies, AdminsPolicyKey); err != nil {
		return nil, fmt.Errorf("error adding policies to application org group %s: %v", conf.Name, err)
	}

	addValue(applicationOrgGroup, mspValue(mspConfig), AdminsPolicyKey)

	var anchorProtos []*pb.AnchorPeer
	for _, anchorPeer := range conf.AnchorPeers {
		anchorProtos = append(anchorProtos, &pb.AnchorPeer{
			Host: anchorPeer.Host,
			Port: int32(anchorPeer.Port),
		})
	}

	// Avoid adding an unnecessary anchor peers element when one is not required.  This helps
	// prevent a delta from the orderer system channel when computing more complex channel
	// creation transactions
	if len(anchorProtos) > 0 {
		addValue(applicationOrgGroup, anchorPeersValue(anchorProtos), AdminsPolicyKey)
	}

	return applicationOrgGroup, nil
}

// ACLValues returns the config definition for an applications resources based ACL definitions.
// It is a value for the /Channel/Application/.
func aclValues(acls map[string]string) *StandardConfigValue {
	a := &pb.ACLs{
		Acls: make(map[string]*pb.APIResource),
	}

	for apiResource, policyRef := range acls {
		a.Acls[apiResource] = &pb.APIResource{PolicyRef: policyRef}
	}

	return &StandardConfigValue{
		key:   ACLsKey,
		value: a,
	}
}

// AnchorPeersValue returns the config definition for an org's anchor peers.
// It is a value for the /Channel/Application/*.
func anchorPeersValue(anchorPeers []*pb.AnchorPeer) *StandardConfigValue {
	return &StandardConfigValue{
		key:   AnchorPeersKey,
		value: &pb.AnchorPeers{AnchorPeers: anchorPeers},
	}
}
