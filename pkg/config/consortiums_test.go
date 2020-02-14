/*
Copyright IBM Corp All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package config

import (
	"testing"

	"github.com/hyperledger/fabric-protos-go/common"
	"github.com/hyperledger/fabric-protos-go/msp"
	. "github.com/onsi/gomega"
)

func TestNewConsortiumsGroup(t *testing.T) {
	t.Parallel()

	gt := NewGomegaWithT(t)
	consortiums := map[string]*Consortium{
		"Consortium1": {
			Organizations: []*Organization{
				{
					Name:     "Org1",
					Policies: createOrgStandardPolicies(),
				},
				{
					Name:     "Org2",
					Policies: createOrgStandardPolicies(),
				},
			},
		},
	}

	mspConfig := &msp.MSPConfig{}
	consortiumsGroup, err := NewConsortiumsGroup(consortiums, mspConfig)
	gt.Expect(err).NotTo(HaveOccurred())

	// ConsortiumsGroup checks
	gt.Expect(len(consortiumsGroup.Groups)).To(Equal(1))
	gt.Expect(consortiumsGroup.Groups["Consortium1"]).NotTo(BeNil())
	gt.Expect(len(consortiumsGroup.Values)).To(Equal(0))
	gt.Expect(len(consortiumsGroup.Policies)).To(Equal(1))
	gt.Expect(consortiumsGroup.Policies[AdminsPolicyKey]).NotTo(BeNil())

	// ConsortiumGroup checks
	gt.Expect(len(consortiumsGroup.Groups["Consortium1"].Groups)).To(Equal(2))
	gt.Expect(consortiumsGroup.Groups["Consortium1"].Groups["Org1"]).NotTo(BeNil())
	gt.Expect(consortiumsGroup.Groups["Consortium1"].Groups["Org2"]).NotTo(BeNil())
	gt.Expect(len(consortiumsGroup.Groups["Consortium1"].Values)).To(Equal(1))
	gt.Expect(consortiumsGroup.Groups["Consortium1"].Values[ChannelCreationPolicyKey]).NotTo(BeNil())
	gt.Expect(len(consortiumsGroup.Groups["Consortium1"].Policies)).To(Equal(0))

	// ConsortiumOrgGroup checks
	gt.Expect(len(consortiumsGroup.Groups["Consortium1"].Groups["Org1"].Groups)).To(Equal(0))
	gt.Expect(len(consortiumsGroup.Groups["Consortium1"].Groups["Org2"].Groups)).To(Equal(0))
	gt.Expect(len(consortiumsGroup.Groups["Consortium1"].Groups["Org1"].Policies)).To(Equal(4))
	gt.Expect(consortiumsGroup.Groups["Consortium1"].Groups["Org1"].Policies[ReadersPolicyKey]).NotTo(BeNil())
	gt.Expect(consortiumsGroup.Groups["Consortium1"].Groups["Org1"].Policies[WritersPolicyKey]).NotTo(BeNil())
	gt.Expect(consortiumsGroup.Groups["Consortium1"].Groups["Org1"].Policies[AdminsPolicyKey]).NotTo(BeNil())
	gt.Expect(consortiumsGroup.Groups["Consortium1"].Groups["Org1"].Policies[EndorsementPolicyKey]).NotTo(BeNil())
	gt.Expect(len(consortiumsGroup.Groups["Consortium1"].Groups["Org2"].Policies)).To(Equal(4))
	gt.Expect(consortiumsGroup.Groups["Consortium1"].Groups["Org2"].Policies[ReadersPolicyKey]).NotTo(BeNil())
	gt.Expect(consortiumsGroup.Groups["Consortium1"].Groups["Org2"].Policies[WritersPolicyKey]).NotTo(BeNil())
	gt.Expect(consortiumsGroup.Groups["Consortium1"].Groups["Org2"].Policies[AdminsPolicyKey]).NotTo(BeNil())
	gt.Expect(consortiumsGroup.Groups["Consortium1"].Groups["Org2"].Policies[EndorsementPolicyKey]).NotTo(BeNil())
	gt.Expect(len(consortiumsGroup.Groups["Consortium1"].Groups["Org1"].Values)).To(Equal(1))
	gt.Expect(consortiumsGroup.Groups["Consortium1"].Groups["Org1"].Values[MSPKey]).NotTo(BeNil())
}

func TestNewConsortiumsGroupFailure(t *testing.T) {
	t.Parallel()

	gt := NewGomegaWithT(t)
	mspConfig := &msp.MSPConfig{}
	consortiums := map[string]*Consortium{
		"Consortium1": {
			Organizations: []*Organization{
				{
					Name:     "Org1",
					Policies: nil,
				},
			},
		},
	}

	consortiumsGroup, err := NewConsortiumsGroup(consortiums, mspConfig)
	gt.Expect(consortiumsGroup).To(BeNil())
	gt.Expect(err).To(MatchError("could not create consortium group: " +
		"could not create consortium org group Org1: " +
		"error adding policies: no policies defined"))
}

func TestSkipAsForeignForConsortiumOrg(t *testing.T) {
	t.Parallel()

	gt := NewGomegaWithT(t)
	mspConfig := &msp.MSPConfig{}
	consortiums := map[string]*Consortium{
		"Consortium1": {
			Organizations: []*Organization{
				{
					Name:          "Org1",
					Policies:      createOrgStandardPolicies(),
					SkipAsForeign: true,
				},
				{
					Name:          "Org2",
					Policies:      createOrgStandardPolicies(),
					SkipAsForeign: true,
				},
			},
		},
	}

	// returns a consortiums group with consortium groups that have empty consortium org groups with only mod policy
	consortiumsGroup, err := NewConsortiumsGroup(consortiums, mspConfig)
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(consortiumsGroup.Groups["Consortium1"].Groups["Org1"]).To(Equal(&common.ConfigGroup{
		ModPolicy: AdminsPolicyKey,
		Groups:    make(map[string]*common.ConfigGroup),
		Values:    make(map[string]*common.ConfigValue),
		Policies:  make(map[string]*common.ConfigPolicy),
	}))
	gt.Expect(consortiumsGroup.Groups["Consortium1"].Groups["Org2"]).To(Equal(&common.ConfigGroup{
		ModPolicy: AdminsPolicyKey,
		Groups:    make(map[string]*common.ConfigGroup),
		Values:    make(map[string]*common.ConfigValue),
		Policies:  make(map[string]*common.ConfigPolicy),
	}))
}
