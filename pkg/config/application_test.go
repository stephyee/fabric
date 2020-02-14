/*
Copyright IBM Corp All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package config

import (
	"errors"
	"testing"

	"github.com/hyperledger/fabric-protos-go/common"
	"github.com/hyperledger/fabric-protos-go/msp"
	. "github.com/onsi/gomega"
)

func TestNewApplicationGroup(t *testing.T) {
	t.Parallel()

	gt := NewGomegaWithT(t)

	mspConfig := &msp.MSPConfig{}

	application := baseApplication()

	applicationGroup, err := NewApplicationGroup(application, mspConfig)
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(len(applicationGroup.Policies)).To(Equal(5))
	gt.Expect(applicationGroup.Policies["Admins"]).NotTo(BeNil())
	gt.Expect(applicationGroup.Policies["Readers"]).NotTo(BeNil())
	gt.Expect(applicationGroup.Policies["Writers"]).NotTo(BeNil())
	gt.Expect(len(applicationGroup.Groups)).To(Equal(2))
	gt.Expect(applicationGroup.Groups["Org1"]).NotTo(BeNil())
	gt.Expect(applicationGroup.Groups["Org2"]).NotTo(BeNil())
	gt.Expect(len(applicationGroup.Values)).To(Equal(2))
	gt.Expect(applicationGroup.Values["ACLs"]).NotTo(BeNil())
	gt.Expect(applicationGroup.Values["Capabilities"]).NotTo(BeNil())
}

func TestNewApplicationGroupFailure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		testName       string
		applicationMod func(*Application)
		expectedErr    error
	}{
		{
			testName: "When application group policy is empty",
			applicationMod: func(a *Application) {
				a.Policies = nil
			},
			expectedErr: errors.New("error adding policies: no policies defined"),
		},
		{
			testName: "When adding policies to application group",
			applicationMod: func(a *Application) {
				a.Organizations[0].Policies = nil
			},
			expectedErr: errors.New("could not create application org group Org1: error adding policies: " +
				"no policies defined"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.testName, func(t *testing.T) {
			t.Parallel()

			gt := NewGomegaWithT(t)

			application := baseApplication()
			mspConfig := &msp.MSPConfig{}
			tt.applicationMod(application)

			configGrp, err := NewApplicationGroup(application, mspConfig)
			gt.Expect(configGrp).To(BeNil())
			gt.Expect(err).To(MatchError(tt.expectedErr))
		})
	}
}

func TestNewApplicationGroupSkipAsForeign(t *testing.T) {
	t.Parallel()

	gt := NewGomegaWithT(t)

	application := &Application{
		Policies: createStandardPolicies(),
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
	}

	mspConfig := &msp.MSPConfig{}

	applicationGroup, err := NewApplicationGroup(application, mspConfig)
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(applicationGroup.Groups["Org1"]).To(Equal(&common.ConfigGroup{
		ModPolicy: AdminsPolicyKey,
		Groups:    make(map[string]*common.ConfigGroup),
		Values:    make(map[string]*common.ConfigValue),
		Policies:  make(map[string]*common.ConfigPolicy),
	}))
	gt.Expect(applicationGroup.Groups["Org2"]).To(Equal(&common.ConfigGroup{
		ModPolicy: AdminsPolicyKey,
		Groups:    make(map[string]*common.ConfigGroup),
		Values:    make(map[string]*common.ConfigValue),
		Policies:  make(map[string]*common.ConfigPolicy),
	}))
}

func baseApplication() *Application {
	return &Application{
		Policies: createStandardPolicies(),
		Organizations: []*Organization{
			{
				Name:     "Org1",
				ID:       "Org1MSP",
				Policies: createOrgStandardPolicies(),
				MSPType:  "bccsp",
				AnchorPeers: []*AnchorPeer{
					{Host: "host1", Port: 123},
				},
			},
			{
				Name:     "Org2",
				ID:       "Org2MSP",
				Policies: createOrgStandardPolicies(),
				MSPType:  "bccsp",
				AnchorPeers: []*AnchorPeer{
					{Host: "host2", Port: 123},
				},
			},
		},
		Capabilities: map[string]bool{
			"V1_3": true,
		},
		ACLs: map[string]string{
			"acl1": "hi",
		},
	}
}
