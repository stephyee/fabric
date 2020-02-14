/*
Copyright IBM Corp All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package config

import (
	"errors"
	"testing"

	"github.com/hyperledger/fabric-protos-go/msp"
	. "github.com/onsi/gomega"
)

func TestCreateChannelTx(t *testing.T) {
	t.Parallel()

	gt := NewGomegaWithT(t)

	profile := baseProfile()

	mspConfig := &msp.FabricMSPConfig{}

	// It returns an envelope
	env, err := CreateChannelTx(&profile, mspConfig)
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(env).NotTo(BeNil())
}

func TestCreateChannelTxFailure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		testName   string
		profileMod func() *Profile
		err        error
	}{
		{
			testName: "When creating the default config template fails",
			profileMod: func() *Profile {
				profile := baseProfile()
				profile.Policies = nil
				return &profile
			},
			err: errors.New("could not generate default config template: error adding policies: " +
				"no policies defined"),
		},
		{
			testName: "When channel is not specified in config",
			profileMod: func() *Profile {
				return nil
			},
			err: errors.New("profile is empty"),
		},
		{
			testName: "When channel ID is not specified in config",
			profileMod: func() *Profile {
				profile := baseProfile()
				profile.ChannelID = ""
				return &profile
			},
			err: errors.New("channel ID is empty"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.testName, func(t *testing.T) {
			t.Parallel()

			gt := NewGomegaWithT(t)

			mspConfig := &msp.FabricMSPConfig{}
			profile := tt.profileMod()

			env, err := CreateChannelTx(profile, mspConfig)
			gt.Expect(env).To(BeNil())
			gt.Expect(err).To(MatchError(tt.err))
		})
	}
}

func baseProfile() Profile {
	return Profile{
		ChannelID:  "testchannel",
		Consortium: "SampleConsortium",
		Application: &Application{
			Policies: createStandardPolicies(),
			Organizations: []*Organization{
				{
					Name:     "Org1",
					ID:       "Org1MSP",
					Policies: createOrgStandardPolicies(),
					MSPType:  "bccsp",
				},
				{
					Name:     "Org2",
					ID:       "Org2MSP",
					Policies: createOrgStandardPolicies(),
					MSPType:  "bccsp",
				},
			},
			Capabilities: map[string]bool{
				"V1_3": true,
			},
		},
		Capabilities: map[string]bool{"V2_0": true},
		Policies:     createStandardPolicies(),
	}
}

func createStandardPolicies() map[string]*Policy {
	return map[string]*Policy{
		ReadersPolicyKey: {
			Type: ImplicitMetaPolicyType,
			Rule: "ANY Readers",
		},
		WritersPolicyKey: {
			Type: ImplicitMetaPolicyType,
			Rule: "ANY Writers",
		},
		AdminsPolicyKey: {
			Type: ImplicitMetaPolicyType,
			Rule: "MAJORITY Admins",
		},
		LifecycleEndorsementPolicyKey: {
			Type: ImplicitMetaPolicyType,
			Rule: "MAJORITY Endorsement",
		},
		EndorsementPolicyKey: {
			Type: ImplicitMetaPolicyType,
			Rule: "MAJORITY Endorsement",
		},
	}
}

func createOrgStandardPolicies() map[string]*Policy {
	return map[string]*Policy{
		ReadersPolicyKey: {
			Type: ImplicitMetaPolicyType,
			Rule: "ANY Readers",
		},
		WritersPolicyKey: {
			Type: ImplicitMetaPolicyType,
			Rule: "ANY Writers",
		},
		AdminsPolicyKey: {
			Type: ImplicitMetaPolicyType,
			Rule: "MAJORITY Admins",
		},
		EndorsementPolicyKey: {
			Type: ImplicitMetaPolicyType,
			Rule: "ANY Endorsement",
		},
	}
}
