/*
Copyright IBM Corp All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package config_test

import (
	"io/ioutil"
	"os"

	"github.com/golang/protobuf/proto"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gexec"

	"github.com/hyperledger/fabric-protos-go/common"
	"github.com/hyperledger/fabric-protos-go/msp"
	"github.com/hyperledger/fabric/integration/nwo"
	"github.com/hyperledger/fabric/integration/nwo/commands"
	"github.com/hyperledger/fabric/pkg/config"
)

var _ = Describe("CreateChannelTx", func() {
	var (
		testDir   string
		network   *nwo.Network
		profile   *config.Profile
		mspConfig *msp.FabricMSPConfig
	)

	BeforeEach(func() {
		var err error
		testDir, err = ioutil.TempDir("", "config")
		Expect(err).NotTo(HaveOccurred())

		network = nwo.New(nwo.BasicSolo(), testDir, nil, StartPort(), components)

		network.GenerateConfigTree()

		network.Bootstrap()

		profile = &config.Profile{
			ChannelID:  "testchannel",
			Consortium: "SampleConsortium",
			Application: &config.Application{
				Policies: createStandardPolicies(),
				Organizations: []*config.Organization{
					{
						Name:     "Org1",
						ID:       "Org1MSP",
						Policies: createOrgStandardPolicies(),
						MSPType:  "bccsp",
						MSPDir:   network.PeerOrgMSPDir(network.Organization("Org1")),
					},
					{
						Name:     "Org2",
						ID:       "Org2MSP",
						Policies: createOrgStandardPolicies(),
						MSPType:  "bccsp",
						MSPDir:   network.PeerOrgMSPDir(network.Organization("Org2")),
					},
				},
				Capabilities: map[string]bool{
					"V1_3": true,
				},
			},
			Capabilities: map[string]bool{"V2_0": true},
			Policies:     createStandardPolicies(),
		}

		mspConfig = &msp.FabricMSPConfig{}
	})

	AfterEach(func() {
		if network != nil {
			network.Cleanup()
		}
		os.RemoveAll(testDir)
	})

	It("creates envelope", func() {
		createChannelTxPath := network.CreateChannelTxPath(profile.ChannelID)

		By("creating a create channel transaction")
		envelope, err := config.CreateChannelTx(profile, mspConfig)
		Expect(err).ToNot(HaveOccurred())
		Expect(envelope).ToNot(BeNil())

		By("using configtxgen to create a create channel transaction")
		sess, err := network.ConfigTxGen(commands.CreateChannelTx{
			ChannelID:             profile.ChannelID,
			Profile:               "TwoOrgsChannel",
			ConfigPath:            testDir,
			OutputCreateChannelTx: createChannelTxPath,
		})
		Expect(err).NotTo(HaveOccurred())
		Eventually(sess, network.EventuallyTimeout).Should(gexec.Exit(0))

		// Reading envelope created using configtxgen
		configTxBytes, err := ioutil.ReadFile(createChannelTxPath)
		Expect(err).ToNot(HaveOccurred())

		// Umarshalling actual and expected envelope to set
		// the expected timestamp to the actual timestamp
		expectedEnvelope := common.Envelope{}
		err = proto.Unmarshal(configTxBytes, &expectedEnvelope)
		Expect(err).NotTo(HaveOccurred())

		expectedPayload := common.Payload{}
		err = proto.Unmarshal(expectedEnvelope.Payload, &expectedPayload)
		Expect(err).NotTo(HaveOccurred())

		expectedHeader := common.ChannelHeader{}
		err = proto.Unmarshal(expectedPayload.Header.ChannelHeader, &expectedHeader)
		Expect(err).NotTo(HaveOccurred())

		expectedData := common.ConfigUpdateEnvelope{}
		err = proto.Unmarshal(expectedPayload.Data, &expectedData)
		Expect(err).NotTo(HaveOccurred())

		expectedConfigUpdate := common.ConfigUpdate{}
		err = proto.Unmarshal(expectedData.ConfigUpdate, &expectedConfigUpdate)
		Expect(err).NotTo(HaveOccurred())

		actualPayload := common.Payload{}
		err = proto.Unmarshal(envelope.Payload, &actualPayload)
		Expect(err).NotTo(HaveOccurred())

		actualHeader := common.ChannelHeader{}
		err = proto.Unmarshal(actualPayload.Header.ChannelHeader, &actualHeader)
		Expect(err).NotTo(HaveOccurred())

		actualData := common.ConfigUpdateEnvelope{}
		err = proto.Unmarshal(actualPayload.Data, &actualData)
		Expect(err).NotTo(HaveOccurred())

		actualConfigUpdate := common.ConfigUpdate{}
		err = proto.Unmarshal(actualData.ConfigUpdate, &actualConfigUpdate)
		Expect(err).NotTo(HaveOccurred())

		Expect(actualConfigUpdate).To(Equal(expectedConfigUpdate))

		By("setting timestamps to match in ConfigUpdate")
		actualTimestamp := actualHeader.Timestamp

		expectedHeader.Timestamp = actualTimestamp

		expectedData.ConfigUpdate = actualData.ConfigUpdate

		// Remarshalling envelopes with updated timestamps
		expectedPayload.Data, err = proto.Marshal(&expectedData)
		Expect(err).NotTo(HaveOccurred())

		expectedPayload.Header.ChannelHeader, err = proto.Marshal(&expectedHeader)
		Expect(err).NotTo(HaveOccurred())

		expectedEnvelope.Payload, err = proto.Marshal(&expectedPayload)
		Expect(err).NotTo(HaveOccurred())

		Expect(proto.Equal(envelope, &expectedEnvelope)).To(BeTrue())

	})
})

func createStandardPolicies() map[string]*config.Policy {
	return map[string]*config.Policy{
		config.ReadersPolicyKey: {
			Type: config.ImplicitMetaPolicyType,
			Rule: "ANY Readers",
		},
		config.WritersPolicyKey: {
			Type: config.ImplicitMetaPolicyType,
			Rule: "ANY Writers",
		},
		config.AdminsPolicyKey: {
			Type: config.ImplicitMetaPolicyType,
			Rule: "MAJORITY Admins",
		},
		config.LifecycleEndorsementPolicyKey: {
			Type: config.ImplicitMetaPolicyType,
			Rule: "MAJORITY Endorsement",
		},
		config.EndorsementPolicyKey: {
			Type: config.ImplicitMetaPolicyType,
			Rule: "MAJORITY Endorsement",
		},
	}
}

func createOrgStandardPolicies() map[string]*config.Policy {
	return map[string]*config.Policy{
		config.ReadersPolicyKey: {
			Type: config.ImplicitMetaPolicyType,
			Rule: "ANY Readers",
		},
		config.WritersPolicyKey: {
			Type: config.ImplicitMetaPolicyType,
			Rule: "ANY Writers",
		},
		config.AdminsPolicyKey: {
			Type: config.ImplicitMetaPolicyType,
			Rule: "MAJORITY Admins",
		},
		config.EndorsementPolicyKey: {
			Type: config.ImplicitMetaPolicyType,
			Rule: "ANY Endorsement",
		},
	}
}
