/*
Copyright IBM Corp. 2017 All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/golang/protobuf/proto"
	cb "github.com/hyperledger/fabric-protos-go/common"
	"github.com/hyperledger/fabric-protos-go/msp"
	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/factory"
	"github.com/hyperledger/fabric/common/channelconfig"
	"github.com/hyperledger/fabric/common/flogging"
	"github.com/hyperledger/fabric/common/tools/protolator"
	"github.com/hyperledger/fabric/common/tools/protolator/protoext/ordererext"
	"github.com/hyperledger/fabric/internal/configtxgen/encoder"
	"github.com/hyperledger/fabric/internal/configtxgen/genesisconfig"
	"github.com/hyperledger/fabric/internal/configtxgen/metadata"
	"github.com/hyperledger/fabric/internal/configtxlator/update"
	mspConfigBuilder "github.com/hyperledger/fabric/msp"
	"github.com/hyperledger/fabric/pkg/configtx"
	"github.com/hyperledger/fabric/pkg/configtx/membership"
	orderertx "github.com/hyperledger/fabric/pkg/configtx/orderer"
	"github.com/hyperledger/fabric/protoutil"
	"github.com/pkg/errors"
	yaml "gopkg.in/yaml.v2"
)

var logger = flogging.MustGetLogger("common.tools.configtxgen")

func doOutputBlock(config *genesisconfig.Profile, channelID string, outputBlock string) error {
	pgen, err := encoder.NewBootstrapper(config)
	if err != nil {
		return errors.WithMessage(err, "could not create bootstrapper")
	}
	logger.Info("Generating genesis block")
	if config.Orderer == nil {
		return errors.Errorf("refusing to generate block which is missing orderer section")
	}
	if config.Consortiums == nil {
		logger.Warning("Genesis block does not contain a consortiums group definition.  This block cannot be used for orderer bootstrap.")
	}
	genesisBlock := pgen.GenesisBlockForChannel(channelID)
	logger.Info("Writing genesis block")
	err = writeFile(outputBlock, protoutil.MarshalOrPanic(genesisBlock), 0640)
	if err != nil {
		return fmt.Errorf("Error writing genesis block: %s", err)
	}
	return nil
}

func doOutputChannelCreateTx(conf, baseProfile *genesisconfig.Profile, channelID string, outputChannelCreateTx string) error {
	logger.Info("Generating new channel configtx")

	var configtx *cb.Envelope
	var err error
	if baseProfile == nil {
		configtx, err = encoder.MakeChannelCreationTransaction(channelID, nil, conf)
	} else {
		configtx, err = encoder.MakeChannelCreationTransactionWithSystemChannelContext(channelID, nil, conf, baseProfile)
	}
	if err != nil {
		return err
	}

	logger.Info("Writing new channel tx")
	err = writeFile(outputChannelCreateTx, protoutil.MarshalOrPanic(configtx), 0640)
	if err != nil {
		return fmt.Errorf("Error writing channel create tx: %s", err)
	}
	return nil
}

func doOutputAnchorPeersUpdate(conf *genesisconfig.Profile, channelID string, outputAnchorPeersUpdate string, asOrg string) error {
	logger.Info("Generating anchor peer update")
	if asOrg == "" {
		return fmt.Errorf("Must specify an organization to update the anchor peer for")
	}

	if conf.Application == nil {
		return fmt.Errorf("Cannot update anchor peers without an application section")
	}

	original, err := encoder.NewChannelGroup(conf)
	if err != nil {
		return errors.WithMessage(err, "error parsing profile as channel group")
	}
	original.Groups[channelconfig.ApplicationGroupKey].Version = 1

	updated := proto.Clone(original).(*cb.ConfigGroup)

	originalOrg, ok := original.Groups[channelconfig.ApplicationGroupKey].Groups[asOrg]
	if !ok {
		return errors.Errorf("org with name '%s' does not exist in config", asOrg)
	}

	if _, ok = originalOrg.Values[channelconfig.AnchorPeersKey]; !ok {
		return errors.Errorf("org '%s' does not have any anchor peers defined", asOrg)
	}

	delete(originalOrg.Values, channelconfig.AnchorPeersKey)

	updt, err := update.Compute(&cb.Config{ChannelGroup: original}, &cb.Config{ChannelGroup: updated})
	if err != nil {
		return errors.WithMessage(err, "could not compute update")
	}
	updt.ChannelId = channelID

	newConfigUpdateEnv := &cb.ConfigUpdateEnvelope{
		ConfigUpdate: protoutil.MarshalOrPanic(updt),
	}

	updateTx, err := protoutil.CreateSignedEnvelope(cb.HeaderType_CONFIG_UPDATE, channelID, nil, newConfigUpdateEnv, 0, 0)

	logger.Info("Writing anchor peer update")
	err = writeFile(outputAnchorPeersUpdate, protoutil.MarshalOrPanic(updateTx), 0640)
	if err != nil {
		return fmt.Errorf("Error writing channel anchor peer update: %s", err)
	}
	return nil
}

func doInspectBlock(inspectBlock string) error {
	logger.Info("Inspecting block")
	data, err := ioutil.ReadFile(inspectBlock)
	if err != nil {
		return fmt.Errorf("Could not read block %s", inspectBlock)
	}

	logger.Info("Parsing genesis block")
	block, err := protoutil.UnmarshalBlock(data)
	if err != nil {
		return fmt.Errorf("error unmarshaling to block: %s", err)
	}
	err = protolator.DeepMarshalJSON(os.Stdout, block)
	if err != nil {
		return fmt.Errorf("malformed block contents: %s", err)
	}
	return nil
}

func doInspectChannelCreateTx(inspectChannelCreateTx string) error {
	logger.Info("Inspecting transaction")
	data, err := ioutil.ReadFile(inspectChannelCreateTx)
	if err != nil {
		return fmt.Errorf("could not read channel create tx: %s", err)
	}

	logger.Info("Parsing transaction")
	env, err := protoutil.UnmarshalEnvelope(data)
	if err != nil {
		return fmt.Errorf("Error unmarshaling envelope: %s", err)
	}

	err = protolator.DeepMarshalJSON(os.Stdout, env)
	if err != nil {
		return fmt.Errorf("malformed transaction contents: %s", err)
	}

	return nil
}

func doPrintOrg(t *genesisconfig.TopLevel, printOrg string) error {
	for _, org := range t.Organizations {
		if org.Name == printOrg {
			og, err := encoder.NewOrdererOrgGroup(org)
			if err != nil {
				return errors.Wrapf(err, "bad org definition for org %s", org.Name)
			}

			if err := protolator.DeepMarshalJSON(os.Stdout, &ordererext.DynamicOrdererOrgGroup{ConfigGroup: og}); err != nil {
				return errors.Wrapf(err, "malformed org definition for org: %s", org.Name)
			}
			return nil
		}
	}
	return errors.Errorf("organization %s not found", printOrg)
}

func writeFile(filename string, data []byte, perm os.FileMode) error {
	dirPath := filepath.Dir(filename)
	exists, err := dirExists(dirPath)
	if err != nil {
		return err
	}
	if !exists {
		err = os.MkdirAll(dirPath, 0750)
		if err != nil {
			return err
		}
	}
	return ioutil.WriteFile(filename, data, perm)
}

func dirExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func main() {
	var outputBlock, outputChannelCreateTx, channelCreateTxBaseProfile, profile, configPath, channelID, inspectBlock, inspectChannelCreateTx, outputAnchorPeersUpdate, asOrg, printOrg string

	flag.StringVar(&outputBlock, "outputBlock", "", "The path to write the genesis block to (if set)")
	flag.StringVar(&channelID, "channelID", "", "The channel ID to use in the configtx")
	flag.StringVar(&outputChannelCreateTx, "outputCreateChannelTx", "", "The path to write a channel creation configtx to (if set)")
	flag.StringVar(&channelCreateTxBaseProfile, "channelCreateTxBaseProfile", "", "Specifies a profile to consider as the orderer system channel current state to allow modification of non-application parameters during channel create tx generation. Only valid in conjunction with 'outputCreateChannelTx'.")
	flag.StringVar(&profile, "profile", "", "The profile from configtx.yaml to use for generation.")
	flag.StringVar(&configPath, "configPath", "", "The path containing the configuration to use (if set)")
	flag.StringVar(&inspectBlock, "inspectBlock", "", "Prints the configuration contained in the block at the specified path")
	flag.StringVar(&inspectChannelCreateTx, "inspectChannelCreateTx", "", "Prints the configuration contained in the transaction at the specified path")
	flag.StringVar(&outputAnchorPeersUpdate, "outputAnchorPeersUpdate", "", "[DEPRECATED] Creates a config update to update an anchor peer (works only with the default channel creation, and only for the first update)")
	flag.StringVar(&asOrg, "asOrg", "", "Performs the config generation as a particular organization (by name), only including values in the write set that org (likely) has privilege to set")
	flag.StringVar(&printOrg, "printOrg", "", "Prints the definition of an organization as JSON. (useful for adding an org to a channel manually)")

	version := flag.Bool("version", false, "Show version information")

	flag.Parse()

	if channelID == "" && (outputBlock != "" || outputChannelCreateTx != "" || outputAnchorPeersUpdate != "") {
		logger.Fatalf("Missing channelID, please specify it with '-channelID'")
	}

	// show version
	if *version {
		printVersion()
		os.Exit(0)
	}

	// don't need to panic when running via command line
	defer func() {
		if err := recover(); err != nil {
			if strings.Contains(fmt.Sprint(err), "Error reading configuration: Unsupported Config Type") {
				logger.Error("Could not find configtx.yaml. " +
					"Please make sure that FABRIC_CFG_PATH or -configPath is set to a path " +
					"which contains configtx.yaml")
				os.Exit(1)
			}
			if strings.Contains(fmt.Sprint(err), "Could not find profile") {
				logger.Error(fmt.Sprint(err) + ". " +
					"Please make sure that FABRIC_CFG_PATH or -configPath is set to a path " +
					"which contains configtx.yaml with the specified profile")
				os.Exit(1)
			}
			logger.Panic(err)
		}
	}()

	logger.Info("Loading configuration")
	err := factory.InitFactories(nil)
	if err != nil {
		logger.Fatalf("Error on initFactories: %s", err)
	}
	var profileConfig *genesisconfig.Profile
	if outputBlock != "" || outputChannelCreateTx != "" || outputAnchorPeersUpdate != "" {
		if profile == "" {
			logger.Fatalf("The '-profile' is required when '-outputBlock', '-outputChannelCreateTx', or '-outputAnchorPeersUpdate' is specified")
		}

		if configPath != "" {
			profileConfig = genesisconfig.Load(profile, configPath)
		} else {
			profileConfig = genesisconfig.Load(profile)
		}
	}

	channel := NewChannel(profileConfig)

	var baseProfile *genesisconfig.Profile
	if channelCreateTxBaseProfile != "" {
		if outputChannelCreateTx == "" {
			logger.Warning("Specified 'channelCreateTxBaseProfile', but did not specify 'outputChannelCreateTx', 'channelCreateTxBaseProfile' will not affect output.")
		}
		if configPath != "" {
			baseProfile = genesisconfig.Load(channelCreateTxBaseProfile, configPath)
		} else {
			baseProfile = genesisconfig.Load(channelCreateTxBaseProfile)
		}
	}

	if outputBlock != "" {
		if err := doOutputBlock(profileConfig, channelID, outputBlock); err != nil {
			logger.Fatalf("Error on outputBlock: %s", err)
		}
	}

	if outputChannelCreateTx != "" {
		if err := doOutputChannelCreateTx(profileConfig, baseProfile, channelID, outputChannelCreateTx); err != nil {
			logger.Fatalf("Error on outputChannelCreateTx: %s", err)
		}
	}

	if inspectBlock != "" {
		if err := doInspectBlock(inspectBlock); err != nil {
			logger.Fatalf("Error on inspectBlock: %s", err)
		}
	}

	if inspectChannelCreateTx != "" {
		if err := doInspectChannelCreateTx(inspectChannelCreateTx); err != nil {
			logger.Fatalf("Error on inspectChannelCreateTx: %s", err)
		}
	}

	if outputAnchorPeersUpdate != "" {
		if err := doOutputAnchorPeersUpdate(profileConfig, channelID, outputAnchorPeersUpdate, asOrg); err != nil {
			logger.Fatalf("Error on inspectChannelCreateTx: %s", err)
		}
	}

	if printOrg != "" {
		var topLevelConfig *genesisconfig.TopLevel
		if configPath != "" {
			topLevelConfig = genesisconfig.LoadTopLevel(configPath)
		} else {
			topLevelConfig = genesisconfig.LoadTopLevel()
		}

		if err := doPrintOrg(topLevelConfig, printOrg); err != nil {
			logger.Fatalf("Error on printOrg: %s", err)
		}
	}
}

func NewChannel(baseProfile *genesisconfig.Profile) configtx.Channel {
	// Application section
	appOrgs := newOrganization(baseProfile.Application.Organizations)

	appCapabilities := []string{}
	for name := range baseProfile.Application.Capabilities {
		appCapabilities = append(appCapabilities, name)
	}

	appPolicies := newPolicies(baseProfile.Application.Policies)

	application := configtx.Application{
		Organizations: appOrgs,
		Capabilities:  appCapabilities,
		Policies:      appPolicies,
		ACLs:          baseProfile.Application.ACLs,
	}

	// Orderer section
	addresses := []configtx.Address{}

	for _, addr := range baseProfile.Orderer.Addresses {
		addrslice := strings.Split(addr, ":")

		port, err := strconv.Atoi(addrslice[1])
		if err != nil {
			panic(err)
		}

		addresses = append(addresses, configtx.Address{
			Host: addrslice[0],
			Port: port,
		})
	}

	kafka := orderertx.Kafka{
		Brokers: baseProfile.Orderer.Kafka.Brokers,
	}

	consentors := []orderertx.Consenter{}

	for _, consenter := range baseProfile.Orderer.EtcdRaft.Consenters {
		clientCert, err := parseCertificateFromBytes(consenter.ClientTlsCert)
		if err != nil {
			panic(err)
		}

		serverCert, err := parseCertificateFromBytes(consenter.ServerTlsCert)
		if err != nil {
			panic(err)
		}

		consentors = append(consentors, orderertx.Consenter{
			Address: orderertx.EtcdAddress{
				Host: consenter.Host,
				Port: int(consenter.Port),
			},
			ClientTLSCert: clientCert,
			ServerTLSCert: serverCert,
		})
	}

	etcdRaft := orderertx.EtcdRaft{
		Consenters: consentors,
		Options: orderertx.EtcdRaftOptions{
			TickInterval:         baseProfile.Orderer.EtcdRaft.Options.TickInterval,
			ElectionTick:         baseProfile.Orderer.EtcdRaft.Options.ElectionTick,
			HeartbeatTick:        baseProfile.Orderer.EtcdRaft.Options.HeartbeatTick,
			MaxInflightBlocks:    baseProfile.Orderer.EtcdRaft.Options.MaxInflightBlocks,
			SnapshotIntervalSize: baseProfile.Orderer.EtcdRaft.Options.SnapshotIntervalSize,
		},
	}

	ordererOrgs := newOrganization(baseProfile.Orderer.Organizations)

	ordererCapabilities := []string{}
	for name := range baseProfile.Orderer.Capabilities {
		ordererCapabilities = append(ordererCapabilities, name)
	}

	orderer := configtx.Orderer{
		OrdererType:  baseProfile.Orderer.OrdererType,
		Addresses:    addresses,
		BatchTimeout: baseProfile.Orderer.BatchTimeout,
		BatchSize: orderertx.BatchSize{
			MaxMessageCount:   baseProfile.Orderer.BatchSize.MaxMessageCount,
			AbsoluteMaxBytes:  baseProfile.Orderer.BatchSize.AbsoluteMaxBytes,
			PreferredMaxBytes: baseProfile.Orderer.BatchSize.PreferredMaxBytes,
		},
		Kafka:         kafka,
		EtcdRaft:      etcdRaft,
		Organizations: ordererOrgs,
		MaxChannels:   baseProfile.Orderer.MaxChannels,
		Capabilities:  ordererCapabilities,
		Policies:      newPolicies(baseProfile.Orderer.Policies),
		State:         orderertx.ConsensusStateNormal,
	}

	// Consortiums section
	consortiums := []configtx.Consortium{}

	for name, c := range baseProfile.Consortiums {
		consortiums = append(consortiums, configtx.Consortium{
			Name:          name,
			Organizations: newOrganization(c.Organizations),
		})
	}

	// Capabilities section
	channelCapabilities := []string{}
	for name := range baseProfile.Capabilities {
		channelCapabilities = append(channelCapabilities, name)
	}

	channel := configtx.Channel{
		Consortium:   baseProfile.Consortium,
		Application:  application,
		Orderer:      orderer,
		Consortiums:  consortiums,
		Capabilities: channelCapabilities,
		Policies:     newPolicies(baseProfile.Policies),
	}

	return channel
}

func parseCertificateFromBytes(cert []byte) (*x509.Certificate, error) {
	pemBlock, _ := pem.Decode(cert)

	certificate, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		return &x509.Certificate{}, err
	}

	return certificate, nil
}

func newOrganization(orgs []*genesisconfig.Organization) []configtx.Organization {
	txorgs := []configtx.Organization{}

	for _, org := range orgs {
		anchorPeers := []configtx.Address{}

		for _, peer := range org.AnchorPeers {
			anchorPeers = append(anchorPeers, configtx.Address{
				Host: peer.Host,
				Port: peer.Port,
			})

			mspConfig, err := getMspConfig(org.MSPDir, "ID", nil)
			if err != nil {
				panic(err)
			}

			txmsp, err := getMSPConfig(mspConfig)
			if err != nil {
				panic(err)
			}

			txorgs = append(txorgs, configtx.Organization{
				Name:             org.Name,
				MSP:              txmsp,
				Policies:         newPolicies(org.Policies),
				AnchorPeers:      anchorPeers,
				OrdererEndpoints: org.OrdererEndpoints,
			})
		}
	}

	return txorgs
}

func parseCertificateListFromBytes(certs [][]byte) ([]*x509.Certificate, error) {
	certificateList := []*x509.Certificate{}

	for _, cert := range certs {
		certificate, err := parseCertificateFromBytes(cert)
		if err != nil {
			return certificateList, err
		}

		certificateList = append(certificateList, certificate)
	}

	return certificateList, nil
}

func parseCRL(crls [][]byte) ([]*pkix.CertificateList, error) {
	certificateLists := []*pkix.CertificateList{}

	for _, crl := range crls {
		pemBlock, _ := pem.Decode(crl)

		certificateList, err := x509.ParseCRL(pemBlock.Bytes)
		if err != nil {
			return certificateLists, fmt.Errorf("parsing crl: %v", err)
		}

		certificateLists = append(certificateLists, certificateList)
	}

	return certificateLists, nil
}

func parsePrivateKeyFromBytes(priv []byte) (crypto.PrivateKey, error) {
	if len(priv) == 0 {
		return nil, nil
	}

	pemBlock, _ := pem.Decode(priv)

	privateKey, err := x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed parsing PKCS#8 private key: %v", err)
	}

	return privateKey, nil
}

func parseOUIdentifiers(identifiers []*msp.FabricOUIdentifier) ([]membership.OUIdentifier, error) {
	fabricIdentifiers := []membership.OUIdentifier{}

	for _, identifier := range identifiers {
		cert, err := parseCertificateFromBytes(identifier.Certificate)
		if err != nil {
			return fabricIdentifiers, err
		}

		fabricOUIdentifier := membership.OUIdentifier{
			Certificate:                  cert,
			OrganizationalUnitIdentifier: identifier.OrganizationalUnitIdentifier,
		}

		fabricIdentifiers = append(fabricIdentifiers, fabricOUIdentifier)
	}

	return fabricIdentifiers, nil
}

func getMSPConfig(config *msp.MSPConfig) (configtx.MSP, error) {
	fabricMSPConfig := &msp.FabricMSPConfig{}

	err := proto.Unmarshal(config.Config, fabricMSPConfig)
	if err != nil {
		return configtx.MSP{}, fmt.Errorf("unmarshaling fabric msp config: %v", err)
	}

	// ROOT CERTS
	rootCerts, err := parseCertificateListFromBytes(fabricMSPConfig.RootCerts)
	if err != nil {
		return configtx.MSP{}, fmt.Errorf("parsing root certs: %v", err)
	}

	// INTERMEDIATE CERTS
	intermediateCerts, err := parseCertificateListFromBytes(fabricMSPConfig.IntermediateCerts)
	if err != nil {
		return configtx.MSP{}, fmt.Errorf("parsing intermediate certs: %v", err)
	}

	// ADMIN CERTS
	adminCerts, err := parseCertificateListFromBytes(fabricMSPConfig.Admins)
	if err != nil {
		return configtx.MSP{}, fmt.Errorf("parsing admin certs: %v", err)
	}

	// REVOCATION LIST
	revocationList, err := parseCRL(fabricMSPConfig.RevocationList)
	if err != nil {
		return configtx.MSP{}, err
	}

	// SIGNING IDENTITY
	publicSigner, err := parseCertificateFromBytes(fabricMSPConfig.SigningIdentity.PublicSigner)
	if err != nil {
		return configtx.MSP{}, fmt.Errorf("parsing signing identity public signer: %v", err)
	}

	keyMaterial, err := parsePrivateKeyFromBytes(fabricMSPConfig.SigningIdentity.PrivateSigner.KeyMaterial)
	if err != nil {
		return configtx.MSP{}, fmt.Errorf("parsing signing identity private key: %v", err)
	}

	signingIdentity := membership.SigningIdentityInfo{
		PublicSigner: publicSigner,
		PrivateSigner: membership.KeyInfo{
			KeyIdentifier: fabricMSPConfig.SigningIdentity.PrivateSigner.KeyIdentifier,
			KeyMaterial:   keyMaterial,
		},
	}

	// OU IDENTIFIERS
	ouIdentifiers, err := parseOUIdentifiers(fabricMSPConfig.OrganizationalUnitIdentifiers)
	if err != nil {
		return configtx.MSP{}, fmt.Errorf("parsing ou identifiers: %v", err)
	}

	// TLS ROOT CERTS
	tlsRootCerts, err := parseCertificateListFromBytes(fabricMSPConfig.TlsRootCerts)
	if err != nil {
		return configtx.MSP{}, fmt.Errorf("parsing tls root certs: %v", err)
	}

	// TLS INTERMEDIATE CERTS
	tlsIntermediateCerts, err := parseCertificateListFromBytes(fabricMSPConfig.TlsIntermediateCerts)
	if err != nil {
		return configtx.MSP{}, fmt.Errorf("parsing tls intermediate certs: %v", err)
	}

	// NODE OUS
	clientOUIdentifierCert, err := parseCertificateFromBytes(fabricMSPConfig.FabricNodeOus.ClientOuIdentifier.Certificate)
	if err != nil {
		return configtx.MSP{}, fmt.Errorf("parsing client ou identifier cert: %v", err)
	}

	peerOUIdentifierCert, err := parseCertificateFromBytes(fabricMSPConfig.FabricNodeOus.PeerOuIdentifier.Certificate)
	if err != nil {
		return configtx.MSP{}, fmt.Errorf("parsing peer ou identifier cert: %v", err)
	}

	adminOUIdentifierCert, err := parseCertificateFromBytes(fabricMSPConfig.FabricNodeOus.AdminOuIdentifier.Certificate)
	if err != nil {
		return configtx.MSP{}, fmt.Errorf("parsing admin ou identifier cert: %v", err)
	}

	ordererOUIdentifierCert, err := parseCertificateFromBytes(fabricMSPConfig.FabricNodeOus.OrdererOuIdentifier.Certificate)
	if err != nil {
		return configtx.MSP{}, fmt.Errorf("parsing orderer ou identifier cert: %v", err)
	}

	nodeOUs := membership.NodeOUs{
		Enable: fabricMSPConfig.FabricNodeOus.Enable,
		ClientOUIdentifier: membership.OUIdentifier{
			Certificate:                  clientOUIdentifierCert,
			OrganizationalUnitIdentifier: fabricMSPConfig.FabricNodeOus.ClientOuIdentifier.OrganizationalUnitIdentifier,
		},
		PeerOUIdentifier: membership.OUIdentifier{
			Certificate:                  peerOUIdentifierCert,
			OrganizationalUnitIdentifier: fabricMSPConfig.FabricNodeOus.PeerOuIdentifier.OrganizationalUnitIdentifier,
		},
		AdminOUIdentifier: membership.OUIdentifier{
			Certificate:                  adminOUIdentifierCert,
			OrganizationalUnitIdentifier: fabricMSPConfig.FabricNodeOus.AdminOuIdentifier.OrganizationalUnitIdentifier,
		},
		OrdererOUIdentifier: membership.OUIdentifier{
			Certificate:                  ordererOUIdentifierCert,
			OrganizationalUnitIdentifier: fabricMSPConfig.FabricNodeOus.OrdererOuIdentifier.OrganizationalUnitIdentifier,
		},
	}

	return configtx.MSP{
		Name:                          fabricMSPConfig.Name,
		RootCerts:                     rootCerts,
		IntermediateCerts:             intermediateCerts,
		Admins:                        adminCerts,
		RevocationList:                revocationList,
		SigningIdentity:               signingIdentity,
		OrganizationalUnitIdentifiers: ouIdentifiers,
		CryptoConfig: membership.CryptoConfig{
			SignatureHashFamily:            fabricMSPConfig.CryptoConfig.SignatureHashFamily,
			IdentityIdentifierHashFunction: fabricMSPConfig.CryptoConfig.IdentityIdentifierHashFunction,
		},
		TLSRootCerts:         tlsRootCerts,
		TLSIntermediateCerts: tlsIntermediateCerts,
		NodeOus:              nodeOUs,
	}, nil
}

// ProviderType indicates the type of an identity provider
type ProviderType int

// The ProviderType of a member relative to the member API
const (
	FABRIC ProviderType = iota // MSP is of FABRIC type
	IDEMIX                     // MSP is of IDEMIX type
	OTHER                      // MSP is of OTHER TYPE

	// NOTE: as new types are added to this set,
	// the mspTypes map below must be extended

	cacerts              = "cacerts"
	admincerts           = "admincerts"
	signcerts            = "signcerts"
	keystore             = "keystore"
	intermediatecerts    = "intermediatecerts"
	crlsfolder           = "crls"
	configfilename       = "config.yaml"
	tlscacerts           = "tlscacerts"
	tlsintermediatecerts = "tlsintermediatecerts"
)

func getMspConfig(dir string, ID string, sigid *msp.SigningIdentityInfo) (*msp.MSPConfig, error) {
	cacertDir := filepath.Join(dir, cacerts)
	admincertDir := filepath.Join(dir, admincerts)
	intermediatecertsDir := filepath.Join(dir, intermediatecerts)
	crlsDir := filepath.Join(dir, crlsfolder)
	configFile := filepath.Join(dir, configfilename)
	tlscacertDir := filepath.Join(dir, tlscacerts)
	tlsintermediatecertsDir := filepath.Join(dir, tlsintermediatecerts)

	cacerts, err := getPemMaterialFromDir(cacertDir)
	if err != nil || len(cacerts) == 0 {
		return nil, errors.WithMessagef(err, "could not load a valid ca certificate from directory %s", cacertDir)
	}

	admincert, err := getPemMaterialFromDir(admincertDir)
	if err != nil && !os.IsNotExist(err) {
		return nil, errors.WithMessagef(err, "could not load a valid admin certificate from directory %s", admincertDir)
	}

	intermediatecerts, err := getPemMaterialFromDir(intermediatecertsDir)
	if !os.IsNotExist(err) {
		return nil, errors.WithMessagef(err, "failed loading intermediate ca certs at [%s]", intermediatecertsDir)
	}

	tlsCACerts, err := getPemMaterialFromDir(tlscacertDir)
	tlsIntermediateCerts := [][]byte{}
	if os.IsNotExist(err) {
	} else if err != nil {
		return nil, errors.WithMessagef(err, "failed loading TLS ca certs at [%s]", tlsintermediatecertsDir)
	} else if len(tlsCACerts) != 0 {
		tlsIntermediateCerts, err = getPemMaterialFromDir(tlsintermediatecertsDir)
		if os.IsNotExist(err) {
		} else if err != nil {
			return nil, errors.WithMessagef(err, "failed loading TLS intermediate ca certs at [%s]", tlsintermediatecertsDir)
		}
	} else {
	}

	crls, err := getPemMaterialFromDir(crlsDir)
	if os.IsNotExist(err) {
	} else if err != nil {
		return nil, errors.WithMessagef(err, "failed loading crls at [%s]", crlsDir)
	}

	// Load configuration file
	// if the configuration file is there then load it
	// otherwise skip it
	var ouis []*msp.FabricOUIdentifier
	var nodeOUs *msp.FabricNodeOUs
	_, err = os.Stat(configFile)
	if err == nil {
		// load the file, if there is a failure in loading it then
		// return an error
		raw, err := ioutil.ReadFile(configFile)
		if err != nil {
			return nil, errors.Wrapf(err, "failed loading configuration file at [%s]", configFile)
		}

		configuration := mspConfigBuilder.Configuration{}
		err = yaml.Unmarshal(raw, &configuration)
		if err != nil {
			return nil, errors.Wrapf(err, "failed unmarshalling configuration file at [%s]", configFile)
		}

		// Prepare OrganizationalUnitIdentifiers
		if len(configuration.OrganizationalUnitIdentifiers) > 0 {
			for _, ouID := range configuration.OrganizationalUnitIdentifiers {
				f := filepath.Join(dir, ouID.Certificate)
				raw, err = readFile(f)
				if err != nil {
					return nil, errors.Wrapf(err, "failed loading OrganizationalUnit certificate at [%s]", f)
				}

				oui := &msp.FabricOUIdentifier{
					Certificate:                  raw,
					OrganizationalUnitIdentifier: ouID.OrganizationalUnitIdentifier,
				}
				ouis = append(ouis, oui)
			}
		}

		// Prepare NodeOUs
		if configuration.NodeOUs != nil && configuration.NodeOUs.Enable {
			nodeOUs = &msp.FabricNodeOUs{
				Enable: true,
			}
			if configuration.NodeOUs.ClientOUIdentifier != nil && len(configuration.NodeOUs.ClientOUIdentifier.OrganizationalUnitIdentifier) != 0 {
				nodeOUs.ClientOuIdentifier = &msp.FabricOUIdentifier{OrganizationalUnitIdentifier: configuration.NodeOUs.ClientOUIdentifier.OrganizationalUnitIdentifier}
			}
			if configuration.NodeOUs.PeerOUIdentifier != nil && len(configuration.NodeOUs.PeerOUIdentifier.OrganizationalUnitIdentifier) != 0 {
				nodeOUs.PeerOuIdentifier = &msp.FabricOUIdentifier{OrganizationalUnitIdentifier: configuration.NodeOUs.PeerOUIdentifier.OrganizationalUnitIdentifier}
			}
			if configuration.NodeOUs.AdminOUIdentifier != nil && len(configuration.NodeOUs.AdminOUIdentifier.OrganizationalUnitIdentifier) != 0 {
				nodeOUs.AdminOuIdentifier = &msp.FabricOUIdentifier{OrganizationalUnitIdentifier: configuration.NodeOUs.AdminOUIdentifier.OrganizationalUnitIdentifier}
			}
			if configuration.NodeOUs.OrdererOUIdentifier != nil && len(configuration.NodeOUs.OrdererOUIdentifier.OrganizationalUnitIdentifier) != 0 {
				nodeOUs.OrdererOuIdentifier = &msp.FabricOUIdentifier{OrganizationalUnitIdentifier: configuration.NodeOUs.OrdererOUIdentifier.OrganizationalUnitIdentifier}
			}

			// Read certificates, if defined

			// ClientOU
			if nodeOUs.ClientOuIdentifier != nil {
				nodeOUs.ClientOuIdentifier.Certificate = loadCertificateAt(dir, configuration.NodeOUs.ClientOUIdentifier.Certificate, "ClientOU")
			}
			// PeerOU
			if nodeOUs.PeerOuIdentifier != nil {
				nodeOUs.PeerOuIdentifier.Certificate = loadCertificateAt(dir, configuration.NodeOUs.PeerOUIdentifier.Certificate, "PeerOU")
			}
			// AdminOU
			if nodeOUs.AdminOuIdentifier != nil {
				nodeOUs.AdminOuIdentifier.Certificate = loadCertificateAt(dir, configuration.NodeOUs.AdminOUIdentifier.Certificate, "AdminOU")
			}
			// OrdererOU
			if nodeOUs.OrdererOuIdentifier != nil {
				nodeOUs.OrdererOuIdentifier.Certificate = loadCertificateAt(dir, configuration.NodeOUs.OrdererOUIdentifier.Certificate, "OrdererOU")
			}
		}
	}

	// Set FabricCryptoConfig
	cryptoConfig := &msp.FabricCryptoConfig{
		SignatureHashFamily:            bccsp.SHA2,
		IdentityIdentifierHashFunction: bccsp.SHA256,
	}

	// Compose FabricMSPConfig
	fmspconf := &msp.FabricMSPConfig{
		Admins:                        admincert,
		RootCerts:                     cacerts,
		IntermediateCerts:             intermediatecerts,
		SigningIdentity:               sigid,
		Name:                          ID,
		OrganizationalUnitIdentifiers: ouis,
		RevocationList:                crls,
		CryptoConfig:                  cryptoConfig,
		TlsRootCerts:                  tlsCACerts,
		TlsIntermediateCerts:          tlsIntermediateCerts,
		FabricNodeOus:                 nodeOUs,
	}

	fmpsjs, _ := proto.Marshal(fmspconf)

	mspconf := &msp.MSPConfig{Config: fmpsjs, Type: int32(FABRIC)}

	return mspconf, nil
}

func loadCertificateAt(dir, certificatePath string, ouType string) []byte {
	f := filepath.Join(dir, certificatePath)
	raw, err := readFile(f)
	if err != nil {
	} else {
		return raw
	}

	return nil
}

func readFile(file string) ([]byte, error) {
	fileCont, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, errors.Wrapf(err, "could not read file %s", file)
	}

	return fileCont, nil
}

func readPemFile(file string) ([]byte, error) {
	bytes, err := readFile(file)
	if err != nil {
		return nil, errors.Wrapf(err, "reading from file %s failed", file)
	}

	b, _ := pem.Decode(bytes)
	if b == nil { // TODO: also check that the type is what we expect (cert vs key..)
		return nil, errors.Errorf("no pem content for file %s", file)
	}

	return bytes, nil
}

func getPemMaterialFromDir(dir string) ([][]byte, error) {
	_, err := os.Stat(dir)
	if os.IsNotExist(err) {
		return nil, err
	}

	content := make([][]byte, 0)
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		return nil, errors.Wrapf(err, "could not read directory %s", dir)
	}

	for _, f := range files {
		fullName := filepath.Join(dir, f.Name())

		f, err := os.Stat(fullName)
		if err != nil {
			continue
		}
		if f.IsDir() {
			continue
		}

		item, err := readPemFile(fullName)
		if err != nil {
			continue
		}

		content = append(content, item)
	}

	return content, nil
}

func newPolicies(policies map[string]*genesisconfig.Policy) map[string]configtx.Policy {
	txpolicies := map[string]configtx.Policy{}
	for name, policy := range policies {
		txpolicies[name] = configtx.Policy{
			Type: policy.Type,
			Rule: policy.Rule,
		}
	}

	return txpolicies
}

func printVersion() {
	fmt.Println(metadata.GetVersionInfo())
}
