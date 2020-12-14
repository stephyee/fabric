/*
 * Fabric API
 *
 * Hyperledger Fabric is an enterprise-grade permissioned distributed ledger framework for developing solutions and applications. Its modular and versatile design satisfies a broad range of industry use cases. It offers a unique approach to consensus that enables performance at scale while preserving privacy.
 *
 * API version: 2.3
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */
package swagger

// This is marshaled into the body of the HTTP response.
type ChannelInfo struct {
	ConsensusRelation string `json:"consensusRelation,omitempty"`
	// Current block height.
	Height int32 `json:"height,omitempty"`
	// The channel name.
	Name string `json:"name,omitempty"`
	Status string `json:"status,omitempty"`
	// The channel relative URL (no Host:Port, only path), e.g.: \"/participation/v1/channels/my-channel\".
	Url string `json:"url,omitempty"`
}
