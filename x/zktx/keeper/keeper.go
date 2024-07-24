package keeper

import (
	"fmt"

	"cosmossdk.io/collections"
	"cosmossdk.io/core/address"
	storetypes "cosmossdk.io/core/store"
	"github.com/cosmos/cosmos-sdk/codec"

	"github.com/hyle-org/hyle/x/zktx"
)

type Keeper struct {
	cdc          codec.BinaryCodec
	addressCodec address.Codec

	// authority is the address capable of executing authority-gated messages.
	// typically, this should be the x/gov module account.
	authority string

	// state management
	Schema    collections.Schema
	Params    collections.Item[zktx.Params]
	Contracts collections.Map[string, zktx.Contract]

	// Proof stuff
	// NbPayload     collections.Map[string, uint16]
	ProvenPayload collections.Map[collections.Pair[[]byte, uint32], zktx.PayloadMetadata]
}

// NewKeeper creates a new Keeper instance
func NewKeeper(cdc codec.BinaryCodec, addressCodec address.Codec, storeService storetypes.KVStoreService, authority string) Keeper {
	if _, err := addressCodec.StringToBytes(authority); err != nil {
		panic(fmt.Errorf("invalid authority address: %w", err))
	}

	sb := collections.NewSchemaBuilder(storeService)
	k := Keeper{
		cdc:          cdc,
		addressCodec: addressCodec,
		authority:    authority,
		Params:       collections.NewItem(sb, zktx.ParamsKey, "params", codec.CollValue[zktx.Params](cdc)),
		Contracts:    collections.NewMap(sb, zktx.ContractNameKey, "contracts", collections.StringKey, codec.CollValue[zktx.Contract](cdc)),
		ProvenPayload: collections.NewMap(sb, zktx.ProvenPayloadKey, "proven_payload",
			collections.PairKeyCodec(collections.BytesKey, collections.Uint32Key), codec.CollValue[zktx.PayloadMetadata](cdc)),
	}

	schema, err := sb.Build()
	if err != nil {
		panic(err)
	}

	k.Schema = schema

	return k
}

// GetAuthority returns the module's authority.
func (k Keeper) GetAuthority() string {
	return k.authority
}
