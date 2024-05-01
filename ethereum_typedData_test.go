package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestVerifyTestdata(t *testing.T) {
	r := require.New(t)
	// TODO: clean up package global assert()
	//a := assert.New(t)
	schemaPath := os.Getenv("MASS_SCHEMA")
	if schemaPath == "" {
		t.Skip()
		return
	}

	tvd, err := os.ReadFile(filepath.Join(schemaPath, "testVectors.json"))
	r.NoError(err)

	var vect schemaTestVectors
	err = json.Unmarshal(tvd, &vect)
	r.NoError(err)
	t.Log("events:", len(vect.Events))

	verifier := newEthClient()
	verifier.chainID = uint(vect.Signatures.ChainID)
	verifier.contractAddresses.StoreRegistry = common.Address(vect.Signatures.ContractAddress)

	for i, vectEvt := range vect.Events {
		t.Log("event:", i)
		var evt StoreEvent
		err = proto.Unmarshal(vectEvt.Encoded, &evt)
		r.NoError(err)
		t.Logf("type: %T", evt.Union)

		hash, err := verifier.eventHash(&evt)
		r.NoError(err)

		r.Equal(true, bytes.Equal(vectEvt.Hash, hash))
	}
}

type schemaTestVectors struct {
	Signatures struct {
		ChainID         int       `json:"chain_id"`
		ContractAddress HexString `json:"contract_address"`
		SignerAddress   string    `json:"signer_address"`
	} `json:"signatures"`
	Events []struct {
		Type      string    `json:"type"`
		Signature HexString `json:"signature"`
		Hash      HexString `json:"hash"`
		Encoded   HexString `json:"encoded"`
	}
	Reduced struct {
		Manifest struct {
			StoreTokenID string `json:"store_token_id"`
			Domain       string `json:"domain"`
			PublishedTag struct {
				Three127D54Db09354057Cdad21C30D0206463Dcda8Cc87D2Bb7C6Dbffa7Ebf15637 struct {
					Text string `json:"text"`
				} `json:"3127d54db09354057cdad21c30d0206463dcda8cc87d2bb7c6dbffa7ebf15637"`
			} `json:"published_tag"`
			EnabledErc20S struct {
				SixEfc7E8D499F3E7Ed288328C66848Ac254Db5F55  bool `json:"6efc7e8d499f3e7ed288328c66848ac254db5f55"`
				Five61Bcc74Eab3F3D0Cd670E3D04750C7E416038C7 bool `json:"561bcc74eab3f3d0cd670e3d04750c7e416038c7"`
			} `json:"enabled_erc20s"`
		} `json:"manifest"`
		Keycards struct {
			Two48B2Fb379D102F621C26459Ca886A6A20B19193A63C9146390Aad0Ccaba5F5Fb9Ac2B24330Fd1296750F6Ce5Bfd8Ea083Eb78C9E358A4515Ecb375E6A21E70F string `json:"248b2fb379d102f621c26459ca886a6a20b19193a63c9146390aad0ccaba5f5fb9ac2b24330fd1296750f6ce5bfd8ea083eb78c9e358a4515ecb375e6a21e70f"`
			A8C465F75De1C0F16Aaa05A0Ca6766B5F98Fbd5Eebcfa8E025F1E0Cfefaa87Fbc0162C42Befb1810Ae15E5F5C07290C64B133A0F2D6B9F7A983A8Ea2D94E051B   string `json:"a8c465f75de1c0f16aaa05a0ca6766b5f98fbd5eebcfa8e025f1e0cfefaa87fbc0162c42befb1810ae15e5f5c07290c64b133a0f2d6b9f7a983a8ea2d94e051b"`
		} `json:"keycards"`
		Items struct {
			FiveB1A2A8B1F298A0C463F86652Daf13179Fd253F5B2Db31Fd089Ce3B90A5A89D3 struct {
				Price    string   `json:"price"`
				Metadata string   `json:"metadata"`
				TagID    []string `json:"tag_id"`
				StockQty int      `json:"stock_qty"`
			} `json:"5b1a2a8b1f298a0c463f86652daf13179fd253f5b2db31fd089ce3b90a5a89d3"`
			One7296C1F9B02617Dec0Db6437790Af4A95339E6005579Df93F6A9F0Eecb3409E struct {
				Price    string        `json:"price"`
				Metadata string        `json:"metadata"`
				TagID    []interface{} `json:"tag_id"`
				StockQty int           `json:"stock_qty"`
			} `json:"17296c1f9b02617dec0db6437790af4a95339e6005579df93f6a9f0eecb3409e"`
		} `json:"items"`
		PublishedItems []string `json:"published_items"`
		OpenOrders     struct {
			TwoDc2479De7E92Ef9Dd4Deff6Df3E0A7A87982A9Ebd1974C5A429Ff3Df4Bce0D9 struct {
				FiveB1A2A8B1F298A0C463F86652Daf13179Fd253F5B2Db31Fd089Ce3B90A5A89D3 int `json:"5b1a2a8b1f298a0c463f86652daf13179fd253f5b2db31fd089ce3b90a5a89d3"`
			} `json:"2dc2479de7e92ef9dd4deff6df3e0a7a87982a9ebd1974c5a429ff3df4bce0d9"`
		} `json:"open_orders"`
		CommitedOrders struct {
			Nine4A6D2C246B5Cd04F8B2D96B41556Cb280B63Ac3E863D226C14C603B09Bb9507 struct {
				PurchaseAddr string `json:"purchase_addr"`
				Items        struct {
					FiveB1A2A8B1F298A0C463F86652Daf13179Fd253F5B2Db31Fd089Ce3B90A5A89D3 int `json:"5b1a2a8b1f298a0c463f86652daf13179fd253f5b2db31fd089ce3b90a5a89d3"`
				} `json:"items"`
				Total string `json:"total"`
			} `json:"94a6d2c246b5cd04f8b2d96b41556cb280b63ac3e863d226c14c603b09bb9507"`
		} `json:"commited_orders"`
		PayedOrders []struct {
			OrderID string `json:"order_id"`
			TxHash  string `json:"tx_hash"`
		} `json:"payed_orders"`
		AbandonedOrders []string `json:"abandoned_orders"`
		Inventory       struct {
			FiveB1A2A8B1F298A0C463F86652Daf13179Fd253F5B2Db31Fd089Ce3B90A5A89D3 int `json:"5b1a2a8b1f298a0c463f86652daf13179fd253f5b2db31fd089ce3b90a5a89d3"`
			One7296C1F9B02617Dec0Db6437790Af4A95339E6005579Df93F6A9F0Eecb3409E  int `json:"17296c1f9b02617dec0db6437790af4a95339e6005579df93f6a9f0eecb3409e"`
		} `json:"inventory"`
	} `json:"reduced"`
}

// HexString can be used to turn a byteslice into a JSON hexadecimal string
type HexString []byte

// MarshalJSON turns the binary data into a hex string
func (s HexString) MarshalJSON() ([]byte, error) {
	str := hex.EncodeToString([]byte(s))
	return json.Marshal(str)
}

// UnmarshalJSON expects data to be a string with hexadecimal bytes inside
func (s *HexString) UnmarshalJSON(data []byte) error {
	var strData string
	err := json.Unmarshal(data, &strData)
	if err != nil {
		return fmt.Errorf("HexString: json decode of string failed: %w", err)
	}
	strData = strings.TrimPrefix(strData, "0x")

	rawData, err := hex.DecodeString(strData)
	if err != nil {
		return fmt.Errorf("HexString: decoding hex to raw bytes failed: %w", err)
	}

	*s = rawData
	return nil
}
