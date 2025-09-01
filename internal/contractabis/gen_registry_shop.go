// SPDX-FileCopyrightText: 2025 Mass Labs
//
// SPDX-License-Identifier: GPL-3.0-or-later

// Generated from abi/ShopReg.json - git at 548ca6e00ffe3f8d841fa4aa985183f0ff3b4dc3

// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package contractsabi

import (
	"errors"
	"math/big"
	"strings"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/event"
)

// Reference imports to suppress errors if they are not otherwise used.
var (
	_ = errors.New
	_ = big.NewInt
	_ = strings.NewReader
	_ = ethereum.NotFound
	_ = bind.Bind
	_ = common.Big1
	_ = types.BloomLookup
	_ = event.NewSubscription
	_ = abi.ConvertType
)

// RegShopMetaData contains all meta data concerning the RegShop contract.
var RegShopMetaData = &bind.MetaData{
	ABI: "[{\"type\":\"constructor\",\"inputs\":[{\"name\":\"r\",\"type\":\"address\",\"internalType\":\"contractRelayReg\"}],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"PERM_addPermission\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"uint8\",\"internalType\":\"uint8\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"PERM_addRelay\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"uint8\",\"internalType\":\"uint8\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"PERM_publishInviteVerifier\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"uint8\",\"internalType\":\"uint8\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"PERM_registerUser\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"uint8\",\"internalType\":\"uint8\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"PERM_removePermission\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"uint8\",\"internalType\":\"uint8\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"PERM_removeRelay\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"uint8\",\"internalType\":\"uint8\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"PERM_removeUser\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"uint8\",\"internalType\":\"uint8\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"PERM_replaceRelay\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"uint8\",\"internalType\":\"uint8\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"PERM_updateRootHash\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"uint8\",\"internalType\":\"uint8\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"_getTokenMessageHash\",\"inputs\":[{\"name\":\"user\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"addPermission\",\"inputs\":[{\"name\":\"shopId\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"user\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"perm\",\"type\":\"uint8\",\"internalType\":\"uint8\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"addRelay\",\"inputs\":[{\"name\":\"shopId\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"relayId\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"allPermissionsGuard\",\"inputs\":[{\"name\":\"id\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"perms\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"approve\",\"inputs\":[{\"name\":\"to\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"tokenId\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"balanceOf\",\"inputs\":[{\"name\":\"owner\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"getAllPermissions\",\"inputs\":[{\"name\":\"id\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"user\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"getAllRelays\",\"inputs\":[{\"name\":\"shopId\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[{\"name\":\"\",\"type\":\"uint256[]\",\"internalType\":\"uint256[]\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"getApproved\",\"inputs\":[{\"name\":\"tokenId\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"address\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"getRelayCount\",\"inputs\":[{\"name\":\"shopId\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"hasEnoughPermissions\",\"inputs\":[{\"name\":\"id\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"user\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"perms\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"hasPermission\",\"inputs\":[{\"name\":\"id\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"user\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"perm\",\"type\":\"uint8\",\"internalType\":\"uint8\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"isApprovedForAll\",\"inputs\":[{\"name\":\"owner\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"operator\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"mint\",\"inputs\":[{\"name\":\"shopId\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"owner\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"name\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"string\",\"internalType\":\"string\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"nonce\",\"inputs\":[{\"name\":\"shopid\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[{\"name\":\"\",\"type\":\"uint64\",\"internalType\":\"uint64\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"ownerOf\",\"inputs\":[{\"name\":\"tokenId\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"address\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"permissionGuard\",\"inputs\":[{\"name\":\"id\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"perm\",\"type\":\"uint8\",\"internalType\":\"uint8\"}],\"outputs\":[],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"permsToBitmap\",\"inputs\":[{\"name\":\"perms\",\"type\":\"uint8[]\",\"internalType\":\"uint8[]\"}],\"outputs\":[{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"publishInviteVerifier\",\"inputs\":[{\"name\":\"shopId\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"verifier\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"redeemInvite\",\"inputs\":[{\"name\":\"shopId\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"v\",\"type\":\"uint8\",\"internalType\":\"uint8\"},{\"name\":\"r\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"s\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"user\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"registerUser\",\"inputs\":[{\"name\":\"shopId\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"user\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"perms\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"relayReg\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"contractRelayReg\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"relays\",\"inputs\":[{\"name\":\"shopid\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"removePermission\",\"inputs\":[{\"name\":\"shopId\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"user\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"perm\",\"type\":\"uint8\",\"internalType\":\"uint8\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"removeRelay\",\"inputs\":[{\"name\":\"shopId\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"idx\",\"type\":\"uint8\",\"internalType\":\"uint8\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"removeUser\",\"inputs\":[{\"name\":\"shopId\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"user\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"replaceRelay\",\"inputs\":[{\"name\":\"shopId\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"idx\",\"type\":\"uint8\",\"internalType\":\"uint8\"},{\"name\":\"relayId\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"rootHashes\",\"inputs\":[{\"name\":\"shopid\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"safeTransferFrom\",\"inputs\":[{\"name\":\"from\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"to\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"tokenId\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"safeTransferFrom\",\"inputs\":[{\"name\":\"from\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"to\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"tokenId\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"data\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"setApprovalForAll\",\"inputs\":[{\"name\":\"operator\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"approved\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"setTokenURI\",\"inputs\":[{\"name\":\"shopId\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"newTokenURI\",\"type\":\"string\",\"internalType\":\"string\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"shopURIs\",\"inputs\":[{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[{\"name\":\"\",\"type\":\"string\",\"internalType\":\"string\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"supportsInterface\",\"inputs\":[{\"name\":\"interfaceId\",\"type\":\"bytes4\",\"internalType\":\"bytes4\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"symbol\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"string\",\"internalType\":\"string\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"tokenByIndex\",\"inputs\":[{\"name\":\"index\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"tokenOfOwnerByIndex\",\"inputs\":[{\"name\":\"owner\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"index\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"tokenURI\",\"inputs\":[{\"name\":\"tokenId\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[{\"name\":\"\",\"type\":\"string\",\"internalType\":\"string\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"totalSupply\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"transferFrom\",\"inputs\":[{\"name\":\"from\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"to\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"tokenId\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"updateRootHash\",\"inputs\":[{\"name\":\"shopId\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"hash\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"_nonce\",\"type\":\"uint64\",\"internalType\":\"uint64\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"event\",\"name\":\"Approval\",\"inputs\":[{\"name\":\"owner\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"approved\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"tokenId\",\"type\":\"uint256\",\"indexed\":true,\"internalType\":\"uint256\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"ApprovalForAll\",\"inputs\":[{\"name\":\"owner\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"operator\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"approved\",\"type\":\"bool\",\"indexed\":false,\"internalType\":\"bool\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"BatchMetadataUpdate\",\"inputs\":[{\"name\":\"_fromTokenId\",\"type\":\"uint256\",\"indexed\":false,\"internalType\":\"uint256\"},{\"name\":\"_toTokenId\",\"type\":\"uint256\",\"indexed\":false,\"internalType\":\"uint256\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"MetadataUpdate\",\"inputs\":[{\"name\":\"_tokenId\",\"type\":\"uint256\",\"indexed\":false,\"internalType\":\"uint256\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"PermissionAdded\",\"inputs\":[{\"name\":\"shopId\",\"type\":\"uint256\",\"indexed\":true,\"internalType\":\"uint256\"},{\"name\":\"user\",\"type\":\"address\",\"indexed\":false,\"internalType\":\"address\"},{\"name\":\"permission\",\"type\":\"uint8\",\"indexed\":false,\"internalType\":\"uint8\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"PermissionRemoved\",\"inputs\":[{\"name\":\"shopId\",\"type\":\"uint256\",\"indexed\":true,\"internalType\":\"uint256\"},{\"name\":\"user\",\"type\":\"address\",\"indexed\":false,\"internalType\":\"address\"},{\"name\":\"permission\",\"type\":\"uint8\",\"indexed\":false,\"internalType\":\"uint8\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"Transfer\",\"inputs\":[{\"name\":\"from\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"to\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"tokenId\",\"type\":\"uint256\",\"indexed\":true,\"internalType\":\"uint256\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"UserAdded\",\"inputs\":[{\"name\":\"shopId\",\"type\":\"uint256\",\"indexed\":true,\"internalType\":\"uint256\"},{\"name\":\"user\",\"type\":\"address\",\"indexed\":false,\"internalType\":\"address\"},{\"name\":\"permissions\",\"type\":\"uint256\",\"indexed\":false,\"internalType\":\"uint256\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"UserRemoved\",\"inputs\":[{\"name\":\"shopId\",\"type\":\"uint256\",\"indexed\":true,\"internalType\":\"uint256\"},{\"name\":\"users\",\"type\":\"address\",\"indexed\":false,\"internalType\":\"address\"}],\"anonymous\":false},{\"type\":\"error\",\"name\":\"ERC721EnumerableForbiddenBatchMint\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"ERC721IncorrectOwner\",\"inputs\":[{\"name\":\"sender\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"tokenId\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"owner\",\"type\":\"address\",\"internalType\":\"address\"}]},{\"type\":\"error\",\"name\":\"ERC721InsufficientApproval\",\"inputs\":[{\"name\":\"operator\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"tokenId\",\"type\":\"uint256\",\"internalType\":\"uint256\"}]},{\"type\":\"error\",\"name\":\"ERC721InvalidApprover\",\"inputs\":[{\"name\":\"approver\",\"type\":\"address\",\"internalType\":\"address\"}]},{\"type\":\"error\",\"name\":\"ERC721InvalidOperator\",\"inputs\":[{\"name\":\"operator\",\"type\":\"address\",\"internalType\":\"address\"}]},{\"type\":\"error\",\"name\":\"ERC721InvalidOwner\",\"inputs\":[{\"name\":\"owner\",\"type\":\"address\",\"internalType\":\"address\"}]},{\"type\":\"error\",\"name\":\"ERC721InvalidReceiver\",\"inputs\":[{\"name\":\"receiver\",\"type\":\"address\",\"internalType\":\"address\"}]},{\"type\":\"error\",\"name\":\"ERC721InvalidSender\",\"inputs\":[{\"name\":\"sender\",\"type\":\"address\",\"internalType\":\"address\"}]},{\"type\":\"error\",\"name\":\"ERC721NonexistentToken\",\"inputs\":[{\"name\":\"tokenId\",\"type\":\"uint256\",\"internalType\":\"uint256\"}]},{\"type\":\"error\",\"name\":\"ERC721OutOfBoundsIndex\",\"inputs\":[{\"name\":\"owner\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"index\",\"type\":\"uint256\",\"internalType\":\"uint256\"}]},{\"type\":\"error\",\"name\":\"InvalidNonce\",\"inputs\":[{\"name\":\"cur\",\"type\":\"uint64\",\"internalType\":\"uint64\"},{\"name\":\"_nonce\",\"type\":\"uint64\",\"internalType\":\"uint64\"}]},{\"type\":\"error\",\"name\":\"NoVerifier\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"NotAuthorized\",\"inputs\":[{\"name\":\"permission\",\"type\":\"uint8\",\"internalType\":\"uint8\"}]}]",
}

// RegShopABI is the input ABI used to generate the binding from.
// Deprecated: Use RegShopMetaData.ABI instead.
var RegShopABI = RegShopMetaData.ABI

// RegShop is an auto generated Go binding around an Ethereum contract.
type RegShop struct {
	RegShopCaller     // Read-only binding to the contract
	RegShopTransactor // Write-only binding to the contract
	RegShopFilterer   // Log filterer for contract events
}

// RegShopCaller is an auto generated read-only Go binding around an Ethereum contract.
type RegShopCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// RegShopTransactor is an auto generated write-only Go binding around an Ethereum contract.
type RegShopTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// RegShopFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type RegShopFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// RegShopSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type RegShopSession struct {
	Contract     *RegShop          // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// RegShopCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type RegShopCallerSession struct {
	Contract *RegShopCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts  // Call options to use throughout this session
}

// RegShopTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type RegShopTransactorSession struct {
	Contract     *RegShopTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts  // Transaction auth options to use throughout this session
}

// RegShopRaw is an auto generated low-level Go binding around an Ethereum contract.
type RegShopRaw struct {
	Contract *RegShop // Generic contract binding to access the raw methods on
}

// RegShopCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type RegShopCallerRaw struct {
	Contract *RegShopCaller // Generic read-only contract binding to access the raw methods on
}

// RegShopTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type RegShopTransactorRaw struct {
	Contract *RegShopTransactor // Generic write-only contract binding to access the raw methods on
}

// NewRegShop creates a new instance of RegShop, bound to a specific deployed contract.
func NewRegShop(address common.Address, backend bind.ContractBackend) (*RegShop, error) {
	contract, err := bindRegShop(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &RegShop{RegShopCaller: RegShopCaller{contract: contract}, RegShopTransactor: RegShopTransactor{contract: contract}, RegShopFilterer: RegShopFilterer{contract: contract}}, nil
}

// NewRegShopCaller creates a new read-only instance of RegShop, bound to a specific deployed contract.
func NewRegShopCaller(address common.Address, caller bind.ContractCaller) (*RegShopCaller, error) {
	contract, err := bindRegShop(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &RegShopCaller{contract: contract}, nil
}

// NewRegShopTransactor creates a new write-only instance of RegShop, bound to a specific deployed contract.
func NewRegShopTransactor(address common.Address, transactor bind.ContractTransactor) (*RegShopTransactor, error) {
	contract, err := bindRegShop(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &RegShopTransactor{contract: contract}, nil
}

// NewRegShopFilterer creates a new log filterer instance of RegShop, bound to a specific deployed contract.
func NewRegShopFilterer(address common.Address, filterer bind.ContractFilterer) (*RegShopFilterer, error) {
	contract, err := bindRegShop(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &RegShopFilterer{contract: contract}, nil
}

// bindRegShop binds a generic wrapper to an already deployed contract.
func bindRegShop(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := RegShopMetaData.GetAbi()
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, *parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_RegShop *RegShopRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _RegShop.Contract.RegShopCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_RegShop *RegShopRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _RegShop.Contract.RegShopTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_RegShop *RegShopRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _RegShop.Contract.RegShopTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_RegShop *RegShopCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _RegShop.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_RegShop *RegShopTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _RegShop.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_RegShop *RegShopTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _RegShop.Contract.contract.Transact(opts, method, params...)
}

// PERMAddPermission is a free data retrieval call binding the contract method 0x537f6178.
//
// Solidity: function PERM_addPermission() view returns(uint8)
func (_RegShop *RegShopCaller) PERMAddPermission(opts *bind.CallOpts) (uint8, error) {
	var out []interface{}
	err := _RegShop.contract.Call(opts, &out, "PERM_addPermission")

	if err != nil {
		return *new(uint8), err
	}

	out0 := *abi.ConvertType(out[0], new(uint8)).(*uint8)

	return out0, err

}

// PERMAddPermission is a free data retrieval call binding the contract method 0x537f6178.
//
// Solidity: function PERM_addPermission() view returns(uint8)
func (_RegShop *RegShopSession) PERMAddPermission() (uint8, error) {
	return _RegShop.Contract.PERMAddPermission(&_RegShop.CallOpts)
}

// PERMAddPermission is a free data retrieval call binding the contract method 0x537f6178.
//
// Solidity: function PERM_addPermission() view returns(uint8)
func (_RegShop *RegShopCallerSession) PERMAddPermission() (uint8, error) {
	return _RegShop.Contract.PERMAddPermission(&_RegShop.CallOpts)
}

// PERMAddRelay is a free data retrieval call binding the contract method 0x0fb7bcf7.
//
// Solidity: function PERM_addRelay() view returns(uint8)
func (_RegShop *RegShopCaller) PERMAddRelay(opts *bind.CallOpts) (uint8, error) {
	var out []interface{}
	err := _RegShop.contract.Call(opts, &out, "PERM_addRelay")

	if err != nil {
		return *new(uint8), err
	}

	out0 := *abi.ConvertType(out[0], new(uint8)).(*uint8)

	return out0, err

}

// PERMAddRelay is a free data retrieval call binding the contract method 0x0fb7bcf7.
//
// Solidity: function PERM_addRelay() view returns(uint8)
func (_RegShop *RegShopSession) PERMAddRelay() (uint8, error) {
	return _RegShop.Contract.PERMAddRelay(&_RegShop.CallOpts)
}

// PERMAddRelay is a free data retrieval call binding the contract method 0x0fb7bcf7.
//
// Solidity: function PERM_addRelay() view returns(uint8)
func (_RegShop *RegShopCallerSession) PERMAddRelay() (uint8, error) {
	return _RegShop.Contract.PERMAddRelay(&_RegShop.CallOpts)
}

// PERMPublishInviteVerifier is a free data retrieval call binding the contract method 0x0f66f8d8.
//
// Solidity: function PERM_publishInviteVerifier() view returns(uint8)
func (_RegShop *RegShopCaller) PERMPublishInviteVerifier(opts *bind.CallOpts) (uint8, error) {
	var out []interface{}
	err := _RegShop.contract.Call(opts, &out, "PERM_publishInviteVerifier")

	if err != nil {
		return *new(uint8), err
	}

	out0 := *abi.ConvertType(out[0], new(uint8)).(*uint8)

	return out0, err

}

// PERMPublishInviteVerifier is a free data retrieval call binding the contract method 0x0f66f8d8.
//
// Solidity: function PERM_publishInviteVerifier() view returns(uint8)
func (_RegShop *RegShopSession) PERMPublishInviteVerifier() (uint8, error) {
	return _RegShop.Contract.PERMPublishInviteVerifier(&_RegShop.CallOpts)
}

// PERMPublishInviteVerifier is a free data retrieval call binding the contract method 0x0f66f8d8.
//
// Solidity: function PERM_publishInviteVerifier() view returns(uint8)
func (_RegShop *RegShopCallerSession) PERMPublishInviteVerifier() (uint8, error) {
	return _RegShop.Contract.PERMPublishInviteVerifier(&_RegShop.CallOpts)
}

// PERMRegisterUser is a free data retrieval call binding the contract method 0xd3c90b32.
//
// Solidity: function PERM_registerUser() view returns(uint8)
func (_RegShop *RegShopCaller) PERMRegisterUser(opts *bind.CallOpts) (uint8, error) {
	var out []interface{}
	err := _RegShop.contract.Call(opts, &out, "PERM_registerUser")

	if err != nil {
		return *new(uint8), err
	}

	out0 := *abi.ConvertType(out[0], new(uint8)).(*uint8)

	return out0, err

}

// PERMRegisterUser is a free data retrieval call binding the contract method 0xd3c90b32.
//
// Solidity: function PERM_registerUser() view returns(uint8)
func (_RegShop *RegShopSession) PERMRegisterUser() (uint8, error) {
	return _RegShop.Contract.PERMRegisterUser(&_RegShop.CallOpts)
}

// PERMRegisterUser is a free data retrieval call binding the contract method 0xd3c90b32.
//
// Solidity: function PERM_registerUser() view returns(uint8)
func (_RegShop *RegShopCallerSession) PERMRegisterUser() (uint8, error) {
	return _RegShop.Contract.PERMRegisterUser(&_RegShop.CallOpts)
}

// PERMRemovePermission is a free data retrieval call binding the contract method 0xd1f9f40f.
//
// Solidity: function PERM_removePermission() view returns(uint8)
func (_RegShop *RegShopCaller) PERMRemovePermission(opts *bind.CallOpts) (uint8, error) {
	var out []interface{}
	err := _RegShop.contract.Call(opts, &out, "PERM_removePermission")

	if err != nil {
		return *new(uint8), err
	}

	out0 := *abi.ConvertType(out[0], new(uint8)).(*uint8)

	return out0, err

}

// PERMRemovePermission is a free data retrieval call binding the contract method 0xd1f9f40f.
//
// Solidity: function PERM_removePermission() view returns(uint8)
func (_RegShop *RegShopSession) PERMRemovePermission() (uint8, error) {
	return _RegShop.Contract.PERMRemovePermission(&_RegShop.CallOpts)
}

// PERMRemovePermission is a free data retrieval call binding the contract method 0xd1f9f40f.
//
// Solidity: function PERM_removePermission() view returns(uint8)
func (_RegShop *RegShopCallerSession) PERMRemovePermission() (uint8, error) {
	return _RegShop.Contract.PERMRemovePermission(&_RegShop.CallOpts)
}

// PERMRemoveRelay is a free data retrieval call binding the contract method 0x5a59cd3d.
//
// Solidity: function PERM_removeRelay() view returns(uint8)
func (_RegShop *RegShopCaller) PERMRemoveRelay(opts *bind.CallOpts) (uint8, error) {
	var out []interface{}
	err := _RegShop.contract.Call(opts, &out, "PERM_removeRelay")

	if err != nil {
		return *new(uint8), err
	}

	out0 := *abi.ConvertType(out[0], new(uint8)).(*uint8)

	return out0, err

}

// PERMRemoveRelay is a free data retrieval call binding the contract method 0x5a59cd3d.
//
// Solidity: function PERM_removeRelay() view returns(uint8)
func (_RegShop *RegShopSession) PERMRemoveRelay() (uint8, error) {
	return _RegShop.Contract.PERMRemoveRelay(&_RegShop.CallOpts)
}

// PERMRemoveRelay is a free data retrieval call binding the contract method 0x5a59cd3d.
//
// Solidity: function PERM_removeRelay() view returns(uint8)
func (_RegShop *RegShopCallerSession) PERMRemoveRelay() (uint8, error) {
	return _RegShop.Contract.PERMRemoveRelay(&_RegShop.CallOpts)
}

// PERMRemoveUser is a free data retrieval call binding the contract method 0xd0f64f9c.
//
// Solidity: function PERM_removeUser() view returns(uint8)
func (_RegShop *RegShopCaller) PERMRemoveUser(opts *bind.CallOpts) (uint8, error) {
	var out []interface{}
	err := _RegShop.contract.Call(opts, &out, "PERM_removeUser")

	if err != nil {
		return *new(uint8), err
	}

	out0 := *abi.ConvertType(out[0], new(uint8)).(*uint8)

	return out0, err

}

// PERMRemoveUser is a free data retrieval call binding the contract method 0xd0f64f9c.
//
// Solidity: function PERM_removeUser() view returns(uint8)
func (_RegShop *RegShopSession) PERMRemoveUser() (uint8, error) {
	return _RegShop.Contract.PERMRemoveUser(&_RegShop.CallOpts)
}

// PERMRemoveUser is a free data retrieval call binding the contract method 0xd0f64f9c.
//
// Solidity: function PERM_removeUser() view returns(uint8)
func (_RegShop *RegShopCallerSession) PERMRemoveUser() (uint8, error) {
	return _RegShop.Contract.PERMRemoveUser(&_RegShop.CallOpts)
}

// PERMReplaceRelay is a free data retrieval call binding the contract method 0xbecf4da4.
//
// Solidity: function PERM_replaceRelay() view returns(uint8)
func (_RegShop *RegShopCaller) PERMReplaceRelay(opts *bind.CallOpts) (uint8, error) {
	var out []interface{}
	err := _RegShop.contract.Call(opts, &out, "PERM_replaceRelay")

	if err != nil {
		return *new(uint8), err
	}

	out0 := *abi.ConvertType(out[0], new(uint8)).(*uint8)

	return out0, err

}

// PERMReplaceRelay is a free data retrieval call binding the contract method 0xbecf4da4.
//
// Solidity: function PERM_replaceRelay() view returns(uint8)
func (_RegShop *RegShopSession) PERMReplaceRelay() (uint8, error) {
	return _RegShop.Contract.PERMReplaceRelay(&_RegShop.CallOpts)
}

// PERMReplaceRelay is a free data retrieval call binding the contract method 0xbecf4da4.
//
// Solidity: function PERM_replaceRelay() view returns(uint8)
func (_RegShop *RegShopCallerSession) PERMReplaceRelay() (uint8, error) {
	return _RegShop.Contract.PERMReplaceRelay(&_RegShop.CallOpts)
}

// PERMUpdateRootHash is a free data retrieval call binding the contract method 0xbcd18721.
//
// Solidity: function PERM_updateRootHash() view returns(uint8)
func (_RegShop *RegShopCaller) PERMUpdateRootHash(opts *bind.CallOpts) (uint8, error) {
	var out []interface{}
	err := _RegShop.contract.Call(opts, &out, "PERM_updateRootHash")

	if err != nil {
		return *new(uint8), err
	}

	out0 := *abi.ConvertType(out[0], new(uint8)).(*uint8)

	return out0, err

}

// PERMUpdateRootHash is a free data retrieval call binding the contract method 0xbcd18721.
//
// Solidity: function PERM_updateRootHash() view returns(uint8)
func (_RegShop *RegShopSession) PERMUpdateRootHash() (uint8, error) {
	return _RegShop.Contract.PERMUpdateRootHash(&_RegShop.CallOpts)
}

// PERMUpdateRootHash is a free data retrieval call binding the contract method 0xbcd18721.
//
// Solidity: function PERM_updateRootHash() view returns(uint8)
func (_RegShop *RegShopCallerSession) PERMUpdateRootHash() (uint8, error) {
	return _RegShop.Contract.PERMUpdateRootHash(&_RegShop.CallOpts)
}

// GetTokenMessageHash is a free data retrieval call binding the contract method 0x46e4a913.
//
// Solidity: function _getTokenMessageHash(address user) pure returns(bytes32)
func (_RegShop *RegShopCaller) GetTokenMessageHash(opts *bind.CallOpts, user common.Address) ([32]byte, error) {
	var out []interface{}
	err := _RegShop.contract.Call(opts, &out, "_getTokenMessageHash", user)

	if err != nil {
		return *new([32]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([32]byte)).(*[32]byte)

	return out0, err

}

// GetTokenMessageHash is a free data retrieval call binding the contract method 0x46e4a913.
//
// Solidity: function _getTokenMessageHash(address user) pure returns(bytes32)
func (_RegShop *RegShopSession) GetTokenMessageHash(user common.Address) ([32]byte, error) {
	return _RegShop.Contract.GetTokenMessageHash(&_RegShop.CallOpts, user)
}

// GetTokenMessageHash is a free data retrieval call binding the contract method 0x46e4a913.
//
// Solidity: function _getTokenMessageHash(address user) pure returns(bytes32)
func (_RegShop *RegShopCallerSession) GetTokenMessageHash(user common.Address) ([32]byte, error) {
	return _RegShop.Contract.GetTokenMessageHash(&_RegShop.CallOpts, user)
}

// AllPermissionsGuard is a free data retrieval call binding the contract method 0x53b8c992.
//
// Solidity: function allPermissionsGuard(uint256 id, uint256 perms) view returns()
func (_RegShop *RegShopCaller) AllPermissionsGuard(opts *bind.CallOpts, id *big.Int, perms *big.Int) error {
	var out []interface{}
	err := _RegShop.contract.Call(opts, &out, "allPermissionsGuard", id, perms)

	if err != nil {
		return err
	}

	return err

}

// AllPermissionsGuard is a free data retrieval call binding the contract method 0x53b8c992.
//
// Solidity: function allPermissionsGuard(uint256 id, uint256 perms) view returns()
func (_RegShop *RegShopSession) AllPermissionsGuard(id *big.Int, perms *big.Int) error {
	return _RegShop.Contract.AllPermissionsGuard(&_RegShop.CallOpts, id, perms)
}

// AllPermissionsGuard is a free data retrieval call binding the contract method 0x53b8c992.
//
// Solidity: function allPermissionsGuard(uint256 id, uint256 perms) view returns()
func (_RegShop *RegShopCallerSession) AllPermissionsGuard(id *big.Int, perms *big.Int) error {
	return _RegShop.Contract.AllPermissionsGuard(&_RegShop.CallOpts, id, perms)
}

// BalanceOf is a free data retrieval call binding the contract method 0x70a08231.
//
// Solidity: function balanceOf(address owner) view returns(uint256)
func (_RegShop *RegShopCaller) BalanceOf(opts *bind.CallOpts, owner common.Address) (*big.Int, error) {
	var out []interface{}
	err := _RegShop.contract.Call(opts, &out, "balanceOf", owner)

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// BalanceOf is a free data retrieval call binding the contract method 0x70a08231.
//
// Solidity: function balanceOf(address owner) view returns(uint256)
func (_RegShop *RegShopSession) BalanceOf(owner common.Address) (*big.Int, error) {
	return _RegShop.Contract.BalanceOf(&_RegShop.CallOpts, owner)
}

// BalanceOf is a free data retrieval call binding the contract method 0x70a08231.
//
// Solidity: function balanceOf(address owner) view returns(uint256)
func (_RegShop *RegShopCallerSession) BalanceOf(owner common.Address) (*big.Int, error) {
	return _RegShop.Contract.BalanceOf(&_RegShop.CallOpts, owner)
}

// GetAllPermissions is a free data retrieval call binding the contract method 0xcb5c0bc1.
//
// Solidity: function getAllPermissions(uint256 id, address user) view returns(uint256)
func (_RegShop *RegShopCaller) GetAllPermissions(opts *bind.CallOpts, id *big.Int, user common.Address) (*big.Int, error) {
	var out []interface{}
	err := _RegShop.contract.Call(opts, &out, "getAllPermissions", id, user)

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// GetAllPermissions is a free data retrieval call binding the contract method 0xcb5c0bc1.
//
// Solidity: function getAllPermissions(uint256 id, address user) view returns(uint256)
func (_RegShop *RegShopSession) GetAllPermissions(id *big.Int, user common.Address) (*big.Int, error) {
	return _RegShop.Contract.GetAllPermissions(&_RegShop.CallOpts, id, user)
}

// GetAllPermissions is a free data retrieval call binding the contract method 0xcb5c0bc1.
//
// Solidity: function getAllPermissions(uint256 id, address user) view returns(uint256)
func (_RegShop *RegShopCallerSession) GetAllPermissions(id *big.Int, user common.Address) (*big.Int, error) {
	return _RegShop.Contract.GetAllPermissions(&_RegShop.CallOpts, id, user)
}

// GetAllRelays is a free data retrieval call binding the contract method 0xce667ce7.
//
// Solidity: function getAllRelays(uint256 shopId) view returns(uint256[])
func (_RegShop *RegShopCaller) GetAllRelays(opts *bind.CallOpts, shopId *big.Int) ([]*big.Int, error) {
	var out []interface{}
	err := _RegShop.contract.Call(opts, &out, "getAllRelays", shopId)

	if err != nil {
		return *new([]*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new([]*big.Int)).(*[]*big.Int)

	return out0, err

}

// GetAllRelays is a free data retrieval call binding the contract method 0xce667ce7.
//
// Solidity: function getAllRelays(uint256 shopId) view returns(uint256[])
func (_RegShop *RegShopSession) GetAllRelays(shopId *big.Int) ([]*big.Int, error) {
	return _RegShop.Contract.GetAllRelays(&_RegShop.CallOpts, shopId)
}

// GetAllRelays is a free data retrieval call binding the contract method 0xce667ce7.
//
// Solidity: function getAllRelays(uint256 shopId) view returns(uint256[])
func (_RegShop *RegShopCallerSession) GetAllRelays(shopId *big.Int) ([]*big.Int, error) {
	return _RegShop.Contract.GetAllRelays(&_RegShop.CallOpts, shopId)
}

// GetApproved is a free data retrieval call binding the contract method 0x081812fc.
//
// Solidity: function getApproved(uint256 tokenId) view returns(address)
func (_RegShop *RegShopCaller) GetApproved(opts *bind.CallOpts, tokenId *big.Int) (common.Address, error) {
	var out []interface{}
	err := _RegShop.contract.Call(opts, &out, "getApproved", tokenId)

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// GetApproved is a free data retrieval call binding the contract method 0x081812fc.
//
// Solidity: function getApproved(uint256 tokenId) view returns(address)
func (_RegShop *RegShopSession) GetApproved(tokenId *big.Int) (common.Address, error) {
	return _RegShop.Contract.GetApproved(&_RegShop.CallOpts, tokenId)
}

// GetApproved is a free data retrieval call binding the contract method 0x081812fc.
//
// Solidity: function getApproved(uint256 tokenId) view returns(address)
func (_RegShop *RegShopCallerSession) GetApproved(tokenId *big.Int) (common.Address, error) {
	return _RegShop.Contract.GetApproved(&_RegShop.CallOpts, tokenId)
}

// GetRelayCount is a free data retrieval call binding the contract method 0x61e11a5f.
//
// Solidity: function getRelayCount(uint256 shopId) view returns(uint256)
func (_RegShop *RegShopCaller) GetRelayCount(opts *bind.CallOpts, shopId *big.Int) (*big.Int, error) {
	var out []interface{}
	err := _RegShop.contract.Call(opts, &out, "getRelayCount", shopId)

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// GetRelayCount is a free data retrieval call binding the contract method 0x61e11a5f.
//
// Solidity: function getRelayCount(uint256 shopId) view returns(uint256)
func (_RegShop *RegShopSession) GetRelayCount(shopId *big.Int) (*big.Int, error) {
	return _RegShop.Contract.GetRelayCount(&_RegShop.CallOpts, shopId)
}

// GetRelayCount is a free data retrieval call binding the contract method 0x61e11a5f.
//
// Solidity: function getRelayCount(uint256 shopId) view returns(uint256)
func (_RegShop *RegShopCallerSession) GetRelayCount(shopId *big.Int) (*big.Int, error) {
	return _RegShop.Contract.GetRelayCount(&_RegShop.CallOpts, shopId)
}

// HasEnoughPermissions is a free data retrieval call binding the contract method 0x2e80d594.
//
// Solidity: function hasEnoughPermissions(uint256 id, address user, uint256 perms) view returns(bool)
func (_RegShop *RegShopCaller) HasEnoughPermissions(opts *bind.CallOpts, id *big.Int, user common.Address, perms *big.Int) (bool, error) {
	var out []interface{}
	err := _RegShop.contract.Call(opts, &out, "hasEnoughPermissions", id, user, perms)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// HasEnoughPermissions is a free data retrieval call binding the contract method 0x2e80d594.
//
// Solidity: function hasEnoughPermissions(uint256 id, address user, uint256 perms) view returns(bool)
func (_RegShop *RegShopSession) HasEnoughPermissions(id *big.Int, user common.Address, perms *big.Int) (bool, error) {
	return _RegShop.Contract.HasEnoughPermissions(&_RegShop.CallOpts, id, user, perms)
}

// HasEnoughPermissions is a free data retrieval call binding the contract method 0x2e80d594.
//
// Solidity: function hasEnoughPermissions(uint256 id, address user, uint256 perms) view returns(bool)
func (_RegShop *RegShopCallerSession) HasEnoughPermissions(id *big.Int, user common.Address, perms *big.Int) (bool, error) {
	return _RegShop.Contract.HasEnoughPermissions(&_RegShop.CallOpts, id, user, perms)
}

// HasPermission is a free data retrieval call binding the contract method 0x823abfd9.
//
// Solidity: function hasPermission(uint256 id, address user, uint8 perm) view returns(bool)
func (_RegShop *RegShopCaller) HasPermission(opts *bind.CallOpts, id *big.Int, user common.Address, perm uint8) (bool, error) {
	var out []interface{}
	err := _RegShop.contract.Call(opts, &out, "hasPermission", id, user, perm)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// HasPermission is a free data retrieval call binding the contract method 0x823abfd9.
//
// Solidity: function hasPermission(uint256 id, address user, uint8 perm) view returns(bool)
func (_RegShop *RegShopSession) HasPermission(id *big.Int, user common.Address, perm uint8) (bool, error) {
	return _RegShop.Contract.HasPermission(&_RegShop.CallOpts, id, user, perm)
}

// HasPermission is a free data retrieval call binding the contract method 0x823abfd9.
//
// Solidity: function hasPermission(uint256 id, address user, uint8 perm) view returns(bool)
func (_RegShop *RegShopCallerSession) HasPermission(id *big.Int, user common.Address, perm uint8) (bool, error) {
	return _RegShop.Contract.HasPermission(&_RegShop.CallOpts, id, user, perm)
}

// IsApprovedForAll is a free data retrieval call binding the contract method 0xe985e9c5.
//
// Solidity: function isApprovedForAll(address owner, address operator) view returns(bool)
func (_RegShop *RegShopCaller) IsApprovedForAll(opts *bind.CallOpts, owner common.Address, operator common.Address) (bool, error) {
	var out []interface{}
	err := _RegShop.contract.Call(opts, &out, "isApprovedForAll", owner, operator)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// IsApprovedForAll is a free data retrieval call binding the contract method 0xe985e9c5.
//
// Solidity: function isApprovedForAll(address owner, address operator) view returns(bool)
func (_RegShop *RegShopSession) IsApprovedForAll(owner common.Address, operator common.Address) (bool, error) {
	return _RegShop.Contract.IsApprovedForAll(&_RegShop.CallOpts, owner, operator)
}

// IsApprovedForAll is a free data retrieval call binding the contract method 0xe985e9c5.
//
// Solidity: function isApprovedForAll(address owner, address operator) view returns(bool)
func (_RegShop *RegShopCallerSession) IsApprovedForAll(owner common.Address, operator common.Address) (bool, error) {
	return _RegShop.Contract.IsApprovedForAll(&_RegShop.CallOpts, owner, operator)
}

// Name is a free data retrieval call binding the contract method 0x06fdde03.
//
// Solidity: function name() view returns(string)
func (_RegShop *RegShopCaller) Name(opts *bind.CallOpts) (string, error) {
	var out []interface{}
	err := _RegShop.contract.Call(opts, &out, "name")

	if err != nil {
		return *new(string), err
	}

	out0 := *abi.ConvertType(out[0], new(string)).(*string)

	return out0, err

}

// Name is a free data retrieval call binding the contract method 0x06fdde03.
//
// Solidity: function name() view returns(string)
func (_RegShop *RegShopSession) Name() (string, error) {
	return _RegShop.Contract.Name(&_RegShop.CallOpts)
}

// Name is a free data retrieval call binding the contract method 0x06fdde03.
//
// Solidity: function name() view returns(string)
func (_RegShop *RegShopCallerSession) Name() (string, error) {
	return _RegShop.Contract.Name(&_RegShop.CallOpts)
}

// Nonce is a free data retrieval call binding the contract method 0xce03fdab.
//
// Solidity: function nonce(uint256 shopid) view returns(uint64)
func (_RegShop *RegShopCaller) Nonce(opts *bind.CallOpts, shopid *big.Int) (uint64, error) {
	var out []interface{}
	err := _RegShop.contract.Call(opts, &out, "nonce", shopid)

	if err != nil {
		return *new(uint64), err
	}

	out0 := *abi.ConvertType(out[0], new(uint64)).(*uint64)

	return out0, err

}

// Nonce is a free data retrieval call binding the contract method 0xce03fdab.
//
// Solidity: function nonce(uint256 shopid) view returns(uint64)
func (_RegShop *RegShopSession) Nonce(shopid *big.Int) (uint64, error) {
	return _RegShop.Contract.Nonce(&_RegShop.CallOpts, shopid)
}

// Nonce is a free data retrieval call binding the contract method 0xce03fdab.
//
// Solidity: function nonce(uint256 shopid) view returns(uint64)
func (_RegShop *RegShopCallerSession) Nonce(shopid *big.Int) (uint64, error) {
	return _RegShop.Contract.Nonce(&_RegShop.CallOpts, shopid)
}

// OwnerOf is a free data retrieval call binding the contract method 0x6352211e.
//
// Solidity: function ownerOf(uint256 tokenId) view returns(address)
func (_RegShop *RegShopCaller) OwnerOf(opts *bind.CallOpts, tokenId *big.Int) (common.Address, error) {
	var out []interface{}
	err := _RegShop.contract.Call(opts, &out, "ownerOf", tokenId)

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// OwnerOf is a free data retrieval call binding the contract method 0x6352211e.
//
// Solidity: function ownerOf(uint256 tokenId) view returns(address)
func (_RegShop *RegShopSession) OwnerOf(tokenId *big.Int) (common.Address, error) {
	return _RegShop.Contract.OwnerOf(&_RegShop.CallOpts, tokenId)
}

// OwnerOf is a free data retrieval call binding the contract method 0x6352211e.
//
// Solidity: function ownerOf(uint256 tokenId) view returns(address)
func (_RegShop *RegShopCallerSession) OwnerOf(tokenId *big.Int) (common.Address, error) {
	return _RegShop.Contract.OwnerOf(&_RegShop.CallOpts, tokenId)
}

// PermissionGuard is a free data retrieval call binding the contract method 0xe87b17b4.
//
// Solidity: function permissionGuard(uint256 id, uint8 perm) view returns()
func (_RegShop *RegShopCaller) PermissionGuard(opts *bind.CallOpts, id *big.Int, perm uint8) error {
	var out []interface{}
	err := _RegShop.contract.Call(opts, &out, "permissionGuard", id, perm)

	if err != nil {
		return err
	}

	return err

}

// PermissionGuard is a free data retrieval call binding the contract method 0xe87b17b4.
//
// Solidity: function permissionGuard(uint256 id, uint8 perm) view returns()
func (_RegShop *RegShopSession) PermissionGuard(id *big.Int, perm uint8) error {
	return _RegShop.Contract.PermissionGuard(&_RegShop.CallOpts, id, perm)
}

// PermissionGuard is a free data retrieval call binding the contract method 0xe87b17b4.
//
// Solidity: function permissionGuard(uint256 id, uint8 perm) view returns()
func (_RegShop *RegShopCallerSession) PermissionGuard(id *big.Int, perm uint8) error {
	return _RegShop.Contract.PermissionGuard(&_RegShop.CallOpts, id, perm)
}

// PermsToBitmap is a free data retrieval call binding the contract method 0x06232ef4.
//
// Solidity: function permsToBitmap(uint8[] perms) pure returns(uint256)
func (_RegShop *RegShopCaller) PermsToBitmap(opts *bind.CallOpts, perms []uint8) (*big.Int, error) {
	var out []interface{}
	err := _RegShop.contract.Call(opts, &out, "permsToBitmap", perms)

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// PermsToBitmap is a free data retrieval call binding the contract method 0x06232ef4.
//
// Solidity: function permsToBitmap(uint8[] perms) pure returns(uint256)
func (_RegShop *RegShopSession) PermsToBitmap(perms []uint8) (*big.Int, error) {
	return _RegShop.Contract.PermsToBitmap(&_RegShop.CallOpts, perms)
}

// PermsToBitmap is a free data retrieval call binding the contract method 0x06232ef4.
//
// Solidity: function permsToBitmap(uint8[] perms) pure returns(uint256)
func (_RegShop *RegShopCallerSession) PermsToBitmap(perms []uint8) (*big.Int, error) {
	return _RegShop.Contract.PermsToBitmap(&_RegShop.CallOpts, perms)
}

// RelayReg is a free data retrieval call binding the contract method 0x38887dde.
//
// Solidity: function relayReg() view returns(address)
func (_RegShop *RegShopCaller) RelayReg(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _RegShop.contract.Call(opts, &out, "relayReg")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// RelayReg is a free data retrieval call binding the contract method 0x38887dde.
//
// Solidity: function relayReg() view returns(address)
func (_RegShop *RegShopSession) RelayReg() (common.Address, error) {
	return _RegShop.Contract.RelayReg(&_RegShop.CallOpts)
}

// RelayReg is a free data retrieval call binding the contract method 0x38887dde.
//
// Solidity: function relayReg() view returns(address)
func (_RegShop *RegShopCallerSession) RelayReg() (common.Address, error) {
	return _RegShop.Contract.RelayReg(&_RegShop.CallOpts)
}

// Relays is a free data retrieval call binding the contract method 0xb08cfd15.
//
// Solidity: function relays(uint256 shopid, uint256 ) view returns(uint256)
func (_RegShop *RegShopCaller) Relays(opts *bind.CallOpts, shopid *big.Int, arg1 *big.Int) (*big.Int, error) {
	var out []interface{}
	err := _RegShop.contract.Call(opts, &out, "relays", shopid, arg1)

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// Relays is a free data retrieval call binding the contract method 0xb08cfd15.
//
// Solidity: function relays(uint256 shopid, uint256 ) view returns(uint256)
func (_RegShop *RegShopSession) Relays(shopid *big.Int, arg1 *big.Int) (*big.Int, error) {
	return _RegShop.Contract.Relays(&_RegShop.CallOpts, shopid, arg1)
}

// Relays is a free data retrieval call binding the contract method 0xb08cfd15.
//
// Solidity: function relays(uint256 shopid, uint256 ) view returns(uint256)
func (_RegShop *RegShopCallerSession) Relays(shopid *big.Int, arg1 *big.Int) (*big.Int, error) {
	return _RegShop.Contract.Relays(&_RegShop.CallOpts, shopid, arg1)
}

// RootHashes is a free data retrieval call binding the contract method 0x53b93557.
//
// Solidity: function rootHashes(uint256 shopid) view returns(bytes32)
func (_RegShop *RegShopCaller) RootHashes(opts *bind.CallOpts, shopid *big.Int) ([32]byte, error) {
	var out []interface{}
	err := _RegShop.contract.Call(opts, &out, "rootHashes", shopid)

	if err != nil {
		return *new([32]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([32]byte)).(*[32]byte)

	return out0, err

}

// RootHashes is a free data retrieval call binding the contract method 0x53b93557.
//
// Solidity: function rootHashes(uint256 shopid) view returns(bytes32)
func (_RegShop *RegShopSession) RootHashes(shopid *big.Int) ([32]byte, error) {
	return _RegShop.Contract.RootHashes(&_RegShop.CallOpts, shopid)
}

// RootHashes is a free data retrieval call binding the contract method 0x53b93557.
//
// Solidity: function rootHashes(uint256 shopid) view returns(bytes32)
func (_RegShop *RegShopCallerSession) RootHashes(shopid *big.Int) ([32]byte, error) {
	return _RegShop.Contract.RootHashes(&_RegShop.CallOpts, shopid)
}

// ShopURIs is a free data retrieval call binding the contract method 0x2229d8f6.
//
// Solidity: function shopURIs(uint256 ) view returns(string)
func (_RegShop *RegShopCaller) ShopURIs(opts *bind.CallOpts, arg0 *big.Int) (string, error) {
	var out []interface{}
	err := _RegShop.contract.Call(opts, &out, "shopURIs", arg0)

	if err != nil {
		return *new(string), err
	}

	out0 := *abi.ConvertType(out[0], new(string)).(*string)

	return out0, err

}

// ShopURIs is a free data retrieval call binding the contract method 0x2229d8f6.
//
// Solidity: function shopURIs(uint256 ) view returns(string)
func (_RegShop *RegShopSession) ShopURIs(arg0 *big.Int) (string, error) {
	return _RegShop.Contract.ShopURIs(&_RegShop.CallOpts, arg0)
}

// ShopURIs is a free data retrieval call binding the contract method 0x2229d8f6.
//
// Solidity: function shopURIs(uint256 ) view returns(string)
func (_RegShop *RegShopCallerSession) ShopURIs(arg0 *big.Int) (string, error) {
	return _RegShop.Contract.ShopURIs(&_RegShop.CallOpts, arg0)
}

// SupportsInterface is a free data retrieval call binding the contract method 0x01ffc9a7.
//
// Solidity: function supportsInterface(bytes4 interfaceId) view returns(bool)
func (_RegShop *RegShopCaller) SupportsInterface(opts *bind.CallOpts, interfaceId [4]byte) (bool, error) {
	var out []interface{}
	err := _RegShop.contract.Call(opts, &out, "supportsInterface", interfaceId)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// SupportsInterface is a free data retrieval call binding the contract method 0x01ffc9a7.
//
// Solidity: function supportsInterface(bytes4 interfaceId) view returns(bool)
func (_RegShop *RegShopSession) SupportsInterface(interfaceId [4]byte) (bool, error) {
	return _RegShop.Contract.SupportsInterface(&_RegShop.CallOpts, interfaceId)
}

// SupportsInterface is a free data retrieval call binding the contract method 0x01ffc9a7.
//
// Solidity: function supportsInterface(bytes4 interfaceId) view returns(bool)
func (_RegShop *RegShopCallerSession) SupportsInterface(interfaceId [4]byte) (bool, error) {
	return _RegShop.Contract.SupportsInterface(&_RegShop.CallOpts, interfaceId)
}

// Symbol is a free data retrieval call binding the contract method 0x95d89b41.
//
// Solidity: function symbol() view returns(string)
func (_RegShop *RegShopCaller) Symbol(opts *bind.CallOpts) (string, error) {
	var out []interface{}
	err := _RegShop.contract.Call(opts, &out, "symbol")

	if err != nil {
		return *new(string), err
	}

	out0 := *abi.ConvertType(out[0], new(string)).(*string)

	return out0, err

}

// Symbol is a free data retrieval call binding the contract method 0x95d89b41.
//
// Solidity: function symbol() view returns(string)
func (_RegShop *RegShopSession) Symbol() (string, error) {
	return _RegShop.Contract.Symbol(&_RegShop.CallOpts)
}

// Symbol is a free data retrieval call binding the contract method 0x95d89b41.
//
// Solidity: function symbol() view returns(string)
func (_RegShop *RegShopCallerSession) Symbol() (string, error) {
	return _RegShop.Contract.Symbol(&_RegShop.CallOpts)
}

// TokenByIndex is a free data retrieval call binding the contract method 0x4f6ccce7.
//
// Solidity: function tokenByIndex(uint256 index) view returns(uint256)
func (_RegShop *RegShopCaller) TokenByIndex(opts *bind.CallOpts, index *big.Int) (*big.Int, error) {
	var out []interface{}
	err := _RegShop.contract.Call(opts, &out, "tokenByIndex", index)

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// TokenByIndex is a free data retrieval call binding the contract method 0x4f6ccce7.
//
// Solidity: function tokenByIndex(uint256 index) view returns(uint256)
func (_RegShop *RegShopSession) TokenByIndex(index *big.Int) (*big.Int, error) {
	return _RegShop.Contract.TokenByIndex(&_RegShop.CallOpts, index)
}

// TokenByIndex is a free data retrieval call binding the contract method 0x4f6ccce7.
//
// Solidity: function tokenByIndex(uint256 index) view returns(uint256)
func (_RegShop *RegShopCallerSession) TokenByIndex(index *big.Int) (*big.Int, error) {
	return _RegShop.Contract.TokenByIndex(&_RegShop.CallOpts, index)
}

// TokenOfOwnerByIndex is a free data retrieval call binding the contract method 0x2f745c59.
//
// Solidity: function tokenOfOwnerByIndex(address owner, uint256 index) view returns(uint256)
func (_RegShop *RegShopCaller) TokenOfOwnerByIndex(opts *bind.CallOpts, owner common.Address, index *big.Int) (*big.Int, error) {
	var out []interface{}
	err := _RegShop.contract.Call(opts, &out, "tokenOfOwnerByIndex", owner, index)

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// TokenOfOwnerByIndex is a free data retrieval call binding the contract method 0x2f745c59.
//
// Solidity: function tokenOfOwnerByIndex(address owner, uint256 index) view returns(uint256)
func (_RegShop *RegShopSession) TokenOfOwnerByIndex(owner common.Address, index *big.Int) (*big.Int, error) {
	return _RegShop.Contract.TokenOfOwnerByIndex(&_RegShop.CallOpts, owner, index)
}

// TokenOfOwnerByIndex is a free data retrieval call binding the contract method 0x2f745c59.
//
// Solidity: function tokenOfOwnerByIndex(address owner, uint256 index) view returns(uint256)
func (_RegShop *RegShopCallerSession) TokenOfOwnerByIndex(owner common.Address, index *big.Int) (*big.Int, error) {
	return _RegShop.Contract.TokenOfOwnerByIndex(&_RegShop.CallOpts, owner, index)
}

// TokenURI is a free data retrieval call binding the contract method 0xc87b56dd.
//
// Solidity: function tokenURI(uint256 tokenId) view returns(string)
func (_RegShop *RegShopCaller) TokenURI(opts *bind.CallOpts, tokenId *big.Int) (string, error) {
	var out []interface{}
	err := _RegShop.contract.Call(opts, &out, "tokenURI", tokenId)

	if err != nil {
		return *new(string), err
	}

	out0 := *abi.ConvertType(out[0], new(string)).(*string)

	return out0, err

}

// TokenURI is a free data retrieval call binding the contract method 0xc87b56dd.
//
// Solidity: function tokenURI(uint256 tokenId) view returns(string)
func (_RegShop *RegShopSession) TokenURI(tokenId *big.Int) (string, error) {
	return _RegShop.Contract.TokenURI(&_RegShop.CallOpts, tokenId)
}

// TokenURI is a free data retrieval call binding the contract method 0xc87b56dd.
//
// Solidity: function tokenURI(uint256 tokenId) view returns(string)
func (_RegShop *RegShopCallerSession) TokenURI(tokenId *big.Int) (string, error) {
	return _RegShop.Contract.TokenURI(&_RegShop.CallOpts, tokenId)
}

// TotalSupply is a free data retrieval call binding the contract method 0x18160ddd.
//
// Solidity: function totalSupply() view returns(uint256)
func (_RegShop *RegShopCaller) TotalSupply(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _RegShop.contract.Call(opts, &out, "totalSupply")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// TotalSupply is a free data retrieval call binding the contract method 0x18160ddd.
//
// Solidity: function totalSupply() view returns(uint256)
func (_RegShop *RegShopSession) TotalSupply() (*big.Int, error) {
	return _RegShop.Contract.TotalSupply(&_RegShop.CallOpts)
}

// TotalSupply is a free data retrieval call binding the contract method 0x18160ddd.
//
// Solidity: function totalSupply() view returns(uint256)
func (_RegShop *RegShopCallerSession) TotalSupply() (*big.Int, error) {
	return _RegShop.Contract.TotalSupply(&_RegShop.CallOpts)
}

// AddPermission is a paid mutator transaction binding the contract method 0x07c2bdd2.
//
// Solidity: function addPermission(uint256 shopId, address user, uint8 perm) returns()
func (_RegShop *RegShopTransactor) AddPermission(opts *bind.TransactOpts, shopId *big.Int, user common.Address, perm uint8) (*types.Transaction, error) {
	return _RegShop.contract.Transact(opts, "addPermission", shopId, user, perm)
}

// AddPermission is a paid mutator transaction binding the contract method 0x07c2bdd2.
//
// Solidity: function addPermission(uint256 shopId, address user, uint8 perm) returns()
func (_RegShop *RegShopSession) AddPermission(shopId *big.Int, user common.Address, perm uint8) (*types.Transaction, error) {
	return _RegShop.Contract.AddPermission(&_RegShop.TransactOpts, shopId, user, perm)
}

// AddPermission is a paid mutator transaction binding the contract method 0x07c2bdd2.
//
// Solidity: function addPermission(uint256 shopId, address user, uint8 perm) returns()
func (_RegShop *RegShopTransactorSession) AddPermission(shopId *big.Int, user common.Address, perm uint8) (*types.Transaction, error) {
	return _RegShop.Contract.AddPermission(&_RegShop.TransactOpts, shopId, user, perm)
}

// AddRelay is a paid mutator transaction binding the contract method 0x48f6092a.
//
// Solidity: function addRelay(uint256 shopId, uint256 relayId) returns()
func (_RegShop *RegShopTransactor) AddRelay(opts *bind.TransactOpts, shopId *big.Int, relayId *big.Int) (*types.Transaction, error) {
	return _RegShop.contract.Transact(opts, "addRelay", shopId, relayId)
}

// AddRelay is a paid mutator transaction binding the contract method 0x48f6092a.
//
// Solidity: function addRelay(uint256 shopId, uint256 relayId) returns()
func (_RegShop *RegShopSession) AddRelay(shopId *big.Int, relayId *big.Int) (*types.Transaction, error) {
	return _RegShop.Contract.AddRelay(&_RegShop.TransactOpts, shopId, relayId)
}

// AddRelay is a paid mutator transaction binding the contract method 0x48f6092a.
//
// Solidity: function addRelay(uint256 shopId, uint256 relayId) returns()
func (_RegShop *RegShopTransactorSession) AddRelay(shopId *big.Int, relayId *big.Int) (*types.Transaction, error) {
	return _RegShop.Contract.AddRelay(&_RegShop.TransactOpts, shopId, relayId)
}

// Approve is a paid mutator transaction binding the contract method 0x095ea7b3.
//
// Solidity: function approve(address to, uint256 tokenId) returns()
func (_RegShop *RegShopTransactor) Approve(opts *bind.TransactOpts, to common.Address, tokenId *big.Int) (*types.Transaction, error) {
	return _RegShop.contract.Transact(opts, "approve", to, tokenId)
}

// Approve is a paid mutator transaction binding the contract method 0x095ea7b3.
//
// Solidity: function approve(address to, uint256 tokenId) returns()
func (_RegShop *RegShopSession) Approve(to common.Address, tokenId *big.Int) (*types.Transaction, error) {
	return _RegShop.Contract.Approve(&_RegShop.TransactOpts, to, tokenId)
}

// Approve is a paid mutator transaction binding the contract method 0x095ea7b3.
//
// Solidity: function approve(address to, uint256 tokenId) returns()
func (_RegShop *RegShopTransactorSession) Approve(to common.Address, tokenId *big.Int) (*types.Transaction, error) {
	return _RegShop.Contract.Approve(&_RegShop.TransactOpts, to, tokenId)
}

// Mint is a paid mutator transaction binding the contract method 0x94bf804d.
//
// Solidity: function mint(uint256 shopId, address owner) returns()
func (_RegShop *RegShopTransactor) Mint(opts *bind.TransactOpts, shopId *big.Int, owner common.Address) (*types.Transaction, error) {
	return _RegShop.contract.Transact(opts, "mint", shopId, owner)
}

// Mint is a paid mutator transaction binding the contract method 0x94bf804d.
//
// Solidity: function mint(uint256 shopId, address owner) returns()
func (_RegShop *RegShopSession) Mint(shopId *big.Int, owner common.Address) (*types.Transaction, error) {
	return _RegShop.Contract.Mint(&_RegShop.TransactOpts, shopId, owner)
}

// Mint is a paid mutator transaction binding the contract method 0x94bf804d.
//
// Solidity: function mint(uint256 shopId, address owner) returns()
func (_RegShop *RegShopTransactorSession) Mint(shopId *big.Int, owner common.Address) (*types.Transaction, error) {
	return _RegShop.Contract.Mint(&_RegShop.TransactOpts, shopId, owner)
}

// PublishInviteVerifier is a paid mutator transaction binding the contract method 0xcec47afe.
//
// Solidity: function publishInviteVerifier(uint256 shopId, address verifier) returns()
func (_RegShop *RegShopTransactor) PublishInviteVerifier(opts *bind.TransactOpts, shopId *big.Int, verifier common.Address) (*types.Transaction, error) {
	return _RegShop.contract.Transact(opts, "publishInviteVerifier", shopId, verifier)
}

// PublishInviteVerifier is a paid mutator transaction binding the contract method 0xcec47afe.
//
// Solidity: function publishInviteVerifier(uint256 shopId, address verifier) returns()
func (_RegShop *RegShopSession) PublishInviteVerifier(shopId *big.Int, verifier common.Address) (*types.Transaction, error) {
	return _RegShop.Contract.PublishInviteVerifier(&_RegShop.TransactOpts, shopId, verifier)
}

// PublishInviteVerifier is a paid mutator transaction binding the contract method 0xcec47afe.
//
// Solidity: function publishInviteVerifier(uint256 shopId, address verifier) returns()
func (_RegShop *RegShopTransactorSession) PublishInviteVerifier(shopId *big.Int, verifier common.Address) (*types.Transaction, error) {
	return _RegShop.Contract.PublishInviteVerifier(&_RegShop.TransactOpts, shopId, verifier)
}

// RedeemInvite is a paid mutator transaction binding the contract method 0xba91a89c.
//
// Solidity: function redeemInvite(uint256 shopId, uint8 v, bytes32 r, bytes32 s, address user) returns()
func (_RegShop *RegShopTransactor) RedeemInvite(opts *bind.TransactOpts, shopId *big.Int, v uint8, r [32]byte, s [32]byte, user common.Address) (*types.Transaction, error) {
	return _RegShop.contract.Transact(opts, "redeemInvite", shopId, v, r, s, user)
}

// RedeemInvite is a paid mutator transaction binding the contract method 0xba91a89c.
//
// Solidity: function redeemInvite(uint256 shopId, uint8 v, bytes32 r, bytes32 s, address user) returns()
func (_RegShop *RegShopSession) RedeemInvite(shopId *big.Int, v uint8, r [32]byte, s [32]byte, user common.Address) (*types.Transaction, error) {
	return _RegShop.Contract.RedeemInvite(&_RegShop.TransactOpts, shopId, v, r, s, user)
}

// RedeemInvite is a paid mutator transaction binding the contract method 0xba91a89c.
//
// Solidity: function redeemInvite(uint256 shopId, uint8 v, bytes32 r, bytes32 s, address user) returns()
func (_RegShop *RegShopTransactorSession) RedeemInvite(shopId *big.Int, v uint8, r [32]byte, s [32]byte, user common.Address) (*types.Transaction, error) {
	return _RegShop.Contract.RedeemInvite(&_RegShop.TransactOpts, shopId, v, r, s, user)
}

// RegisterUser is a paid mutator transaction binding the contract method 0x55789e2a.
//
// Solidity: function registerUser(uint256 shopId, address user, uint256 perms) returns()
func (_RegShop *RegShopTransactor) RegisterUser(opts *bind.TransactOpts, shopId *big.Int, user common.Address, perms *big.Int) (*types.Transaction, error) {
	return _RegShop.contract.Transact(opts, "registerUser", shopId, user, perms)
}

// RegisterUser is a paid mutator transaction binding the contract method 0x55789e2a.
//
// Solidity: function registerUser(uint256 shopId, address user, uint256 perms) returns()
func (_RegShop *RegShopSession) RegisterUser(shopId *big.Int, user common.Address, perms *big.Int) (*types.Transaction, error) {
	return _RegShop.Contract.RegisterUser(&_RegShop.TransactOpts, shopId, user, perms)
}

// RegisterUser is a paid mutator transaction binding the contract method 0x55789e2a.
//
// Solidity: function registerUser(uint256 shopId, address user, uint256 perms) returns()
func (_RegShop *RegShopTransactorSession) RegisterUser(shopId *big.Int, user common.Address, perms *big.Int) (*types.Transaction, error) {
	return _RegShop.Contract.RegisterUser(&_RegShop.TransactOpts, shopId, user, perms)
}

// RemovePermission is a paid mutator transaction binding the contract method 0xf721fab8.
//
// Solidity: function removePermission(uint256 shopId, address user, uint8 perm) returns()
func (_RegShop *RegShopTransactor) RemovePermission(opts *bind.TransactOpts, shopId *big.Int, user common.Address, perm uint8) (*types.Transaction, error) {
	return _RegShop.contract.Transact(opts, "removePermission", shopId, user, perm)
}

// RemovePermission is a paid mutator transaction binding the contract method 0xf721fab8.
//
// Solidity: function removePermission(uint256 shopId, address user, uint8 perm) returns()
func (_RegShop *RegShopSession) RemovePermission(shopId *big.Int, user common.Address, perm uint8) (*types.Transaction, error) {
	return _RegShop.Contract.RemovePermission(&_RegShop.TransactOpts, shopId, user, perm)
}

// RemovePermission is a paid mutator transaction binding the contract method 0xf721fab8.
//
// Solidity: function removePermission(uint256 shopId, address user, uint8 perm) returns()
func (_RegShop *RegShopTransactorSession) RemovePermission(shopId *big.Int, user common.Address, perm uint8) (*types.Transaction, error) {
	return _RegShop.Contract.RemovePermission(&_RegShop.TransactOpts, shopId, user, perm)
}

// RemoveRelay is a paid mutator transaction binding the contract method 0xe9d928d5.
//
// Solidity: function removeRelay(uint256 shopId, uint8 idx) returns()
func (_RegShop *RegShopTransactor) RemoveRelay(opts *bind.TransactOpts, shopId *big.Int, idx uint8) (*types.Transaction, error) {
	return _RegShop.contract.Transact(opts, "removeRelay", shopId, idx)
}

// RemoveRelay is a paid mutator transaction binding the contract method 0xe9d928d5.
//
// Solidity: function removeRelay(uint256 shopId, uint8 idx) returns()
func (_RegShop *RegShopSession) RemoveRelay(shopId *big.Int, idx uint8) (*types.Transaction, error) {
	return _RegShop.Contract.RemoveRelay(&_RegShop.TransactOpts, shopId, idx)
}

// RemoveRelay is a paid mutator transaction binding the contract method 0xe9d928d5.
//
// Solidity: function removeRelay(uint256 shopId, uint8 idx) returns()
func (_RegShop *RegShopTransactorSession) RemoveRelay(shopId *big.Int, idx uint8) (*types.Transaction, error) {
	return _RegShop.Contract.RemoveRelay(&_RegShop.TransactOpts, shopId, idx)
}

// RemoveUser is a paid mutator transaction binding the contract method 0x0c8f91a9.
//
// Solidity: function removeUser(uint256 shopId, address user) returns()
func (_RegShop *RegShopTransactor) RemoveUser(opts *bind.TransactOpts, shopId *big.Int, user common.Address) (*types.Transaction, error) {
	return _RegShop.contract.Transact(opts, "removeUser", shopId, user)
}

// RemoveUser is a paid mutator transaction binding the contract method 0x0c8f91a9.
//
// Solidity: function removeUser(uint256 shopId, address user) returns()
func (_RegShop *RegShopSession) RemoveUser(shopId *big.Int, user common.Address) (*types.Transaction, error) {
	return _RegShop.Contract.RemoveUser(&_RegShop.TransactOpts, shopId, user)
}

// RemoveUser is a paid mutator transaction binding the contract method 0x0c8f91a9.
//
// Solidity: function removeUser(uint256 shopId, address user) returns()
func (_RegShop *RegShopTransactorSession) RemoveUser(shopId *big.Int, user common.Address) (*types.Transaction, error) {
	return _RegShop.Contract.RemoveUser(&_RegShop.TransactOpts, shopId, user)
}

// ReplaceRelay is a paid mutator transaction binding the contract method 0x3447af9f.
//
// Solidity: function replaceRelay(uint256 shopId, uint8 idx, uint256 relayId) returns()
func (_RegShop *RegShopTransactor) ReplaceRelay(opts *bind.TransactOpts, shopId *big.Int, idx uint8, relayId *big.Int) (*types.Transaction, error) {
	return _RegShop.contract.Transact(opts, "replaceRelay", shopId, idx, relayId)
}

// ReplaceRelay is a paid mutator transaction binding the contract method 0x3447af9f.
//
// Solidity: function replaceRelay(uint256 shopId, uint8 idx, uint256 relayId) returns()
func (_RegShop *RegShopSession) ReplaceRelay(shopId *big.Int, idx uint8, relayId *big.Int) (*types.Transaction, error) {
	return _RegShop.Contract.ReplaceRelay(&_RegShop.TransactOpts, shopId, idx, relayId)
}

// ReplaceRelay is a paid mutator transaction binding the contract method 0x3447af9f.
//
// Solidity: function replaceRelay(uint256 shopId, uint8 idx, uint256 relayId) returns()
func (_RegShop *RegShopTransactorSession) ReplaceRelay(shopId *big.Int, idx uint8, relayId *big.Int) (*types.Transaction, error) {
	return _RegShop.Contract.ReplaceRelay(&_RegShop.TransactOpts, shopId, idx, relayId)
}

// SafeTransferFrom is a paid mutator transaction binding the contract method 0x42842e0e.
//
// Solidity: function safeTransferFrom(address from, address to, uint256 tokenId) returns()
func (_RegShop *RegShopTransactor) SafeTransferFrom(opts *bind.TransactOpts, from common.Address, to common.Address, tokenId *big.Int) (*types.Transaction, error) {
	return _RegShop.contract.Transact(opts, "safeTransferFrom", from, to, tokenId)
}

// SafeTransferFrom is a paid mutator transaction binding the contract method 0x42842e0e.
//
// Solidity: function safeTransferFrom(address from, address to, uint256 tokenId) returns()
func (_RegShop *RegShopSession) SafeTransferFrom(from common.Address, to common.Address, tokenId *big.Int) (*types.Transaction, error) {
	return _RegShop.Contract.SafeTransferFrom(&_RegShop.TransactOpts, from, to, tokenId)
}

// SafeTransferFrom is a paid mutator transaction binding the contract method 0x42842e0e.
//
// Solidity: function safeTransferFrom(address from, address to, uint256 tokenId) returns()
func (_RegShop *RegShopTransactorSession) SafeTransferFrom(from common.Address, to common.Address, tokenId *big.Int) (*types.Transaction, error) {
	return _RegShop.Contract.SafeTransferFrom(&_RegShop.TransactOpts, from, to, tokenId)
}

// SafeTransferFrom0 is a paid mutator transaction binding the contract method 0xb88d4fde.
//
// Solidity: function safeTransferFrom(address from, address to, uint256 tokenId, bytes data) returns()
func (_RegShop *RegShopTransactor) SafeTransferFrom0(opts *bind.TransactOpts, from common.Address, to common.Address, tokenId *big.Int, data []byte) (*types.Transaction, error) {
	return _RegShop.contract.Transact(opts, "safeTransferFrom0", from, to, tokenId, data)
}

// SafeTransferFrom0 is a paid mutator transaction binding the contract method 0xb88d4fde.
//
// Solidity: function safeTransferFrom(address from, address to, uint256 tokenId, bytes data) returns()
func (_RegShop *RegShopSession) SafeTransferFrom0(from common.Address, to common.Address, tokenId *big.Int, data []byte) (*types.Transaction, error) {
	return _RegShop.Contract.SafeTransferFrom0(&_RegShop.TransactOpts, from, to, tokenId, data)
}

// SafeTransferFrom0 is a paid mutator transaction binding the contract method 0xb88d4fde.
//
// Solidity: function safeTransferFrom(address from, address to, uint256 tokenId, bytes data) returns()
func (_RegShop *RegShopTransactorSession) SafeTransferFrom0(from common.Address, to common.Address, tokenId *big.Int, data []byte) (*types.Transaction, error) {
	return _RegShop.Contract.SafeTransferFrom0(&_RegShop.TransactOpts, from, to, tokenId, data)
}

// SetApprovalForAll is a paid mutator transaction binding the contract method 0xa22cb465.
//
// Solidity: function setApprovalForAll(address operator, bool approved) returns()
func (_RegShop *RegShopTransactor) SetApprovalForAll(opts *bind.TransactOpts, operator common.Address, approved bool) (*types.Transaction, error) {
	return _RegShop.contract.Transact(opts, "setApprovalForAll", operator, approved)
}

// SetApprovalForAll is a paid mutator transaction binding the contract method 0xa22cb465.
//
// Solidity: function setApprovalForAll(address operator, bool approved) returns()
func (_RegShop *RegShopSession) SetApprovalForAll(operator common.Address, approved bool) (*types.Transaction, error) {
	return _RegShop.Contract.SetApprovalForAll(&_RegShop.TransactOpts, operator, approved)
}

// SetApprovalForAll is a paid mutator transaction binding the contract method 0xa22cb465.
//
// Solidity: function setApprovalForAll(address operator, bool approved) returns()
func (_RegShop *RegShopTransactorSession) SetApprovalForAll(operator common.Address, approved bool) (*types.Transaction, error) {
	return _RegShop.Contract.SetApprovalForAll(&_RegShop.TransactOpts, operator, approved)
}

// SetTokenURI is a paid mutator transaction binding the contract method 0x162094c4.
//
// Solidity: function setTokenURI(uint256 shopId, string newTokenURI) returns()
func (_RegShop *RegShopTransactor) SetTokenURI(opts *bind.TransactOpts, shopId *big.Int, newTokenURI string) (*types.Transaction, error) {
	return _RegShop.contract.Transact(opts, "setTokenURI", shopId, newTokenURI)
}

// SetTokenURI is a paid mutator transaction binding the contract method 0x162094c4.
//
// Solidity: function setTokenURI(uint256 shopId, string newTokenURI) returns()
func (_RegShop *RegShopSession) SetTokenURI(shopId *big.Int, newTokenURI string) (*types.Transaction, error) {
	return _RegShop.Contract.SetTokenURI(&_RegShop.TransactOpts, shopId, newTokenURI)
}

// SetTokenURI is a paid mutator transaction binding the contract method 0x162094c4.
//
// Solidity: function setTokenURI(uint256 shopId, string newTokenURI) returns()
func (_RegShop *RegShopTransactorSession) SetTokenURI(shopId *big.Int, newTokenURI string) (*types.Transaction, error) {
	return _RegShop.Contract.SetTokenURI(&_RegShop.TransactOpts, shopId, newTokenURI)
}

// TransferFrom is a paid mutator transaction binding the contract method 0x23b872dd.
//
// Solidity: function transferFrom(address from, address to, uint256 tokenId) returns()
func (_RegShop *RegShopTransactor) TransferFrom(opts *bind.TransactOpts, from common.Address, to common.Address, tokenId *big.Int) (*types.Transaction, error) {
	return _RegShop.contract.Transact(opts, "transferFrom", from, to, tokenId)
}

// TransferFrom is a paid mutator transaction binding the contract method 0x23b872dd.
//
// Solidity: function transferFrom(address from, address to, uint256 tokenId) returns()
func (_RegShop *RegShopSession) TransferFrom(from common.Address, to common.Address, tokenId *big.Int) (*types.Transaction, error) {
	return _RegShop.Contract.TransferFrom(&_RegShop.TransactOpts, from, to, tokenId)
}

// TransferFrom is a paid mutator transaction binding the contract method 0x23b872dd.
//
// Solidity: function transferFrom(address from, address to, uint256 tokenId) returns()
func (_RegShop *RegShopTransactorSession) TransferFrom(from common.Address, to common.Address, tokenId *big.Int) (*types.Transaction, error) {
	return _RegShop.Contract.TransferFrom(&_RegShop.TransactOpts, from, to, tokenId)
}

// UpdateRootHash is a paid mutator transaction binding the contract method 0x175253f5.
//
// Solidity: function updateRootHash(uint256 shopId, bytes32 hash, uint64 _nonce) returns()
func (_RegShop *RegShopTransactor) UpdateRootHash(opts *bind.TransactOpts, shopId *big.Int, hash [32]byte, _nonce uint64) (*types.Transaction, error) {
	return _RegShop.contract.Transact(opts, "updateRootHash", shopId, hash, _nonce)
}

// UpdateRootHash is a paid mutator transaction binding the contract method 0x175253f5.
//
// Solidity: function updateRootHash(uint256 shopId, bytes32 hash, uint64 _nonce) returns()
func (_RegShop *RegShopSession) UpdateRootHash(shopId *big.Int, hash [32]byte, _nonce uint64) (*types.Transaction, error) {
	return _RegShop.Contract.UpdateRootHash(&_RegShop.TransactOpts, shopId, hash, _nonce)
}

// UpdateRootHash is a paid mutator transaction binding the contract method 0x175253f5.
//
// Solidity: function updateRootHash(uint256 shopId, bytes32 hash, uint64 _nonce) returns()
func (_RegShop *RegShopTransactorSession) UpdateRootHash(shopId *big.Int, hash [32]byte, _nonce uint64) (*types.Transaction, error) {
	return _RegShop.Contract.UpdateRootHash(&_RegShop.TransactOpts, shopId, hash, _nonce)
}

// RegShopApprovalIterator is returned from FilterApproval and is used to iterate over the raw logs and unpacked data for Approval events raised by the RegShop contract.
type RegShopApprovalIterator struct {
	Event *RegShopApproval // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *RegShopApprovalIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(RegShopApproval)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(RegShopApproval)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *RegShopApprovalIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *RegShopApprovalIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// RegShopApproval represents a Approval event raised by the RegShop contract.
type RegShopApproval struct {
	Owner    common.Address
	Approved common.Address
	TokenId  *big.Int
	Raw      types.Log // Blockchain specific contextual infos
}

// FilterApproval is a free log retrieval operation binding the contract event 0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925.
//
// Solidity: event Approval(address indexed owner, address indexed approved, uint256 indexed tokenId)
func (_RegShop *RegShopFilterer) FilterApproval(opts *bind.FilterOpts, owner []common.Address, approved []common.Address, tokenId []*big.Int) (*RegShopApprovalIterator, error) {

	var ownerRule []interface{}
	for _, ownerItem := range owner {
		ownerRule = append(ownerRule, ownerItem)
	}
	var approvedRule []interface{}
	for _, approvedItem := range approved {
		approvedRule = append(approvedRule, approvedItem)
	}
	var tokenIdRule []interface{}
	for _, tokenIdItem := range tokenId {
		tokenIdRule = append(tokenIdRule, tokenIdItem)
	}

	logs, sub, err := _RegShop.contract.FilterLogs(opts, "Approval", ownerRule, approvedRule, tokenIdRule)
	if err != nil {
		return nil, err
	}
	return &RegShopApprovalIterator{contract: _RegShop.contract, event: "Approval", logs: logs, sub: sub}, nil
}

// WatchApproval is a free log subscription operation binding the contract event 0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925.
//
// Solidity: event Approval(address indexed owner, address indexed approved, uint256 indexed tokenId)
func (_RegShop *RegShopFilterer) WatchApproval(opts *bind.WatchOpts, sink chan<- *RegShopApproval, owner []common.Address, approved []common.Address, tokenId []*big.Int) (event.Subscription, error) {

	var ownerRule []interface{}
	for _, ownerItem := range owner {
		ownerRule = append(ownerRule, ownerItem)
	}
	var approvedRule []interface{}
	for _, approvedItem := range approved {
		approvedRule = append(approvedRule, approvedItem)
	}
	var tokenIdRule []interface{}
	for _, tokenIdItem := range tokenId {
		tokenIdRule = append(tokenIdRule, tokenIdItem)
	}

	logs, sub, err := _RegShop.contract.WatchLogs(opts, "Approval", ownerRule, approvedRule, tokenIdRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(RegShopApproval)
				if err := _RegShop.contract.UnpackLog(event, "Approval", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseApproval is a log parse operation binding the contract event 0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925.
//
// Solidity: event Approval(address indexed owner, address indexed approved, uint256 indexed tokenId)
func (_RegShop *RegShopFilterer) ParseApproval(log types.Log) (*RegShopApproval, error) {
	event := new(RegShopApproval)
	if err := _RegShop.contract.UnpackLog(event, "Approval", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// RegShopApprovalForAllIterator is returned from FilterApprovalForAll and is used to iterate over the raw logs and unpacked data for ApprovalForAll events raised by the RegShop contract.
type RegShopApprovalForAllIterator struct {
	Event *RegShopApprovalForAll // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *RegShopApprovalForAllIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(RegShopApprovalForAll)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(RegShopApprovalForAll)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *RegShopApprovalForAllIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *RegShopApprovalForAllIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// RegShopApprovalForAll represents a ApprovalForAll event raised by the RegShop contract.
type RegShopApprovalForAll struct {
	Owner    common.Address
	Operator common.Address
	Approved bool
	Raw      types.Log // Blockchain specific contextual infos
}

// FilterApprovalForAll is a free log retrieval operation binding the contract event 0x17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31.
//
// Solidity: event ApprovalForAll(address indexed owner, address indexed operator, bool approved)
func (_RegShop *RegShopFilterer) FilterApprovalForAll(opts *bind.FilterOpts, owner []common.Address, operator []common.Address) (*RegShopApprovalForAllIterator, error) {

	var ownerRule []interface{}
	for _, ownerItem := range owner {
		ownerRule = append(ownerRule, ownerItem)
	}
	var operatorRule []interface{}
	for _, operatorItem := range operator {
		operatorRule = append(operatorRule, operatorItem)
	}

	logs, sub, err := _RegShop.contract.FilterLogs(opts, "ApprovalForAll", ownerRule, operatorRule)
	if err != nil {
		return nil, err
	}
	return &RegShopApprovalForAllIterator{contract: _RegShop.contract, event: "ApprovalForAll", logs: logs, sub: sub}, nil
}

// WatchApprovalForAll is a free log subscription operation binding the contract event 0x17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31.
//
// Solidity: event ApprovalForAll(address indexed owner, address indexed operator, bool approved)
func (_RegShop *RegShopFilterer) WatchApprovalForAll(opts *bind.WatchOpts, sink chan<- *RegShopApprovalForAll, owner []common.Address, operator []common.Address) (event.Subscription, error) {

	var ownerRule []interface{}
	for _, ownerItem := range owner {
		ownerRule = append(ownerRule, ownerItem)
	}
	var operatorRule []interface{}
	for _, operatorItem := range operator {
		operatorRule = append(operatorRule, operatorItem)
	}

	logs, sub, err := _RegShop.contract.WatchLogs(opts, "ApprovalForAll", ownerRule, operatorRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(RegShopApprovalForAll)
				if err := _RegShop.contract.UnpackLog(event, "ApprovalForAll", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseApprovalForAll is a log parse operation binding the contract event 0x17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31.
//
// Solidity: event ApprovalForAll(address indexed owner, address indexed operator, bool approved)
func (_RegShop *RegShopFilterer) ParseApprovalForAll(log types.Log) (*RegShopApprovalForAll, error) {
	event := new(RegShopApprovalForAll)
	if err := _RegShop.contract.UnpackLog(event, "ApprovalForAll", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// RegShopBatchMetadataUpdateIterator is returned from FilterBatchMetadataUpdate and is used to iterate over the raw logs and unpacked data for BatchMetadataUpdate events raised by the RegShop contract.
type RegShopBatchMetadataUpdateIterator struct {
	Event *RegShopBatchMetadataUpdate // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *RegShopBatchMetadataUpdateIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(RegShopBatchMetadataUpdate)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(RegShopBatchMetadataUpdate)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *RegShopBatchMetadataUpdateIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *RegShopBatchMetadataUpdateIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// RegShopBatchMetadataUpdate represents a BatchMetadataUpdate event raised by the RegShop contract.
type RegShopBatchMetadataUpdate struct {
	FromTokenId *big.Int
	ToTokenId   *big.Int
	Raw         types.Log // Blockchain specific contextual infos
}

// FilterBatchMetadataUpdate is a free log retrieval operation binding the contract event 0x6bd5c950a8d8df17f772f5af37cb3655737899cbf903264b9795592da439661c.
//
// Solidity: event BatchMetadataUpdate(uint256 _fromTokenId, uint256 _toTokenId)
func (_RegShop *RegShopFilterer) FilterBatchMetadataUpdate(opts *bind.FilterOpts) (*RegShopBatchMetadataUpdateIterator, error) {

	logs, sub, err := _RegShop.contract.FilterLogs(opts, "BatchMetadataUpdate")
	if err != nil {
		return nil, err
	}
	return &RegShopBatchMetadataUpdateIterator{contract: _RegShop.contract, event: "BatchMetadataUpdate", logs: logs, sub: sub}, nil
}

// WatchBatchMetadataUpdate is a free log subscription operation binding the contract event 0x6bd5c950a8d8df17f772f5af37cb3655737899cbf903264b9795592da439661c.
//
// Solidity: event BatchMetadataUpdate(uint256 _fromTokenId, uint256 _toTokenId)
func (_RegShop *RegShopFilterer) WatchBatchMetadataUpdate(opts *bind.WatchOpts, sink chan<- *RegShopBatchMetadataUpdate) (event.Subscription, error) {

	logs, sub, err := _RegShop.contract.WatchLogs(opts, "BatchMetadataUpdate")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(RegShopBatchMetadataUpdate)
				if err := _RegShop.contract.UnpackLog(event, "BatchMetadataUpdate", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseBatchMetadataUpdate is a log parse operation binding the contract event 0x6bd5c950a8d8df17f772f5af37cb3655737899cbf903264b9795592da439661c.
//
// Solidity: event BatchMetadataUpdate(uint256 _fromTokenId, uint256 _toTokenId)
func (_RegShop *RegShopFilterer) ParseBatchMetadataUpdate(log types.Log) (*RegShopBatchMetadataUpdate, error) {
	event := new(RegShopBatchMetadataUpdate)
	if err := _RegShop.contract.UnpackLog(event, "BatchMetadataUpdate", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// RegShopMetadataUpdateIterator is returned from FilterMetadataUpdate and is used to iterate over the raw logs and unpacked data for MetadataUpdate events raised by the RegShop contract.
type RegShopMetadataUpdateIterator struct {
	Event *RegShopMetadataUpdate // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *RegShopMetadataUpdateIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(RegShopMetadataUpdate)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(RegShopMetadataUpdate)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *RegShopMetadataUpdateIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *RegShopMetadataUpdateIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// RegShopMetadataUpdate represents a MetadataUpdate event raised by the RegShop contract.
type RegShopMetadataUpdate struct {
	TokenId *big.Int
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterMetadataUpdate is a free log retrieval operation binding the contract event 0xf8e1a15aba9398e019f0b49df1a4fde98ee17ae345cb5f6b5e2c27f5033e8ce7.
//
// Solidity: event MetadataUpdate(uint256 _tokenId)
func (_RegShop *RegShopFilterer) FilterMetadataUpdate(opts *bind.FilterOpts) (*RegShopMetadataUpdateIterator, error) {

	logs, sub, err := _RegShop.contract.FilterLogs(opts, "MetadataUpdate")
	if err != nil {
		return nil, err
	}
	return &RegShopMetadataUpdateIterator{contract: _RegShop.contract, event: "MetadataUpdate", logs: logs, sub: sub}, nil
}

// WatchMetadataUpdate is a free log subscription operation binding the contract event 0xf8e1a15aba9398e019f0b49df1a4fde98ee17ae345cb5f6b5e2c27f5033e8ce7.
//
// Solidity: event MetadataUpdate(uint256 _tokenId)
func (_RegShop *RegShopFilterer) WatchMetadataUpdate(opts *bind.WatchOpts, sink chan<- *RegShopMetadataUpdate) (event.Subscription, error) {

	logs, sub, err := _RegShop.contract.WatchLogs(opts, "MetadataUpdate")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(RegShopMetadataUpdate)
				if err := _RegShop.contract.UnpackLog(event, "MetadataUpdate", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseMetadataUpdate is a log parse operation binding the contract event 0xf8e1a15aba9398e019f0b49df1a4fde98ee17ae345cb5f6b5e2c27f5033e8ce7.
//
// Solidity: event MetadataUpdate(uint256 _tokenId)
func (_RegShop *RegShopFilterer) ParseMetadataUpdate(log types.Log) (*RegShopMetadataUpdate, error) {
	event := new(RegShopMetadataUpdate)
	if err := _RegShop.contract.UnpackLog(event, "MetadataUpdate", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// RegShopPermissionAddedIterator is returned from FilterPermissionAdded and is used to iterate over the raw logs and unpacked data for PermissionAdded events raised by the RegShop contract.
type RegShopPermissionAddedIterator struct {
	Event *RegShopPermissionAdded // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *RegShopPermissionAddedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(RegShopPermissionAdded)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(RegShopPermissionAdded)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *RegShopPermissionAddedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *RegShopPermissionAddedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// RegShopPermissionAdded represents a PermissionAdded event raised by the RegShop contract.
type RegShopPermissionAdded struct {
	ShopId     *big.Int
	User       common.Address
	Permission uint8
	Raw        types.Log // Blockchain specific contextual infos
}

// FilterPermissionAdded is a free log retrieval operation binding the contract event 0xfe5ce55a0223949361eee308dd59d3ba26f5c9c0485a8bc3acfdef8bff7f1606.
//
// Solidity: event PermissionAdded(uint256 indexed shopId, address user, uint8 permission)
func (_RegShop *RegShopFilterer) FilterPermissionAdded(opts *bind.FilterOpts, shopId []*big.Int) (*RegShopPermissionAddedIterator, error) {

	var shopIdRule []interface{}
	for _, shopIdItem := range shopId {
		shopIdRule = append(shopIdRule, shopIdItem)
	}

	logs, sub, err := _RegShop.contract.FilterLogs(opts, "PermissionAdded", shopIdRule)
	if err != nil {
		return nil, err
	}
	return &RegShopPermissionAddedIterator{contract: _RegShop.contract, event: "PermissionAdded", logs: logs, sub: sub}, nil
}

// WatchPermissionAdded is a free log subscription operation binding the contract event 0xfe5ce55a0223949361eee308dd59d3ba26f5c9c0485a8bc3acfdef8bff7f1606.
//
// Solidity: event PermissionAdded(uint256 indexed shopId, address user, uint8 permission)
func (_RegShop *RegShopFilterer) WatchPermissionAdded(opts *bind.WatchOpts, sink chan<- *RegShopPermissionAdded, shopId []*big.Int) (event.Subscription, error) {

	var shopIdRule []interface{}
	for _, shopIdItem := range shopId {
		shopIdRule = append(shopIdRule, shopIdItem)
	}

	logs, sub, err := _RegShop.contract.WatchLogs(opts, "PermissionAdded", shopIdRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(RegShopPermissionAdded)
				if err := _RegShop.contract.UnpackLog(event, "PermissionAdded", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParsePermissionAdded is a log parse operation binding the contract event 0xfe5ce55a0223949361eee308dd59d3ba26f5c9c0485a8bc3acfdef8bff7f1606.
//
// Solidity: event PermissionAdded(uint256 indexed shopId, address user, uint8 permission)
func (_RegShop *RegShopFilterer) ParsePermissionAdded(log types.Log) (*RegShopPermissionAdded, error) {
	event := new(RegShopPermissionAdded)
	if err := _RegShop.contract.UnpackLog(event, "PermissionAdded", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// RegShopPermissionRemovedIterator is returned from FilterPermissionRemoved and is used to iterate over the raw logs and unpacked data for PermissionRemoved events raised by the RegShop contract.
type RegShopPermissionRemovedIterator struct {
	Event *RegShopPermissionRemoved // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *RegShopPermissionRemovedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(RegShopPermissionRemoved)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(RegShopPermissionRemoved)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *RegShopPermissionRemovedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *RegShopPermissionRemovedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// RegShopPermissionRemoved represents a PermissionRemoved event raised by the RegShop contract.
type RegShopPermissionRemoved struct {
	ShopId     *big.Int
	User       common.Address
	Permission uint8
	Raw        types.Log // Blockchain specific contextual infos
}

// FilterPermissionRemoved is a free log retrieval operation binding the contract event 0x7357f7ed6884dc29891d5b9cf8a0acec4aaeded84da448cd3d3805b123f7bc1e.
//
// Solidity: event PermissionRemoved(uint256 indexed shopId, address user, uint8 permission)
func (_RegShop *RegShopFilterer) FilterPermissionRemoved(opts *bind.FilterOpts, shopId []*big.Int) (*RegShopPermissionRemovedIterator, error) {

	var shopIdRule []interface{}
	for _, shopIdItem := range shopId {
		shopIdRule = append(shopIdRule, shopIdItem)
	}

	logs, sub, err := _RegShop.contract.FilterLogs(opts, "PermissionRemoved", shopIdRule)
	if err != nil {
		return nil, err
	}
	return &RegShopPermissionRemovedIterator{contract: _RegShop.contract, event: "PermissionRemoved", logs: logs, sub: sub}, nil
}

// WatchPermissionRemoved is a free log subscription operation binding the contract event 0x7357f7ed6884dc29891d5b9cf8a0acec4aaeded84da448cd3d3805b123f7bc1e.
//
// Solidity: event PermissionRemoved(uint256 indexed shopId, address user, uint8 permission)
func (_RegShop *RegShopFilterer) WatchPermissionRemoved(opts *bind.WatchOpts, sink chan<- *RegShopPermissionRemoved, shopId []*big.Int) (event.Subscription, error) {

	var shopIdRule []interface{}
	for _, shopIdItem := range shopId {
		shopIdRule = append(shopIdRule, shopIdItem)
	}

	logs, sub, err := _RegShop.contract.WatchLogs(opts, "PermissionRemoved", shopIdRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(RegShopPermissionRemoved)
				if err := _RegShop.contract.UnpackLog(event, "PermissionRemoved", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParsePermissionRemoved is a log parse operation binding the contract event 0x7357f7ed6884dc29891d5b9cf8a0acec4aaeded84da448cd3d3805b123f7bc1e.
//
// Solidity: event PermissionRemoved(uint256 indexed shopId, address user, uint8 permission)
func (_RegShop *RegShopFilterer) ParsePermissionRemoved(log types.Log) (*RegShopPermissionRemoved, error) {
	event := new(RegShopPermissionRemoved)
	if err := _RegShop.contract.UnpackLog(event, "PermissionRemoved", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// RegShopTransferIterator is returned from FilterTransfer and is used to iterate over the raw logs and unpacked data for Transfer events raised by the RegShop contract.
type RegShopTransferIterator struct {
	Event *RegShopTransfer // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *RegShopTransferIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(RegShopTransfer)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(RegShopTransfer)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *RegShopTransferIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *RegShopTransferIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// RegShopTransfer represents a Transfer event raised by the RegShop contract.
type RegShopTransfer struct {
	From    common.Address
	To      common.Address
	TokenId *big.Int
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterTransfer is a free log retrieval operation binding the contract event 0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef.
//
// Solidity: event Transfer(address indexed from, address indexed to, uint256 indexed tokenId)
func (_RegShop *RegShopFilterer) FilterTransfer(opts *bind.FilterOpts, from []common.Address, to []common.Address, tokenId []*big.Int) (*RegShopTransferIterator, error) {

	var fromRule []interface{}
	for _, fromItem := range from {
		fromRule = append(fromRule, fromItem)
	}
	var toRule []interface{}
	for _, toItem := range to {
		toRule = append(toRule, toItem)
	}
	var tokenIdRule []interface{}
	for _, tokenIdItem := range tokenId {
		tokenIdRule = append(tokenIdRule, tokenIdItem)
	}

	logs, sub, err := _RegShop.contract.FilterLogs(opts, "Transfer", fromRule, toRule, tokenIdRule)
	if err != nil {
		return nil, err
	}
	return &RegShopTransferIterator{contract: _RegShop.contract, event: "Transfer", logs: logs, sub: sub}, nil
}

// WatchTransfer is a free log subscription operation binding the contract event 0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef.
//
// Solidity: event Transfer(address indexed from, address indexed to, uint256 indexed tokenId)
func (_RegShop *RegShopFilterer) WatchTransfer(opts *bind.WatchOpts, sink chan<- *RegShopTransfer, from []common.Address, to []common.Address, tokenId []*big.Int) (event.Subscription, error) {

	var fromRule []interface{}
	for _, fromItem := range from {
		fromRule = append(fromRule, fromItem)
	}
	var toRule []interface{}
	for _, toItem := range to {
		toRule = append(toRule, toItem)
	}
	var tokenIdRule []interface{}
	for _, tokenIdItem := range tokenId {
		tokenIdRule = append(tokenIdRule, tokenIdItem)
	}

	logs, sub, err := _RegShop.contract.WatchLogs(opts, "Transfer", fromRule, toRule, tokenIdRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(RegShopTransfer)
				if err := _RegShop.contract.UnpackLog(event, "Transfer", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseTransfer is a log parse operation binding the contract event 0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef.
//
// Solidity: event Transfer(address indexed from, address indexed to, uint256 indexed tokenId)
func (_RegShop *RegShopFilterer) ParseTransfer(log types.Log) (*RegShopTransfer, error) {
	event := new(RegShopTransfer)
	if err := _RegShop.contract.UnpackLog(event, "Transfer", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// RegShopUserAddedIterator is returned from FilterUserAdded and is used to iterate over the raw logs and unpacked data for UserAdded events raised by the RegShop contract.
type RegShopUserAddedIterator struct {
	Event *RegShopUserAdded // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *RegShopUserAddedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(RegShopUserAdded)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(RegShopUserAdded)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *RegShopUserAddedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *RegShopUserAddedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// RegShopUserAdded represents a UserAdded event raised by the RegShop contract.
type RegShopUserAdded struct {
	ShopId      *big.Int
	User        common.Address
	Permissions *big.Int
	Raw         types.Log // Blockchain specific contextual infos
}

// FilterUserAdded is a free log retrieval operation binding the contract event 0x865275e7fa20bfbd4ba610b45893bd10c6b08b8aeb9964b72ad321d370726e5f.
//
// Solidity: event UserAdded(uint256 indexed shopId, address user, uint256 permissions)
func (_RegShop *RegShopFilterer) FilterUserAdded(opts *bind.FilterOpts, shopId []*big.Int) (*RegShopUserAddedIterator, error) {

	var shopIdRule []interface{}
	for _, shopIdItem := range shopId {
		shopIdRule = append(shopIdRule, shopIdItem)
	}

	logs, sub, err := _RegShop.contract.FilterLogs(opts, "UserAdded", shopIdRule)
	if err != nil {
		return nil, err
	}
	return &RegShopUserAddedIterator{contract: _RegShop.contract, event: "UserAdded", logs: logs, sub: sub}, nil
}

// WatchUserAdded is a free log subscription operation binding the contract event 0x865275e7fa20bfbd4ba610b45893bd10c6b08b8aeb9964b72ad321d370726e5f.
//
// Solidity: event UserAdded(uint256 indexed shopId, address user, uint256 permissions)
func (_RegShop *RegShopFilterer) WatchUserAdded(opts *bind.WatchOpts, sink chan<- *RegShopUserAdded, shopId []*big.Int) (event.Subscription, error) {

	var shopIdRule []interface{}
	for _, shopIdItem := range shopId {
		shopIdRule = append(shopIdRule, shopIdItem)
	}

	logs, sub, err := _RegShop.contract.WatchLogs(opts, "UserAdded", shopIdRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(RegShopUserAdded)
				if err := _RegShop.contract.UnpackLog(event, "UserAdded", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseUserAdded is a log parse operation binding the contract event 0x865275e7fa20bfbd4ba610b45893bd10c6b08b8aeb9964b72ad321d370726e5f.
//
// Solidity: event UserAdded(uint256 indexed shopId, address user, uint256 permissions)
func (_RegShop *RegShopFilterer) ParseUserAdded(log types.Log) (*RegShopUserAdded, error) {
	event := new(RegShopUserAdded)
	if err := _RegShop.contract.UnpackLog(event, "UserAdded", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// RegShopUserRemovedIterator is returned from FilterUserRemoved and is used to iterate over the raw logs and unpacked data for UserRemoved events raised by the RegShop contract.
type RegShopUserRemovedIterator struct {
	Event *RegShopUserRemoved // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *RegShopUserRemovedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(RegShopUserRemoved)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(RegShopUserRemoved)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *RegShopUserRemovedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *RegShopUserRemovedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// RegShopUserRemoved represents a UserRemoved event raised by the RegShop contract.
type RegShopUserRemoved struct {
	ShopId *big.Int
	Users  common.Address
	Raw    types.Log // Blockchain specific contextual infos
}

// FilterUserRemoved is a free log retrieval operation binding the contract event 0x89703ec90073f7f060a05db721bf6e6bfea7a783e08a7d7e3c50667da7a491f5.
//
// Solidity: event UserRemoved(uint256 indexed shopId, address users)
func (_RegShop *RegShopFilterer) FilterUserRemoved(opts *bind.FilterOpts, shopId []*big.Int) (*RegShopUserRemovedIterator, error) {

	var shopIdRule []interface{}
	for _, shopIdItem := range shopId {
		shopIdRule = append(shopIdRule, shopIdItem)
	}

	logs, sub, err := _RegShop.contract.FilterLogs(opts, "UserRemoved", shopIdRule)
	if err != nil {
		return nil, err
	}
	return &RegShopUserRemovedIterator{contract: _RegShop.contract, event: "UserRemoved", logs: logs, sub: sub}, nil
}

// WatchUserRemoved is a free log subscription operation binding the contract event 0x89703ec90073f7f060a05db721bf6e6bfea7a783e08a7d7e3c50667da7a491f5.
//
// Solidity: event UserRemoved(uint256 indexed shopId, address users)
func (_RegShop *RegShopFilterer) WatchUserRemoved(opts *bind.WatchOpts, sink chan<- *RegShopUserRemoved, shopId []*big.Int) (event.Subscription, error) {

	var shopIdRule []interface{}
	for _, shopIdItem := range shopId {
		shopIdRule = append(shopIdRule, shopIdItem)
	}

	logs, sub, err := _RegShop.contract.WatchLogs(opts, "UserRemoved", shopIdRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(RegShopUserRemoved)
				if err := _RegShop.contract.UnpackLog(event, "UserRemoved", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseUserRemoved is a log parse operation binding the contract event 0x89703ec90073f7f060a05db721bf6e6bfea7a783e08a7d7e3c50667da7a491f5.
//
// Solidity: event UserRemoved(uint256 indexed shopId, address users)
func (_RegShop *RegShopFilterer) ParseUserRemoved(log types.Log) (*RegShopUserRemoved, error) {
	event := new(RegShopUserRemoved)
	if err := _RegShop.contract.UnpackLog(event, "UserRemoved", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}
