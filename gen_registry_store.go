// SPDX-FileCopyrightText: 2024 Mass Labs
//
// SPDX-License-Identifier: GPL-3.0-or-later

// Generated from abi/StoreReg.json - git at dfca5599fdf0e533fb6aebeceb379122332fe8a3

// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package main

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

// RegStoreMetaData contains all meta data concerning the RegStore contract.
var RegStoreMetaData = &bind.MetaData{
	ABI: "[{\"type\":\"constructor\",\"inputs\":[{\"name\":\"r\",\"type\":\"address\",\"internalType\":\"contractRelayReg\"}],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"_getTokenMessageHash\",\"inputs\":[{\"name\":\"user\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"addRelay\",\"inputs\":[{\"name\":\"storeId\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"relayId\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"approve\",\"inputs\":[{\"name\":\"account\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"id\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[],\"stateMutability\":\"payable\"},{\"type\":\"function\",\"name\":\"balanceOf\",\"inputs\":[{\"name\":\"owner\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[{\"name\":\"result\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"getAllRelays\",\"inputs\":[{\"name\":\"storeId\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[{\"name\":\"\",\"type\":\"uint256[]\",\"internalType\":\"uint256[]\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"getApproved\",\"inputs\":[{\"name\":\"id\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[{\"name\":\"result\",\"type\":\"address\",\"internalType\":\"address\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"getRelayCount\",\"inputs\":[{\"name\":\"storeId\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"hasAtLeastAccess\",\"inputs\":[{\"name\":\"storeId\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"addr\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"want\",\"type\":\"uint8\",\"internalType\":\"enumAccessLevel\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"isApprovedForAll\",\"inputs\":[{\"name\":\"owner\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"operator\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[{\"name\":\"result\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"mint\",\"inputs\":[{\"name\":\"storeId\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"owner\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"name\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"string\",\"internalType\":\"string\"}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"ownerOf\",\"inputs\":[{\"name\":\"id\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[{\"name\":\"result\",\"type\":\"address\",\"internalType\":\"address\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"publishInviteVerifier\",\"inputs\":[{\"name\":\"storeId\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"verifier\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"redeemInvite\",\"inputs\":[{\"name\":\"storeId\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"v\",\"type\":\"uint8\",\"internalType\":\"uint8\"},{\"name\":\"r\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"s\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"user\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"registerUser\",\"inputs\":[{\"name\":\"storeId\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"addr\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"acl\",\"type\":\"uint8\",\"internalType\":\"enumAccessLevel\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"relayReg\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"contractRelayReg\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"relays\",\"inputs\":[{\"name\":\"storeid\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"removeRelay\",\"inputs\":[{\"name\":\"storeId\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"idx\",\"type\":\"uint8\",\"internalType\":\"uint8\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"removeUser\",\"inputs\":[{\"name\":\"storeId\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"who\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"replaceRelay\",\"inputs\":[{\"name\":\"storeId\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"idx\",\"type\":\"uint8\",\"internalType\":\"uint8\"},{\"name\":\"relayId\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"requireOnlyAdminOrHigher\",\"inputs\":[{\"name\":\"storeId\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"who\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"rootHashes\",\"inputs\":[{\"name\":\"storeid\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"safeTransferFrom\",\"inputs\":[{\"name\":\"from\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"to\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"id\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[],\"stateMutability\":\"payable\"},{\"type\":\"function\",\"name\":\"safeTransferFrom\",\"inputs\":[{\"name\":\"from\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"to\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"id\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"data\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"outputs\":[],\"stateMutability\":\"payable\"},{\"type\":\"function\",\"name\":\"setApprovalForAll\",\"inputs\":[{\"name\":\"operator\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"isApproved\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"storesToUsers\",\"inputs\":[{\"name\":\"storeid\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"storeuser\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[{\"name\":\"\",\"type\":\"uint8\",\"internalType\":\"enumAccessLevel\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"supportsInterface\",\"inputs\":[{\"name\":\"interfaceId\",\"type\":\"bytes4\",\"internalType\":\"bytes4\"}],\"outputs\":[{\"name\":\"result\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"symbol\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"string\",\"internalType\":\"string\"}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"tokenURI\",\"inputs\":[{\"name\":\"id\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[{\"name\":\"\",\"type\":\"string\",\"internalType\":\"string\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"transferFrom\",\"inputs\":[{\"name\":\"from\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"to\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"id\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[],\"stateMutability\":\"payable\"},{\"type\":\"function\",\"name\":\"updateRootHash\",\"inputs\":[{\"name\":\"storeId\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"hash\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"event\",\"name\":\"Approval\",\"inputs\":[{\"name\":\"owner\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"account\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"id\",\"type\":\"uint256\",\"indexed\":true,\"internalType\":\"uint256\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"ApprovalForAll\",\"inputs\":[{\"name\":\"owner\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"operator\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"isApproved\",\"type\":\"bool\",\"indexed\":false,\"internalType\":\"bool\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"Transfer\",\"inputs\":[{\"name\":\"from\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"to\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"id\",\"type\":\"uint256\",\"indexed\":true,\"internalType\":\"uint256\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"UserAdded\",\"inputs\":[{\"name\":\"storeId\",\"type\":\"uint256\",\"indexed\":true,\"internalType\":\"uint256\"},{\"name\":\"user\",\"type\":\"address\",\"indexed\":false,\"internalType\":\"address\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"UserRemoved\",\"inputs\":[{\"name\":\"storeId\",\"type\":\"uint256\",\"indexed\":true,\"internalType\":\"uint256\"},{\"name\":\"users\",\"type\":\"address\",\"indexed\":false,\"internalType\":\"address\"}],\"anonymous\":false},{\"type\":\"error\",\"name\":\"AccountBalanceOverflow\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"BalanceQueryForZeroAddress\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"InvalidAccessLevel\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"NoVerifier\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"NotAuthorized\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"NotOwnerNorApproved\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"TokenAlreadyExists\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"TokenDoesNotExist\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"TransferFromIncorrectOwner\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"TransferToNonERC721ReceiverImplementer\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"TransferToZeroAddress\",\"inputs\":[]}]",
}

// RegStoreABI is the input ABI used to generate the binding from.
// Deprecated: Use RegStoreMetaData.ABI instead.
var RegStoreABI = RegStoreMetaData.ABI

// RegStore is an auto generated Go binding around an Ethereum contract.
type RegStore struct {
	RegStoreCaller     // Read-only binding to the contract
	RegStoreTransactor // Write-only binding to the contract
	RegStoreFilterer   // Log filterer for contract events
}

// RegStoreCaller is an auto generated read-only Go binding around an Ethereum contract.
type RegStoreCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// RegStoreTransactor is an auto generated write-only Go binding around an Ethereum contract.
type RegStoreTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// RegStoreFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type RegStoreFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// RegStoreSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type RegStoreSession struct {
	Contract     *RegStore         // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// RegStoreCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type RegStoreCallerSession struct {
	Contract *RegStoreCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts   // Call options to use throughout this session
}

// RegStoreTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type RegStoreTransactorSession struct {
	Contract     *RegStoreTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts   // Transaction auth options to use throughout this session
}

// RegStoreRaw is an auto generated low-level Go binding around an Ethereum contract.
type RegStoreRaw struct {
	Contract *RegStore // Generic contract binding to access the raw methods on
}

// RegStoreCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type RegStoreCallerRaw struct {
	Contract *RegStoreCaller // Generic read-only contract binding to access the raw methods on
}

// RegStoreTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type RegStoreTransactorRaw struct {
	Contract *RegStoreTransactor // Generic write-only contract binding to access the raw methods on
}

// NewRegStore creates a new instance of RegStore, bound to a specific deployed contract.
func NewRegStore(address common.Address, backend bind.ContractBackend) (*RegStore, error) {
	contract, err := bindRegStore(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &RegStore{RegStoreCaller: RegStoreCaller{contract: contract}, RegStoreTransactor: RegStoreTransactor{contract: contract}, RegStoreFilterer: RegStoreFilterer{contract: contract}}, nil
}

// NewRegStoreCaller creates a new read-only instance of RegStore, bound to a specific deployed contract.
func NewRegStoreCaller(address common.Address, caller bind.ContractCaller) (*RegStoreCaller, error) {
	contract, err := bindRegStore(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &RegStoreCaller{contract: contract}, nil
}

// NewRegStoreTransactor creates a new write-only instance of RegStore, bound to a specific deployed contract.
func NewRegStoreTransactor(address common.Address, transactor bind.ContractTransactor) (*RegStoreTransactor, error) {
	contract, err := bindRegStore(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &RegStoreTransactor{contract: contract}, nil
}

// NewRegStoreFilterer creates a new log filterer instance of RegStore, bound to a specific deployed contract.
func NewRegStoreFilterer(address common.Address, filterer bind.ContractFilterer) (*RegStoreFilterer, error) {
	contract, err := bindRegStore(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &RegStoreFilterer{contract: contract}, nil
}

// bindRegStore binds a generic wrapper to an already deployed contract.
func bindRegStore(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := RegStoreMetaData.GetAbi()
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, *parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_RegStore *RegStoreRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _RegStore.Contract.RegStoreCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_RegStore *RegStoreRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _RegStore.Contract.RegStoreTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_RegStore *RegStoreRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _RegStore.Contract.RegStoreTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_RegStore *RegStoreCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _RegStore.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_RegStore *RegStoreTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _RegStore.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_RegStore *RegStoreTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _RegStore.Contract.contract.Transact(opts, method, params...)
}

// GetTokenMessageHash is a free data retrieval call binding the contract method 0x46e4a913.
//
// Solidity: function _getTokenMessageHash(address user) pure returns(bytes32)
func (_RegStore *RegStoreCaller) GetTokenMessageHash(opts *bind.CallOpts, user common.Address) ([32]byte, error) {
	var out []interface{}
	err := _RegStore.contract.Call(opts, &out, "_getTokenMessageHash", user)

	if err != nil {
		return *new([32]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([32]byte)).(*[32]byte)

	return out0, err

}

// GetTokenMessageHash is a free data retrieval call binding the contract method 0x46e4a913.
//
// Solidity: function _getTokenMessageHash(address user) pure returns(bytes32)
func (_RegStore *RegStoreSession) GetTokenMessageHash(user common.Address) ([32]byte, error) {
	return _RegStore.Contract.GetTokenMessageHash(&_RegStore.CallOpts, user)
}

// GetTokenMessageHash is a free data retrieval call binding the contract method 0x46e4a913.
//
// Solidity: function _getTokenMessageHash(address user) pure returns(bytes32)
func (_RegStore *RegStoreCallerSession) GetTokenMessageHash(user common.Address) ([32]byte, error) {
	return _RegStore.Contract.GetTokenMessageHash(&_RegStore.CallOpts, user)
}

// BalanceOf is a free data retrieval call binding the contract method 0x70a08231.
//
// Solidity: function balanceOf(address owner) view returns(uint256 result)
func (_RegStore *RegStoreCaller) BalanceOf(opts *bind.CallOpts, owner common.Address) (*big.Int, error) {
	var out []interface{}
	err := _RegStore.contract.Call(opts, &out, "balanceOf", owner)

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// BalanceOf is a free data retrieval call binding the contract method 0x70a08231.
//
// Solidity: function balanceOf(address owner) view returns(uint256 result)
func (_RegStore *RegStoreSession) BalanceOf(owner common.Address) (*big.Int, error) {
	return _RegStore.Contract.BalanceOf(&_RegStore.CallOpts, owner)
}

// BalanceOf is a free data retrieval call binding the contract method 0x70a08231.
//
// Solidity: function balanceOf(address owner) view returns(uint256 result)
func (_RegStore *RegStoreCallerSession) BalanceOf(owner common.Address) (*big.Int, error) {
	return _RegStore.Contract.BalanceOf(&_RegStore.CallOpts, owner)
}

// GetAllRelays is a free data retrieval call binding the contract method 0xce667ce7.
//
// Solidity: function getAllRelays(uint256 storeId) view returns(uint256[])
func (_RegStore *RegStoreCaller) GetAllRelays(opts *bind.CallOpts, storeId *big.Int) ([]*big.Int, error) {
	var out []interface{}
	err := _RegStore.contract.Call(opts, &out, "getAllRelays", storeId)

	if err != nil {
		return *new([]*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new([]*big.Int)).(*[]*big.Int)

	return out0, err

}

// GetAllRelays is a free data retrieval call binding the contract method 0xce667ce7.
//
// Solidity: function getAllRelays(uint256 storeId) view returns(uint256[])
func (_RegStore *RegStoreSession) GetAllRelays(storeId *big.Int) ([]*big.Int, error) {
	return _RegStore.Contract.GetAllRelays(&_RegStore.CallOpts, storeId)
}

// GetAllRelays is a free data retrieval call binding the contract method 0xce667ce7.
//
// Solidity: function getAllRelays(uint256 storeId) view returns(uint256[])
func (_RegStore *RegStoreCallerSession) GetAllRelays(storeId *big.Int) ([]*big.Int, error) {
	return _RegStore.Contract.GetAllRelays(&_RegStore.CallOpts, storeId)
}

// GetApproved is a free data retrieval call binding the contract method 0x081812fc.
//
// Solidity: function getApproved(uint256 id) view returns(address result)
func (_RegStore *RegStoreCaller) GetApproved(opts *bind.CallOpts, id *big.Int) (common.Address, error) {
	var out []interface{}
	err := _RegStore.contract.Call(opts, &out, "getApproved", id)

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// GetApproved is a free data retrieval call binding the contract method 0x081812fc.
//
// Solidity: function getApproved(uint256 id) view returns(address result)
func (_RegStore *RegStoreSession) GetApproved(id *big.Int) (common.Address, error) {
	return _RegStore.Contract.GetApproved(&_RegStore.CallOpts, id)
}

// GetApproved is a free data retrieval call binding the contract method 0x081812fc.
//
// Solidity: function getApproved(uint256 id) view returns(address result)
func (_RegStore *RegStoreCallerSession) GetApproved(id *big.Int) (common.Address, error) {
	return _RegStore.Contract.GetApproved(&_RegStore.CallOpts, id)
}

// GetRelayCount is a free data retrieval call binding the contract method 0x61e11a5f.
//
// Solidity: function getRelayCount(uint256 storeId) view returns(uint256)
func (_RegStore *RegStoreCaller) GetRelayCount(opts *bind.CallOpts, storeId *big.Int) (*big.Int, error) {
	var out []interface{}
	err := _RegStore.contract.Call(opts, &out, "getRelayCount", storeId)

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// GetRelayCount is a free data retrieval call binding the contract method 0x61e11a5f.
//
// Solidity: function getRelayCount(uint256 storeId) view returns(uint256)
func (_RegStore *RegStoreSession) GetRelayCount(storeId *big.Int) (*big.Int, error) {
	return _RegStore.Contract.GetRelayCount(&_RegStore.CallOpts, storeId)
}

// GetRelayCount is a free data retrieval call binding the contract method 0x61e11a5f.
//
// Solidity: function getRelayCount(uint256 storeId) view returns(uint256)
func (_RegStore *RegStoreCallerSession) GetRelayCount(storeId *big.Int) (*big.Int, error) {
	return _RegStore.Contract.GetRelayCount(&_RegStore.CallOpts, storeId)
}

// HasAtLeastAccess is a free data retrieval call binding the contract method 0x45174ff3.
//
// Solidity: function hasAtLeastAccess(uint256 storeId, address addr, uint8 want) view returns(bool)
func (_RegStore *RegStoreCaller) HasAtLeastAccess(opts *bind.CallOpts, storeId *big.Int, addr common.Address, want uint8) (bool, error) {
	var out []interface{}
	err := _RegStore.contract.Call(opts, &out, "hasAtLeastAccess", storeId, addr, want)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// HasAtLeastAccess is a free data retrieval call binding the contract method 0x45174ff3.
//
// Solidity: function hasAtLeastAccess(uint256 storeId, address addr, uint8 want) view returns(bool)
func (_RegStore *RegStoreSession) HasAtLeastAccess(storeId *big.Int, addr common.Address, want uint8) (bool, error) {
	return _RegStore.Contract.HasAtLeastAccess(&_RegStore.CallOpts, storeId, addr, want)
}

// HasAtLeastAccess is a free data retrieval call binding the contract method 0x45174ff3.
//
// Solidity: function hasAtLeastAccess(uint256 storeId, address addr, uint8 want) view returns(bool)
func (_RegStore *RegStoreCallerSession) HasAtLeastAccess(storeId *big.Int, addr common.Address, want uint8) (bool, error) {
	return _RegStore.Contract.HasAtLeastAccess(&_RegStore.CallOpts, storeId, addr, want)
}

// IsApprovedForAll is a free data retrieval call binding the contract method 0xe985e9c5.
//
// Solidity: function isApprovedForAll(address owner, address operator) view returns(bool result)
func (_RegStore *RegStoreCaller) IsApprovedForAll(opts *bind.CallOpts, owner common.Address, operator common.Address) (bool, error) {
	var out []interface{}
	err := _RegStore.contract.Call(opts, &out, "isApprovedForAll", owner, operator)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// IsApprovedForAll is a free data retrieval call binding the contract method 0xe985e9c5.
//
// Solidity: function isApprovedForAll(address owner, address operator) view returns(bool result)
func (_RegStore *RegStoreSession) IsApprovedForAll(owner common.Address, operator common.Address) (bool, error) {
	return _RegStore.Contract.IsApprovedForAll(&_RegStore.CallOpts, owner, operator)
}

// IsApprovedForAll is a free data retrieval call binding the contract method 0xe985e9c5.
//
// Solidity: function isApprovedForAll(address owner, address operator) view returns(bool result)
func (_RegStore *RegStoreCallerSession) IsApprovedForAll(owner common.Address, operator common.Address) (bool, error) {
	return _RegStore.Contract.IsApprovedForAll(&_RegStore.CallOpts, owner, operator)
}

// Name is a free data retrieval call binding the contract method 0x06fdde03.
//
// Solidity: function name() pure returns(string)
func (_RegStore *RegStoreCaller) Name(opts *bind.CallOpts) (string, error) {
	var out []interface{}
	err := _RegStore.contract.Call(opts, &out, "name")

	if err != nil {
		return *new(string), err
	}

	out0 := *abi.ConvertType(out[0], new(string)).(*string)

	return out0, err

}

// Name is a free data retrieval call binding the contract method 0x06fdde03.
//
// Solidity: function name() pure returns(string)
func (_RegStore *RegStoreSession) Name() (string, error) {
	return _RegStore.Contract.Name(&_RegStore.CallOpts)
}

// Name is a free data retrieval call binding the contract method 0x06fdde03.
//
// Solidity: function name() pure returns(string)
func (_RegStore *RegStoreCallerSession) Name() (string, error) {
	return _RegStore.Contract.Name(&_RegStore.CallOpts)
}

// OwnerOf is a free data retrieval call binding the contract method 0x6352211e.
//
// Solidity: function ownerOf(uint256 id) view returns(address result)
func (_RegStore *RegStoreCaller) OwnerOf(opts *bind.CallOpts, id *big.Int) (common.Address, error) {
	var out []interface{}
	err := _RegStore.contract.Call(opts, &out, "ownerOf", id)

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// OwnerOf is a free data retrieval call binding the contract method 0x6352211e.
//
// Solidity: function ownerOf(uint256 id) view returns(address result)
func (_RegStore *RegStoreSession) OwnerOf(id *big.Int) (common.Address, error) {
	return _RegStore.Contract.OwnerOf(&_RegStore.CallOpts, id)
}

// OwnerOf is a free data retrieval call binding the contract method 0x6352211e.
//
// Solidity: function ownerOf(uint256 id) view returns(address result)
func (_RegStore *RegStoreCallerSession) OwnerOf(id *big.Int) (common.Address, error) {
	return _RegStore.Contract.OwnerOf(&_RegStore.CallOpts, id)
}

// RelayReg is a free data retrieval call binding the contract method 0x38887dde.
//
// Solidity: function relayReg() view returns(address)
func (_RegStore *RegStoreCaller) RelayReg(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _RegStore.contract.Call(opts, &out, "relayReg")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// RelayReg is a free data retrieval call binding the contract method 0x38887dde.
//
// Solidity: function relayReg() view returns(address)
func (_RegStore *RegStoreSession) RelayReg() (common.Address, error) {
	return _RegStore.Contract.RelayReg(&_RegStore.CallOpts)
}

// RelayReg is a free data retrieval call binding the contract method 0x38887dde.
//
// Solidity: function relayReg() view returns(address)
func (_RegStore *RegStoreCallerSession) RelayReg() (common.Address, error) {
	return _RegStore.Contract.RelayReg(&_RegStore.CallOpts)
}

// Relays is a free data retrieval call binding the contract method 0xb08cfd15.
//
// Solidity: function relays(uint256 storeid, uint256 ) view returns(uint256)
func (_RegStore *RegStoreCaller) Relays(opts *bind.CallOpts, storeid *big.Int, arg1 *big.Int) (*big.Int, error) {
	var out []interface{}
	err := _RegStore.contract.Call(opts, &out, "relays", storeid, arg1)

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// Relays is a free data retrieval call binding the contract method 0xb08cfd15.
//
// Solidity: function relays(uint256 storeid, uint256 ) view returns(uint256)
func (_RegStore *RegStoreSession) Relays(storeid *big.Int, arg1 *big.Int) (*big.Int, error) {
	return _RegStore.Contract.Relays(&_RegStore.CallOpts, storeid, arg1)
}

// Relays is a free data retrieval call binding the contract method 0xb08cfd15.
//
// Solidity: function relays(uint256 storeid, uint256 ) view returns(uint256)
func (_RegStore *RegStoreCallerSession) Relays(storeid *big.Int, arg1 *big.Int) (*big.Int, error) {
	return _RegStore.Contract.Relays(&_RegStore.CallOpts, storeid, arg1)
}

// RequireOnlyAdminOrHigher is a free data retrieval call binding the contract method 0x385b38bb.
//
// Solidity: function requireOnlyAdminOrHigher(uint256 storeId, address who) view returns()
func (_RegStore *RegStoreCaller) RequireOnlyAdminOrHigher(opts *bind.CallOpts, storeId *big.Int, who common.Address) error {
	var out []interface{}
	err := _RegStore.contract.Call(opts, &out, "requireOnlyAdminOrHigher", storeId, who)

	if err != nil {
		return err
	}

	return err

}

// RequireOnlyAdminOrHigher is a free data retrieval call binding the contract method 0x385b38bb.
//
// Solidity: function requireOnlyAdminOrHigher(uint256 storeId, address who) view returns()
func (_RegStore *RegStoreSession) RequireOnlyAdminOrHigher(storeId *big.Int, who common.Address) error {
	return _RegStore.Contract.RequireOnlyAdminOrHigher(&_RegStore.CallOpts, storeId, who)
}

// RequireOnlyAdminOrHigher is a free data retrieval call binding the contract method 0x385b38bb.
//
// Solidity: function requireOnlyAdminOrHigher(uint256 storeId, address who) view returns()
func (_RegStore *RegStoreCallerSession) RequireOnlyAdminOrHigher(storeId *big.Int, who common.Address) error {
	return _RegStore.Contract.RequireOnlyAdminOrHigher(&_RegStore.CallOpts, storeId, who)
}

// RootHashes is a free data retrieval call binding the contract method 0x53b93557.
//
// Solidity: function rootHashes(uint256 storeid) view returns(bytes32)
func (_RegStore *RegStoreCaller) RootHashes(opts *bind.CallOpts, storeid *big.Int) ([32]byte, error) {
	var out []interface{}
	err := _RegStore.contract.Call(opts, &out, "rootHashes", storeid)

	if err != nil {
		return *new([32]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([32]byte)).(*[32]byte)

	return out0, err

}

// RootHashes is a free data retrieval call binding the contract method 0x53b93557.
//
// Solidity: function rootHashes(uint256 storeid) view returns(bytes32)
func (_RegStore *RegStoreSession) RootHashes(storeid *big.Int) ([32]byte, error) {
	return _RegStore.Contract.RootHashes(&_RegStore.CallOpts, storeid)
}

// RootHashes is a free data retrieval call binding the contract method 0x53b93557.
//
// Solidity: function rootHashes(uint256 storeid) view returns(bytes32)
func (_RegStore *RegStoreCallerSession) RootHashes(storeid *big.Int) ([32]byte, error) {
	return _RegStore.Contract.RootHashes(&_RegStore.CallOpts, storeid)
}

// StoresToUsers is a free data retrieval call binding the contract method 0xb253af66.
//
// Solidity: function storesToUsers(uint256 storeid, address storeuser) view returns(uint8)
func (_RegStore *RegStoreCaller) StoresToUsers(opts *bind.CallOpts, storeid *big.Int, storeuser common.Address) (uint8, error) {
	var out []interface{}
	err := _RegStore.contract.Call(opts, &out, "storesToUsers", storeid, storeuser)

	if err != nil {
		return *new(uint8), err
	}

	out0 := *abi.ConvertType(out[0], new(uint8)).(*uint8)

	return out0, err

}

// StoresToUsers is a free data retrieval call binding the contract method 0xb253af66.
//
// Solidity: function storesToUsers(uint256 storeid, address storeuser) view returns(uint8)
func (_RegStore *RegStoreSession) StoresToUsers(storeid *big.Int, storeuser common.Address) (uint8, error) {
	return _RegStore.Contract.StoresToUsers(&_RegStore.CallOpts, storeid, storeuser)
}

// StoresToUsers is a free data retrieval call binding the contract method 0xb253af66.
//
// Solidity: function storesToUsers(uint256 storeid, address storeuser) view returns(uint8)
func (_RegStore *RegStoreCallerSession) StoresToUsers(storeid *big.Int, storeuser common.Address) (uint8, error) {
	return _RegStore.Contract.StoresToUsers(&_RegStore.CallOpts, storeid, storeuser)
}

// SupportsInterface is a free data retrieval call binding the contract method 0x01ffc9a7.
//
// Solidity: function supportsInterface(bytes4 interfaceId) view returns(bool result)
func (_RegStore *RegStoreCaller) SupportsInterface(opts *bind.CallOpts, interfaceId [4]byte) (bool, error) {
	var out []interface{}
	err := _RegStore.contract.Call(opts, &out, "supportsInterface", interfaceId)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// SupportsInterface is a free data retrieval call binding the contract method 0x01ffc9a7.
//
// Solidity: function supportsInterface(bytes4 interfaceId) view returns(bool result)
func (_RegStore *RegStoreSession) SupportsInterface(interfaceId [4]byte) (bool, error) {
	return _RegStore.Contract.SupportsInterface(&_RegStore.CallOpts, interfaceId)
}

// SupportsInterface is a free data retrieval call binding the contract method 0x01ffc9a7.
//
// Solidity: function supportsInterface(bytes4 interfaceId) view returns(bool result)
func (_RegStore *RegStoreCallerSession) SupportsInterface(interfaceId [4]byte) (bool, error) {
	return _RegStore.Contract.SupportsInterface(&_RegStore.CallOpts, interfaceId)
}

// Symbol is a free data retrieval call binding the contract method 0x95d89b41.
//
// Solidity: function symbol() pure returns(string)
func (_RegStore *RegStoreCaller) Symbol(opts *bind.CallOpts) (string, error) {
	var out []interface{}
	err := _RegStore.contract.Call(opts, &out, "symbol")

	if err != nil {
		return *new(string), err
	}

	out0 := *abi.ConvertType(out[0], new(string)).(*string)

	return out0, err

}

// Symbol is a free data retrieval call binding the contract method 0x95d89b41.
//
// Solidity: function symbol() pure returns(string)
func (_RegStore *RegStoreSession) Symbol() (string, error) {
	return _RegStore.Contract.Symbol(&_RegStore.CallOpts)
}

// Symbol is a free data retrieval call binding the contract method 0x95d89b41.
//
// Solidity: function symbol() pure returns(string)
func (_RegStore *RegStoreCallerSession) Symbol() (string, error) {
	return _RegStore.Contract.Symbol(&_RegStore.CallOpts)
}

// TokenURI is a free data retrieval call binding the contract method 0xc87b56dd.
//
// Solidity: function tokenURI(uint256 id) view returns(string)
func (_RegStore *RegStoreCaller) TokenURI(opts *bind.CallOpts, id *big.Int) (string, error) {
	var out []interface{}
	err := _RegStore.contract.Call(opts, &out, "tokenURI", id)

	if err != nil {
		return *new(string), err
	}

	out0 := *abi.ConvertType(out[0], new(string)).(*string)

	return out0, err

}

// TokenURI is a free data retrieval call binding the contract method 0xc87b56dd.
//
// Solidity: function tokenURI(uint256 id) view returns(string)
func (_RegStore *RegStoreSession) TokenURI(id *big.Int) (string, error) {
	return _RegStore.Contract.TokenURI(&_RegStore.CallOpts, id)
}

// TokenURI is a free data retrieval call binding the contract method 0xc87b56dd.
//
// Solidity: function tokenURI(uint256 id) view returns(string)
func (_RegStore *RegStoreCallerSession) TokenURI(id *big.Int) (string, error) {
	return _RegStore.Contract.TokenURI(&_RegStore.CallOpts, id)
}

// AddRelay is a paid mutator transaction binding the contract method 0x48f6092a.
//
// Solidity: function addRelay(uint256 storeId, uint256 relayId) returns()
func (_RegStore *RegStoreTransactor) AddRelay(opts *bind.TransactOpts, storeId *big.Int, relayId *big.Int) (*types.Transaction, error) {
	return _RegStore.contract.Transact(opts, "addRelay", storeId, relayId)
}

// AddRelay is a paid mutator transaction binding the contract method 0x48f6092a.
//
// Solidity: function addRelay(uint256 storeId, uint256 relayId) returns()
func (_RegStore *RegStoreSession) AddRelay(storeId *big.Int, relayId *big.Int) (*types.Transaction, error) {
	return _RegStore.Contract.AddRelay(&_RegStore.TransactOpts, storeId, relayId)
}

// AddRelay is a paid mutator transaction binding the contract method 0x48f6092a.
//
// Solidity: function addRelay(uint256 storeId, uint256 relayId) returns()
func (_RegStore *RegStoreTransactorSession) AddRelay(storeId *big.Int, relayId *big.Int) (*types.Transaction, error) {
	return _RegStore.Contract.AddRelay(&_RegStore.TransactOpts, storeId, relayId)
}

// Approve is a paid mutator transaction binding the contract method 0x095ea7b3.
//
// Solidity: function approve(address account, uint256 id) payable returns()
func (_RegStore *RegStoreTransactor) Approve(opts *bind.TransactOpts, account common.Address, id *big.Int) (*types.Transaction, error) {
	return _RegStore.contract.Transact(opts, "approve", account, id)
}

// Approve is a paid mutator transaction binding the contract method 0x095ea7b3.
//
// Solidity: function approve(address account, uint256 id) payable returns()
func (_RegStore *RegStoreSession) Approve(account common.Address, id *big.Int) (*types.Transaction, error) {
	return _RegStore.Contract.Approve(&_RegStore.TransactOpts, account, id)
}

// Approve is a paid mutator transaction binding the contract method 0x095ea7b3.
//
// Solidity: function approve(address account, uint256 id) payable returns()
func (_RegStore *RegStoreTransactorSession) Approve(account common.Address, id *big.Int) (*types.Transaction, error) {
	return _RegStore.Contract.Approve(&_RegStore.TransactOpts, account, id)
}

// Mint is a paid mutator transaction binding the contract method 0x94bf804d.
//
// Solidity: function mint(uint256 storeId, address owner) returns()
func (_RegStore *RegStoreTransactor) Mint(opts *bind.TransactOpts, storeId *big.Int, owner common.Address) (*types.Transaction, error) {
	return _RegStore.contract.Transact(opts, "mint", storeId, owner)
}

// Mint is a paid mutator transaction binding the contract method 0x94bf804d.
//
// Solidity: function mint(uint256 storeId, address owner) returns()
func (_RegStore *RegStoreSession) Mint(storeId *big.Int, owner common.Address) (*types.Transaction, error) {
	return _RegStore.Contract.Mint(&_RegStore.TransactOpts, storeId, owner)
}

// Mint is a paid mutator transaction binding the contract method 0x94bf804d.
//
// Solidity: function mint(uint256 storeId, address owner) returns()
func (_RegStore *RegStoreTransactorSession) Mint(storeId *big.Int, owner common.Address) (*types.Transaction, error) {
	return _RegStore.Contract.Mint(&_RegStore.TransactOpts, storeId, owner)
}

// PublishInviteVerifier is a paid mutator transaction binding the contract method 0xcec47afe.
//
// Solidity: function publishInviteVerifier(uint256 storeId, address verifier) returns()
func (_RegStore *RegStoreTransactor) PublishInviteVerifier(opts *bind.TransactOpts, storeId *big.Int, verifier common.Address) (*types.Transaction, error) {
	return _RegStore.contract.Transact(opts, "publishInviteVerifier", storeId, verifier)
}

// PublishInviteVerifier is a paid mutator transaction binding the contract method 0xcec47afe.
//
// Solidity: function publishInviteVerifier(uint256 storeId, address verifier) returns()
func (_RegStore *RegStoreSession) PublishInviteVerifier(storeId *big.Int, verifier common.Address) (*types.Transaction, error) {
	return _RegStore.Contract.PublishInviteVerifier(&_RegStore.TransactOpts, storeId, verifier)
}

// PublishInviteVerifier is a paid mutator transaction binding the contract method 0xcec47afe.
//
// Solidity: function publishInviteVerifier(uint256 storeId, address verifier) returns()
func (_RegStore *RegStoreTransactorSession) PublishInviteVerifier(storeId *big.Int, verifier common.Address) (*types.Transaction, error) {
	return _RegStore.Contract.PublishInviteVerifier(&_RegStore.TransactOpts, storeId, verifier)
}

// RedeemInvite is a paid mutator transaction binding the contract method 0xba91a89c.
//
// Solidity: function redeemInvite(uint256 storeId, uint8 v, bytes32 r, bytes32 s, address user) returns()
func (_RegStore *RegStoreTransactor) RedeemInvite(opts *bind.TransactOpts, storeId *big.Int, v uint8, r [32]byte, s [32]byte, user common.Address) (*types.Transaction, error) {
	return _RegStore.contract.Transact(opts, "redeemInvite", storeId, v, r, s, user)
}

// RedeemInvite is a paid mutator transaction binding the contract method 0xba91a89c.
//
// Solidity: function redeemInvite(uint256 storeId, uint8 v, bytes32 r, bytes32 s, address user) returns()
func (_RegStore *RegStoreSession) RedeemInvite(storeId *big.Int, v uint8, r [32]byte, s [32]byte, user common.Address) (*types.Transaction, error) {
	return _RegStore.Contract.RedeemInvite(&_RegStore.TransactOpts, storeId, v, r, s, user)
}

// RedeemInvite is a paid mutator transaction binding the contract method 0xba91a89c.
//
// Solidity: function redeemInvite(uint256 storeId, uint8 v, bytes32 r, bytes32 s, address user) returns()
func (_RegStore *RegStoreTransactorSession) RedeemInvite(storeId *big.Int, v uint8, r [32]byte, s [32]byte, user common.Address) (*types.Transaction, error) {
	return _RegStore.Contract.RedeemInvite(&_RegStore.TransactOpts, storeId, v, r, s, user)
}

// RegisterUser is a paid mutator transaction binding the contract method 0x3785096a.
//
// Solidity: function registerUser(uint256 storeId, address addr, uint8 acl) returns()
func (_RegStore *RegStoreTransactor) RegisterUser(opts *bind.TransactOpts, storeId *big.Int, addr common.Address, acl uint8) (*types.Transaction, error) {
	return _RegStore.contract.Transact(opts, "registerUser", storeId, addr, acl)
}

// RegisterUser is a paid mutator transaction binding the contract method 0x3785096a.
//
// Solidity: function registerUser(uint256 storeId, address addr, uint8 acl) returns()
func (_RegStore *RegStoreSession) RegisterUser(storeId *big.Int, addr common.Address, acl uint8) (*types.Transaction, error) {
	return _RegStore.Contract.RegisterUser(&_RegStore.TransactOpts, storeId, addr, acl)
}

// RegisterUser is a paid mutator transaction binding the contract method 0x3785096a.
//
// Solidity: function registerUser(uint256 storeId, address addr, uint8 acl) returns()
func (_RegStore *RegStoreTransactorSession) RegisterUser(storeId *big.Int, addr common.Address, acl uint8) (*types.Transaction, error) {
	return _RegStore.Contract.RegisterUser(&_RegStore.TransactOpts, storeId, addr, acl)
}

// RemoveRelay is a paid mutator transaction binding the contract method 0xe9d928d5.
//
// Solidity: function removeRelay(uint256 storeId, uint8 idx) returns()
func (_RegStore *RegStoreTransactor) RemoveRelay(opts *bind.TransactOpts, storeId *big.Int, idx uint8) (*types.Transaction, error) {
	return _RegStore.contract.Transact(opts, "removeRelay", storeId, idx)
}

// RemoveRelay is a paid mutator transaction binding the contract method 0xe9d928d5.
//
// Solidity: function removeRelay(uint256 storeId, uint8 idx) returns()
func (_RegStore *RegStoreSession) RemoveRelay(storeId *big.Int, idx uint8) (*types.Transaction, error) {
	return _RegStore.Contract.RemoveRelay(&_RegStore.TransactOpts, storeId, idx)
}

// RemoveRelay is a paid mutator transaction binding the contract method 0xe9d928d5.
//
// Solidity: function removeRelay(uint256 storeId, uint8 idx) returns()
func (_RegStore *RegStoreTransactorSession) RemoveRelay(storeId *big.Int, idx uint8) (*types.Transaction, error) {
	return _RegStore.Contract.RemoveRelay(&_RegStore.TransactOpts, storeId, idx)
}

// RemoveUser is a paid mutator transaction binding the contract method 0x0c8f91a9.
//
// Solidity: function removeUser(uint256 storeId, address who) returns()
func (_RegStore *RegStoreTransactor) RemoveUser(opts *bind.TransactOpts, storeId *big.Int, who common.Address) (*types.Transaction, error) {
	return _RegStore.contract.Transact(opts, "removeUser", storeId, who)
}

// RemoveUser is a paid mutator transaction binding the contract method 0x0c8f91a9.
//
// Solidity: function removeUser(uint256 storeId, address who) returns()
func (_RegStore *RegStoreSession) RemoveUser(storeId *big.Int, who common.Address) (*types.Transaction, error) {
	return _RegStore.Contract.RemoveUser(&_RegStore.TransactOpts, storeId, who)
}

// RemoveUser is a paid mutator transaction binding the contract method 0x0c8f91a9.
//
// Solidity: function removeUser(uint256 storeId, address who) returns()
func (_RegStore *RegStoreTransactorSession) RemoveUser(storeId *big.Int, who common.Address) (*types.Transaction, error) {
	return _RegStore.Contract.RemoveUser(&_RegStore.TransactOpts, storeId, who)
}

// ReplaceRelay is a paid mutator transaction binding the contract method 0x3447af9f.
//
// Solidity: function replaceRelay(uint256 storeId, uint8 idx, uint256 relayId) returns()
func (_RegStore *RegStoreTransactor) ReplaceRelay(opts *bind.TransactOpts, storeId *big.Int, idx uint8, relayId *big.Int) (*types.Transaction, error) {
	return _RegStore.contract.Transact(opts, "replaceRelay", storeId, idx, relayId)
}

// ReplaceRelay is a paid mutator transaction binding the contract method 0x3447af9f.
//
// Solidity: function replaceRelay(uint256 storeId, uint8 idx, uint256 relayId) returns()
func (_RegStore *RegStoreSession) ReplaceRelay(storeId *big.Int, idx uint8, relayId *big.Int) (*types.Transaction, error) {
	return _RegStore.Contract.ReplaceRelay(&_RegStore.TransactOpts, storeId, idx, relayId)
}

// ReplaceRelay is a paid mutator transaction binding the contract method 0x3447af9f.
//
// Solidity: function replaceRelay(uint256 storeId, uint8 idx, uint256 relayId) returns()
func (_RegStore *RegStoreTransactorSession) ReplaceRelay(storeId *big.Int, idx uint8, relayId *big.Int) (*types.Transaction, error) {
	return _RegStore.Contract.ReplaceRelay(&_RegStore.TransactOpts, storeId, idx, relayId)
}

// SafeTransferFrom is a paid mutator transaction binding the contract method 0x42842e0e.
//
// Solidity: function safeTransferFrom(address from, address to, uint256 id) payable returns()
func (_RegStore *RegStoreTransactor) SafeTransferFrom(opts *bind.TransactOpts, from common.Address, to common.Address, id *big.Int) (*types.Transaction, error) {
	return _RegStore.contract.Transact(opts, "safeTransferFrom", from, to, id)
}

// SafeTransferFrom is a paid mutator transaction binding the contract method 0x42842e0e.
//
// Solidity: function safeTransferFrom(address from, address to, uint256 id) payable returns()
func (_RegStore *RegStoreSession) SafeTransferFrom(from common.Address, to common.Address, id *big.Int) (*types.Transaction, error) {
	return _RegStore.Contract.SafeTransferFrom(&_RegStore.TransactOpts, from, to, id)
}

// SafeTransferFrom is a paid mutator transaction binding the contract method 0x42842e0e.
//
// Solidity: function safeTransferFrom(address from, address to, uint256 id) payable returns()
func (_RegStore *RegStoreTransactorSession) SafeTransferFrom(from common.Address, to common.Address, id *big.Int) (*types.Transaction, error) {
	return _RegStore.Contract.SafeTransferFrom(&_RegStore.TransactOpts, from, to, id)
}

// SafeTransferFrom0 is a paid mutator transaction binding the contract method 0xb88d4fde.
//
// Solidity: function safeTransferFrom(address from, address to, uint256 id, bytes data) payable returns()
func (_RegStore *RegStoreTransactor) SafeTransferFrom0(opts *bind.TransactOpts, from common.Address, to common.Address, id *big.Int, data []byte) (*types.Transaction, error) {
	return _RegStore.contract.Transact(opts, "safeTransferFrom0", from, to, id, data)
}

// SafeTransferFrom0 is a paid mutator transaction binding the contract method 0xb88d4fde.
//
// Solidity: function safeTransferFrom(address from, address to, uint256 id, bytes data) payable returns()
func (_RegStore *RegStoreSession) SafeTransferFrom0(from common.Address, to common.Address, id *big.Int, data []byte) (*types.Transaction, error) {
	return _RegStore.Contract.SafeTransferFrom0(&_RegStore.TransactOpts, from, to, id, data)
}

// SafeTransferFrom0 is a paid mutator transaction binding the contract method 0xb88d4fde.
//
// Solidity: function safeTransferFrom(address from, address to, uint256 id, bytes data) payable returns()
func (_RegStore *RegStoreTransactorSession) SafeTransferFrom0(from common.Address, to common.Address, id *big.Int, data []byte) (*types.Transaction, error) {
	return _RegStore.Contract.SafeTransferFrom0(&_RegStore.TransactOpts, from, to, id, data)
}

// SetApprovalForAll is a paid mutator transaction binding the contract method 0xa22cb465.
//
// Solidity: function setApprovalForAll(address operator, bool isApproved) returns()
func (_RegStore *RegStoreTransactor) SetApprovalForAll(opts *bind.TransactOpts, operator common.Address, isApproved bool) (*types.Transaction, error) {
	return _RegStore.contract.Transact(opts, "setApprovalForAll", operator, isApproved)
}

// SetApprovalForAll is a paid mutator transaction binding the contract method 0xa22cb465.
//
// Solidity: function setApprovalForAll(address operator, bool isApproved) returns()
func (_RegStore *RegStoreSession) SetApprovalForAll(operator common.Address, isApproved bool) (*types.Transaction, error) {
	return _RegStore.Contract.SetApprovalForAll(&_RegStore.TransactOpts, operator, isApproved)
}

// SetApprovalForAll is a paid mutator transaction binding the contract method 0xa22cb465.
//
// Solidity: function setApprovalForAll(address operator, bool isApproved) returns()
func (_RegStore *RegStoreTransactorSession) SetApprovalForAll(operator common.Address, isApproved bool) (*types.Transaction, error) {
	return _RegStore.Contract.SetApprovalForAll(&_RegStore.TransactOpts, operator, isApproved)
}

// TransferFrom is a paid mutator transaction binding the contract method 0x23b872dd.
//
// Solidity: function transferFrom(address from, address to, uint256 id) payable returns()
func (_RegStore *RegStoreTransactor) TransferFrom(opts *bind.TransactOpts, from common.Address, to common.Address, id *big.Int) (*types.Transaction, error) {
	return _RegStore.contract.Transact(opts, "transferFrom", from, to, id)
}

// TransferFrom is a paid mutator transaction binding the contract method 0x23b872dd.
//
// Solidity: function transferFrom(address from, address to, uint256 id) payable returns()
func (_RegStore *RegStoreSession) TransferFrom(from common.Address, to common.Address, id *big.Int) (*types.Transaction, error) {
	return _RegStore.Contract.TransferFrom(&_RegStore.TransactOpts, from, to, id)
}

// TransferFrom is a paid mutator transaction binding the contract method 0x23b872dd.
//
// Solidity: function transferFrom(address from, address to, uint256 id) payable returns()
func (_RegStore *RegStoreTransactorSession) TransferFrom(from common.Address, to common.Address, id *big.Int) (*types.Transaction, error) {
	return _RegStore.Contract.TransferFrom(&_RegStore.TransactOpts, from, to, id)
}

// UpdateRootHash is a paid mutator transaction binding the contract method 0xd5e0bb66.
//
// Solidity: function updateRootHash(uint256 storeId, bytes32 hash) returns()
func (_RegStore *RegStoreTransactor) UpdateRootHash(opts *bind.TransactOpts, storeId *big.Int, hash [32]byte) (*types.Transaction, error) {
	return _RegStore.contract.Transact(opts, "updateRootHash", storeId, hash)
}

// UpdateRootHash is a paid mutator transaction binding the contract method 0xd5e0bb66.
//
// Solidity: function updateRootHash(uint256 storeId, bytes32 hash) returns()
func (_RegStore *RegStoreSession) UpdateRootHash(storeId *big.Int, hash [32]byte) (*types.Transaction, error) {
	return _RegStore.Contract.UpdateRootHash(&_RegStore.TransactOpts, storeId, hash)
}

// UpdateRootHash is a paid mutator transaction binding the contract method 0xd5e0bb66.
//
// Solidity: function updateRootHash(uint256 storeId, bytes32 hash) returns()
func (_RegStore *RegStoreTransactorSession) UpdateRootHash(storeId *big.Int, hash [32]byte) (*types.Transaction, error) {
	return _RegStore.Contract.UpdateRootHash(&_RegStore.TransactOpts, storeId, hash)
}

// RegStoreApprovalIterator is returned from FilterApproval and is used to iterate over the raw logs and unpacked data for Approval events raised by the RegStore contract.
type RegStoreApprovalIterator struct {
	Event *RegStoreApproval // Event containing the contract specifics and raw log

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
func (it *RegStoreApprovalIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(RegStoreApproval)
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
		it.Event = new(RegStoreApproval)
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
func (it *RegStoreApprovalIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *RegStoreApprovalIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// RegStoreApproval represents a Approval event raised by the RegStore contract.
type RegStoreApproval struct {
	Owner   common.Address
	Account common.Address
	Id      *big.Int
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterApproval is a free log retrieval operation binding the contract event 0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925.
//
// Solidity: event Approval(address indexed owner, address indexed account, uint256 indexed id)
func (_RegStore *RegStoreFilterer) FilterApproval(opts *bind.FilterOpts, owner []common.Address, account []common.Address, id []*big.Int) (*RegStoreApprovalIterator, error) {

	var ownerRule []interface{}
	for _, ownerItem := range owner {
		ownerRule = append(ownerRule, ownerItem)
	}
	var accountRule []interface{}
	for _, accountItem := range account {
		accountRule = append(accountRule, accountItem)
	}
	var idRule []interface{}
	for _, idItem := range id {
		idRule = append(idRule, idItem)
	}

	logs, sub, err := _RegStore.contract.FilterLogs(opts, "Approval", ownerRule, accountRule, idRule)
	if err != nil {
		return nil, err
	}
	return &RegStoreApprovalIterator{contract: _RegStore.contract, event: "Approval", logs: logs, sub: sub}, nil
}

// WatchApproval is a free log subscription operation binding the contract event 0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925.
//
// Solidity: event Approval(address indexed owner, address indexed account, uint256 indexed id)
func (_RegStore *RegStoreFilterer) WatchApproval(opts *bind.WatchOpts, sink chan<- *RegStoreApproval, owner []common.Address, account []common.Address, id []*big.Int) (event.Subscription, error) {

	var ownerRule []interface{}
	for _, ownerItem := range owner {
		ownerRule = append(ownerRule, ownerItem)
	}
	var accountRule []interface{}
	for _, accountItem := range account {
		accountRule = append(accountRule, accountItem)
	}
	var idRule []interface{}
	for _, idItem := range id {
		idRule = append(idRule, idItem)
	}

	logs, sub, err := _RegStore.contract.WatchLogs(opts, "Approval", ownerRule, accountRule, idRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(RegStoreApproval)
				if err := _RegStore.contract.UnpackLog(event, "Approval", log); err != nil {
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
// Solidity: event Approval(address indexed owner, address indexed account, uint256 indexed id)
func (_RegStore *RegStoreFilterer) ParseApproval(log types.Log) (*RegStoreApproval, error) {
	event := new(RegStoreApproval)
	if err := _RegStore.contract.UnpackLog(event, "Approval", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// RegStoreApprovalForAllIterator is returned from FilterApprovalForAll and is used to iterate over the raw logs and unpacked data for ApprovalForAll events raised by the RegStore contract.
type RegStoreApprovalForAllIterator struct {
	Event *RegStoreApprovalForAll // Event containing the contract specifics and raw log

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
func (it *RegStoreApprovalForAllIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(RegStoreApprovalForAll)
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
		it.Event = new(RegStoreApprovalForAll)
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
func (it *RegStoreApprovalForAllIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *RegStoreApprovalForAllIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// RegStoreApprovalForAll represents a ApprovalForAll event raised by the RegStore contract.
type RegStoreApprovalForAll struct {
	Owner      common.Address
	Operator   common.Address
	IsApproved bool
	Raw        types.Log // Blockchain specific contextual infos
}

// FilterApprovalForAll is a free log retrieval operation binding the contract event 0x17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31.
//
// Solidity: event ApprovalForAll(address indexed owner, address indexed operator, bool isApproved)
func (_RegStore *RegStoreFilterer) FilterApprovalForAll(opts *bind.FilterOpts, owner []common.Address, operator []common.Address) (*RegStoreApprovalForAllIterator, error) {

	var ownerRule []interface{}
	for _, ownerItem := range owner {
		ownerRule = append(ownerRule, ownerItem)
	}
	var operatorRule []interface{}
	for _, operatorItem := range operator {
		operatorRule = append(operatorRule, operatorItem)
	}

	logs, sub, err := _RegStore.contract.FilterLogs(opts, "ApprovalForAll", ownerRule, operatorRule)
	if err != nil {
		return nil, err
	}
	return &RegStoreApprovalForAllIterator{contract: _RegStore.contract, event: "ApprovalForAll", logs: logs, sub: sub}, nil
}

// WatchApprovalForAll is a free log subscription operation binding the contract event 0x17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31.
//
// Solidity: event ApprovalForAll(address indexed owner, address indexed operator, bool isApproved)
func (_RegStore *RegStoreFilterer) WatchApprovalForAll(opts *bind.WatchOpts, sink chan<- *RegStoreApprovalForAll, owner []common.Address, operator []common.Address) (event.Subscription, error) {

	var ownerRule []interface{}
	for _, ownerItem := range owner {
		ownerRule = append(ownerRule, ownerItem)
	}
	var operatorRule []interface{}
	for _, operatorItem := range operator {
		operatorRule = append(operatorRule, operatorItem)
	}

	logs, sub, err := _RegStore.contract.WatchLogs(opts, "ApprovalForAll", ownerRule, operatorRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(RegStoreApprovalForAll)
				if err := _RegStore.contract.UnpackLog(event, "ApprovalForAll", log); err != nil {
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
// Solidity: event ApprovalForAll(address indexed owner, address indexed operator, bool isApproved)
func (_RegStore *RegStoreFilterer) ParseApprovalForAll(log types.Log) (*RegStoreApprovalForAll, error) {
	event := new(RegStoreApprovalForAll)
	if err := _RegStore.contract.UnpackLog(event, "ApprovalForAll", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// RegStoreTransferIterator is returned from FilterTransfer and is used to iterate over the raw logs and unpacked data for Transfer events raised by the RegStore contract.
type RegStoreTransferIterator struct {
	Event *RegStoreTransfer // Event containing the contract specifics and raw log

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
func (it *RegStoreTransferIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(RegStoreTransfer)
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
		it.Event = new(RegStoreTransfer)
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
func (it *RegStoreTransferIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *RegStoreTransferIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// RegStoreTransfer represents a Transfer event raised by the RegStore contract.
type RegStoreTransfer struct {
	From common.Address
	To   common.Address
	Id   *big.Int
	Raw  types.Log // Blockchain specific contextual infos
}

// FilterTransfer is a free log retrieval operation binding the contract event 0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef.
//
// Solidity: event Transfer(address indexed from, address indexed to, uint256 indexed id)
func (_RegStore *RegStoreFilterer) FilterTransfer(opts *bind.FilterOpts, from []common.Address, to []common.Address, id []*big.Int) (*RegStoreTransferIterator, error) {

	var fromRule []interface{}
	for _, fromItem := range from {
		fromRule = append(fromRule, fromItem)
	}
	var toRule []interface{}
	for _, toItem := range to {
		toRule = append(toRule, toItem)
	}
	var idRule []interface{}
	for _, idItem := range id {
		idRule = append(idRule, idItem)
	}

	logs, sub, err := _RegStore.contract.FilterLogs(opts, "Transfer", fromRule, toRule, idRule)
	if err != nil {
		return nil, err
	}
	return &RegStoreTransferIterator{contract: _RegStore.contract, event: "Transfer", logs: logs, sub: sub}, nil
}

// WatchTransfer is a free log subscription operation binding the contract event 0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef.
//
// Solidity: event Transfer(address indexed from, address indexed to, uint256 indexed id)
func (_RegStore *RegStoreFilterer) WatchTransfer(opts *bind.WatchOpts, sink chan<- *RegStoreTransfer, from []common.Address, to []common.Address, id []*big.Int) (event.Subscription, error) {

	var fromRule []interface{}
	for _, fromItem := range from {
		fromRule = append(fromRule, fromItem)
	}
	var toRule []interface{}
	for _, toItem := range to {
		toRule = append(toRule, toItem)
	}
	var idRule []interface{}
	for _, idItem := range id {
		idRule = append(idRule, idItem)
	}

	logs, sub, err := _RegStore.contract.WatchLogs(opts, "Transfer", fromRule, toRule, idRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(RegStoreTransfer)
				if err := _RegStore.contract.UnpackLog(event, "Transfer", log); err != nil {
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
// Solidity: event Transfer(address indexed from, address indexed to, uint256 indexed id)
func (_RegStore *RegStoreFilterer) ParseTransfer(log types.Log) (*RegStoreTransfer, error) {
	event := new(RegStoreTransfer)
	if err := _RegStore.contract.UnpackLog(event, "Transfer", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// RegStoreUserAddedIterator is returned from FilterUserAdded and is used to iterate over the raw logs and unpacked data for UserAdded events raised by the RegStore contract.
type RegStoreUserAddedIterator struct {
	Event *RegStoreUserAdded // Event containing the contract specifics and raw log

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
func (it *RegStoreUserAddedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(RegStoreUserAdded)
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
		it.Event = new(RegStoreUserAdded)
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
func (it *RegStoreUserAddedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *RegStoreUserAddedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// RegStoreUserAdded represents a UserAdded event raised by the RegStore contract.
type RegStoreUserAdded struct {
	StoreId *big.Int
	User    common.Address
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterUserAdded is a free log retrieval operation binding the contract event 0x785caf8769bd44d265fce8c1a3327e91646fe19be3a87506383b5e95a5c43494.
//
// Solidity: event UserAdded(uint256 indexed storeId, address user)
func (_RegStore *RegStoreFilterer) FilterUserAdded(opts *bind.FilterOpts, storeId []*big.Int) (*RegStoreUserAddedIterator, error) {

	var storeIdRule []interface{}
	for _, storeIdItem := range storeId {
		storeIdRule = append(storeIdRule, storeIdItem)
	}

	logs, sub, err := _RegStore.contract.FilterLogs(opts, "UserAdded", storeIdRule)
	if err != nil {
		return nil, err
	}
	return &RegStoreUserAddedIterator{contract: _RegStore.contract, event: "UserAdded", logs: logs, sub: sub}, nil
}

// WatchUserAdded is a free log subscription operation binding the contract event 0x785caf8769bd44d265fce8c1a3327e91646fe19be3a87506383b5e95a5c43494.
//
// Solidity: event UserAdded(uint256 indexed storeId, address user)
func (_RegStore *RegStoreFilterer) WatchUserAdded(opts *bind.WatchOpts, sink chan<- *RegStoreUserAdded, storeId []*big.Int) (event.Subscription, error) {

	var storeIdRule []interface{}
	for _, storeIdItem := range storeId {
		storeIdRule = append(storeIdRule, storeIdItem)
	}

	logs, sub, err := _RegStore.contract.WatchLogs(opts, "UserAdded", storeIdRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(RegStoreUserAdded)
				if err := _RegStore.contract.UnpackLog(event, "UserAdded", log); err != nil {
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

// ParseUserAdded is a log parse operation binding the contract event 0x785caf8769bd44d265fce8c1a3327e91646fe19be3a87506383b5e95a5c43494.
//
// Solidity: event UserAdded(uint256 indexed storeId, address user)
func (_RegStore *RegStoreFilterer) ParseUserAdded(log types.Log) (*RegStoreUserAdded, error) {
	event := new(RegStoreUserAdded)
	if err := _RegStore.contract.UnpackLog(event, "UserAdded", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// RegStoreUserRemovedIterator is returned from FilterUserRemoved and is used to iterate over the raw logs and unpacked data for UserRemoved events raised by the RegStore contract.
type RegStoreUserRemovedIterator struct {
	Event *RegStoreUserRemoved // Event containing the contract specifics and raw log

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
func (it *RegStoreUserRemovedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(RegStoreUserRemoved)
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
		it.Event = new(RegStoreUserRemoved)
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
func (it *RegStoreUserRemovedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *RegStoreUserRemovedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// RegStoreUserRemoved represents a UserRemoved event raised by the RegStore contract.
type RegStoreUserRemoved struct {
	StoreId *big.Int
	Users   common.Address
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterUserRemoved is a free log retrieval operation binding the contract event 0x89703ec90073f7f060a05db721bf6e6bfea7a783e08a7d7e3c50667da7a491f5.
//
// Solidity: event UserRemoved(uint256 indexed storeId, address users)
func (_RegStore *RegStoreFilterer) FilterUserRemoved(opts *bind.FilterOpts, storeId []*big.Int) (*RegStoreUserRemovedIterator, error) {

	var storeIdRule []interface{}
	for _, storeIdItem := range storeId {
		storeIdRule = append(storeIdRule, storeIdItem)
	}

	logs, sub, err := _RegStore.contract.FilterLogs(opts, "UserRemoved", storeIdRule)
	if err != nil {
		return nil, err
	}
	return &RegStoreUserRemovedIterator{contract: _RegStore.contract, event: "UserRemoved", logs: logs, sub: sub}, nil
}

// WatchUserRemoved is a free log subscription operation binding the contract event 0x89703ec90073f7f060a05db721bf6e6bfea7a783e08a7d7e3c50667da7a491f5.
//
// Solidity: event UserRemoved(uint256 indexed storeId, address users)
func (_RegStore *RegStoreFilterer) WatchUserRemoved(opts *bind.WatchOpts, sink chan<- *RegStoreUserRemoved, storeId []*big.Int) (event.Subscription, error) {

	var storeIdRule []interface{}
	for _, storeIdItem := range storeId {
		storeIdRule = append(storeIdRule, storeIdItem)
	}

	logs, sub, err := _RegStore.contract.WatchLogs(opts, "UserRemoved", storeIdRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(RegStoreUserRemoved)
				if err := _RegStore.contract.UnpackLog(event, "UserRemoved", log); err != nil {
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
// Solidity: event UserRemoved(uint256 indexed storeId, address users)
func (_RegStore *RegStoreFilterer) ParseUserRemoved(log types.Log) (*RegStoreUserRemoved, error) {
	event := new(RegStoreUserRemoved)
	if err := _RegStore.contract.UnpackLog(event, "UserRemoved", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}
