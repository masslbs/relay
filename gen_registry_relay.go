// SPDX-FileCopyrightText: 2024 Mass Labs
//
// SPDX-License-Identifier: GPL-3.0-or-later

// Generated from abi/RelayReg.json - git at 0d9625366fb6e24fb5f3b70b43d981764a26e3a2

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

// RegRelayMetaData contains all meta data concerning the RegRelay contract.
var RegRelayMetaData = &bind.MetaData{
	ABI: "[{\"type\":\"constructor\",\"inputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"approve\",\"inputs\":[{\"name\":\"account\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"id\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[],\"stateMutability\":\"payable\"},{\"type\":\"function\",\"name\":\"balanceOf\",\"inputs\":[{\"name\":\"owner\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[{\"name\":\"result\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"getApproved\",\"inputs\":[{\"name\":\"id\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[{\"name\":\"result\",\"type\":\"address\",\"internalType\":\"address\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"isApprovedForAll\",\"inputs\":[{\"name\":\"owner\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"operator\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[{\"name\":\"result\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"mint\",\"inputs\":[{\"name\":\"newRelayId\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"relay\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"uri\",\"type\":\"string\",\"internalType\":\"string\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"name\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"string\",\"internalType\":\"string\"}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"ownerOf\",\"inputs\":[{\"name\":\"id\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[{\"name\":\"result\",\"type\":\"address\",\"internalType\":\"address\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"relayURIs\",\"inputs\":[{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[{\"name\":\"\",\"type\":\"string\",\"internalType\":\"string\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"safeTransferFrom\",\"inputs\":[{\"name\":\"from\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"to\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"id\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[],\"stateMutability\":\"payable\"},{\"type\":\"function\",\"name\":\"safeTransferFrom\",\"inputs\":[{\"name\":\"from\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"to\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"id\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"data\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"outputs\":[],\"stateMutability\":\"payable\"},{\"type\":\"function\",\"name\":\"setApprovalForAll\",\"inputs\":[{\"name\":\"operator\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"isApproved\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"supportsInterface\",\"inputs\":[{\"name\":\"interfaceId\",\"type\":\"bytes4\",\"internalType\":\"bytes4\"}],\"outputs\":[{\"name\":\"result\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"symbol\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"string\",\"internalType\":\"string\"}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"tokenURI\",\"inputs\":[{\"name\":\"id\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[{\"name\":\"\",\"type\":\"string\",\"internalType\":\"string\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"transferFrom\",\"inputs\":[{\"name\":\"from\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"to\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"id\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[],\"stateMutability\":\"payable\"},{\"type\":\"function\",\"name\":\"updateURI\",\"inputs\":[{\"name\":\"relayId\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"uri\",\"type\":\"string\",\"internalType\":\"string\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"event\",\"name\":\"Approval\",\"inputs\":[{\"name\":\"owner\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"account\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"id\",\"type\":\"uint256\",\"indexed\":true,\"internalType\":\"uint256\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"ApprovalForAll\",\"inputs\":[{\"name\":\"owner\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"operator\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"isApproved\",\"type\":\"bool\",\"indexed\":false,\"internalType\":\"bool\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"Transfer\",\"inputs\":[{\"name\":\"from\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"to\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"id\",\"type\":\"uint256\",\"indexed\":true,\"internalType\":\"uint256\"}],\"anonymous\":false},{\"type\":\"error\",\"name\":\"AccountBalanceOverflow\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"BalanceQueryForZeroAddress\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"NotOwnerNorApproved\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"TokenAlreadyExists\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"TokenDoesNotExist\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"TransferFromIncorrectOwner\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"TransferToNonERC721ReceiverImplementer\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"TransferToZeroAddress\",\"inputs\":[]}]",
}

// RegRelayABI is the input ABI used to generate the binding from.
// Deprecated: Use RegRelayMetaData.ABI instead.
var RegRelayABI = RegRelayMetaData.ABI

// RegRelay is an auto generated Go binding around an Ethereum contract.
type RegRelay struct {
	RegRelayCaller     // Read-only binding to the contract
	RegRelayTransactor // Write-only binding to the contract
	RegRelayFilterer   // Log filterer for contract events
}

// RegRelayCaller is an auto generated read-only Go binding around an Ethereum contract.
type RegRelayCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// RegRelayTransactor is an auto generated write-only Go binding around an Ethereum contract.
type RegRelayTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// RegRelayFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type RegRelayFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// RegRelaySession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type RegRelaySession struct {
	Contract     *RegRelay         // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// RegRelayCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type RegRelayCallerSession struct {
	Contract *RegRelayCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts   // Call options to use throughout this session
}

// RegRelayTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type RegRelayTransactorSession struct {
	Contract     *RegRelayTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts   // Transaction auth options to use throughout this session
}

// RegRelayRaw is an auto generated low-level Go binding around an Ethereum contract.
type RegRelayRaw struct {
	Contract *RegRelay // Generic contract binding to access the raw methods on
}

// RegRelayCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type RegRelayCallerRaw struct {
	Contract *RegRelayCaller // Generic read-only contract binding to access the raw methods on
}

// RegRelayTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type RegRelayTransactorRaw struct {
	Contract *RegRelayTransactor // Generic write-only contract binding to access the raw methods on
}

// NewRegRelay creates a new instance of RegRelay, bound to a specific deployed contract.
func NewRegRelay(address common.Address, backend bind.ContractBackend) (*RegRelay, error) {
	contract, err := bindRegRelay(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &RegRelay{RegRelayCaller: RegRelayCaller{contract: contract}, RegRelayTransactor: RegRelayTransactor{contract: contract}, RegRelayFilterer: RegRelayFilterer{contract: contract}}, nil
}

// NewRegRelayCaller creates a new read-only instance of RegRelay, bound to a specific deployed contract.
func NewRegRelayCaller(address common.Address, caller bind.ContractCaller) (*RegRelayCaller, error) {
	contract, err := bindRegRelay(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &RegRelayCaller{contract: contract}, nil
}

// NewRegRelayTransactor creates a new write-only instance of RegRelay, bound to a specific deployed contract.
func NewRegRelayTransactor(address common.Address, transactor bind.ContractTransactor) (*RegRelayTransactor, error) {
	contract, err := bindRegRelay(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &RegRelayTransactor{contract: contract}, nil
}

// NewRegRelayFilterer creates a new log filterer instance of RegRelay, bound to a specific deployed contract.
func NewRegRelayFilterer(address common.Address, filterer bind.ContractFilterer) (*RegRelayFilterer, error) {
	contract, err := bindRegRelay(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &RegRelayFilterer{contract: contract}, nil
}

// bindRegRelay binds a generic wrapper to an already deployed contract.
func bindRegRelay(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := RegRelayMetaData.GetAbi()
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, *parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_RegRelay *RegRelayRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _RegRelay.Contract.RegRelayCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_RegRelay *RegRelayRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _RegRelay.Contract.RegRelayTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_RegRelay *RegRelayRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _RegRelay.Contract.RegRelayTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_RegRelay *RegRelayCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _RegRelay.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_RegRelay *RegRelayTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _RegRelay.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_RegRelay *RegRelayTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _RegRelay.Contract.contract.Transact(opts, method, params...)
}

// BalanceOf is a free data retrieval call binding the contract method 0x70a08231.
//
// Solidity: function balanceOf(address owner) view returns(uint256 result)
func (_RegRelay *RegRelayCaller) BalanceOf(opts *bind.CallOpts, owner common.Address) (*big.Int, error) {
	var out []interface{}
	err := _RegRelay.contract.Call(opts, &out, "balanceOf", owner)

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// BalanceOf is a free data retrieval call binding the contract method 0x70a08231.
//
// Solidity: function balanceOf(address owner) view returns(uint256 result)
func (_RegRelay *RegRelaySession) BalanceOf(owner common.Address) (*big.Int, error) {
	return _RegRelay.Contract.BalanceOf(&_RegRelay.CallOpts, owner)
}

// BalanceOf is a free data retrieval call binding the contract method 0x70a08231.
//
// Solidity: function balanceOf(address owner) view returns(uint256 result)
func (_RegRelay *RegRelayCallerSession) BalanceOf(owner common.Address) (*big.Int, error) {
	return _RegRelay.Contract.BalanceOf(&_RegRelay.CallOpts, owner)
}

// GetApproved is a free data retrieval call binding the contract method 0x081812fc.
//
// Solidity: function getApproved(uint256 id) view returns(address result)
func (_RegRelay *RegRelayCaller) GetApproved(opts *bind.CallOpts, id *big.Int) (common.Address, error) {
	var out []interface{}
	err := _RegRelay.contract.Call(opts, &out, "getApproved", id)

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// GetApproved is a free data retrieval call binding the contract method 0x081812fc.
//
// Solidity: function getApproved(uint256 id) view returns(address result)
func (_RegRelay *RegRelaySession) GetApproved(id *big.Int) (common.Address, error) {
	return _RegRelay.Contract.GetApproved(&_RegRelay.CallOpts, id)
}

// GetApproved is a free data retrieval call binding the contract method 0x081812fc.
//
// Solidity: function getApproved(uint256 id) view returns(address result)
func (_RegRelay *RegRelayCallerSession) GetApproved(id *big.Int) (common.Address, error) {
	return _RegRelay.Contract.GetApproved(&_RegRelay.CallOpts, id)
}

// IsApprovedForAll is a free data retrieval call binding the contract method 0xe985e9c5.
//
// Solidity: function isApprovedForAll(address owner, address operator) view returns(bool result)
func (_RegRelay *RegRelayCaller) IsApprovedForAll(opts *bind.CallOpts, owner common.Address, operator common.Address) (bool, error) {
	var out []interface{}
	err := _RegRelay.contract.Call(opts, &out, "isApprovedForAll", owner, operator)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// IsApprovedForAll is a free data retrieval call binding the contract method 0xe985e9c5.
//
// Solidity: function isApprovedForAll(address owner, address operator) view returns(bool result)
func (_RegRelay *RegRelaySession) IsApprovedForAll(owner common.Address, operator common.Address) (bool, error) {
	return _RegRelay.Contract.IsApprovedForAll(&_RegRelay.CallOpts, owner, operator)
}

// IsApprovedForAll is a free data retrieval call binding the contract method 0xe985e9c5.
//
// Solidity: function isApprovedForAll(address owner, address operator) view returns(bool result)
func (_RegRelay *RegRelayCallerSession) IsApprovedForAll(owner common.Address, operator common.Address) (bool, error) {
	return _RegRelay.Contract.IsApprovedForAll(&_RegRelay.CallOpts, owner, operator)
}

// Name is a free data retrieval call binding the contract method 0x06fdde03.
//
// Solidity: function name() pure returns(string)
func (_RegRelay *RegRelayCaller) Name(opts *bind.CallOpts) (string, error) {
	var out []interface{}
	err := _RegRelay.contract.Call(opts, &out, "name")

	if err != nil {
		return *new(string), err
	}

	out0 := *abi.ConvertType(out[0], new(string)).(*string)

	return out0, err

}

// Name is a free data retrieval call binding the contract method 0x06fdde03.
//
// Solidity: function name() pure returns(string)
func (_RegRelay *RegRelaySession) Name() (string, error) {
	return _RegRelay.Contract.Name(&_RegRelay.CallOpts)
}

// Name is a free data retrieval call binding the contract method 0x06fdde03.
//
// Solidity: function name() pure returns(string)
func (_RegRelay *RegRelayCallerSession) Name() (string, error) {
	return _RegRelay.Contract.Name(&_RegRelay.CallOpts)
}

// OwnerOf is a free data retrieval call binding the contract method 0x6352211e.
//
// Solidity: function ownerOf(uint256 id) view returns(address result)
func (_RegRelay *RegRelayCaller) OwnerOf(opts *bind.CallOpts, id *big.Int) (common.Address, error) {
	var out []interface{}
	err := _RegRelay.contract.Call(opts, &out, "ownerOf", id)

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// OwnerOf is a free data retrieval call binding the contract method 0x6352211e.
//
// Solidity: function ownerOf(uint256 id) view returns(address result)
func (_RegRelay *RegRelaySession) OwnerOf(id *big.Int) (common.Address, error) {
	return _RegRelay.Contract.OwnerOf(&_RegRelay.CallOpts, id)
}

// OwnerOf is a free data retrieval call binding the contract method 0x6352211e.
//
// Solidity: function ownerOf(uint256 id) view returns(address result)
func (_RegRelay *RegRelayCallerSession) OwnerOf(id *big.Int) (common.Address, error) {
	return _RegRelay.Contract.OwnerOf(&_RegRelay.CallOpts, id)
}

// RelayURIs is a free data retrieval call binding the contract method 0x8a465217.
//
// Solidity: function relayURIs(uint256 ) view returns(string)
func (_RegRelay *RegRelayCaller) RelayURIs(opts *bind.CallOpts, arg0 *big.Int) (string, error) {
	var out []interface{}
	err := _RegRelay.contract.Call(opts, &out, "relayURIs", arg0)

	if err != nil {
		return *new(string), err
	}

	out0 := *abi.ConvertType(out[0], new(string)).(*string)

	return out0, err

}

// RelayURIs is a free data retrieval call binding the contract method 0x8a465217.
//
// Solidity: function relayURIs(uint256 ) view returns(string)
func (_RegRelay *RegRelaySession) RelayURIs(arg0 *big.Int) (string, error) {
	return _RegRelay.Contract.RelayURIs(&_RegRelay.CallOpts, arg0)
}

// RelayURIs is a free data retrieval call binding the contract method 0x8a465217.
//
// Solidity: function relayURIs(uint256 ) view returns(string)
func (_RegRelay *RegRelayCallerSession) RelayURIs(arg0 *big.Int) (string, error) {
	return _RegRelay.Contract.RelayURIs(&_RegRelay.CallOpts, arg0)
}

// SupportsInterface is a free data retrieval call binding the contract method 0x01ffc9a7.
//
// Solidity: function supportsInterface(bytes4 interfaceId) view returns(bool result)
func (_RegRelay *RegRelayCaller) SupportsInterface(opts *bind.CallOpts, interfaceId [4]byte) (bool, error) {
	var out []interface{}
	err := _RegRelay.contract.Call(opts, &out, "supportsInterface", interfaceId)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// SupportsInterface is a free data retrieval call binding the contract method 0x01ffc9a7.
//
// Solidity: function supportsInterface(bytes4 interfaceId) view returns(bool result)
func (_RegRelay *RegRelaySession) SupportsInterface(interfaceId [4]byte) (bool, error) {
	return _RegRelay.Contract.SupportsInterface(&_RegRelay.CallOpts, interfaceId)
}

// SupportsInterface is a free data retrieval call binding the contract method 0x01ffc9a7.
//
// Solidity: function supportsInterface(bytes4 interfaceId) view returns(bool result)
func (_RegRelay *RegRelayCallerSession) SupportsInterface(interfaceId [4]byte) (bool, error) {
	return _RegRelay.Contract.SupportsInterface(&_RegRelay.CallOpts, interfaceId)
}

// Symbol is a free data retrieval call binding the contract method 0x95d89b41.
//
// Solidity: function symbol() pure returns(string)
func (_RegRelay *RegRelayCaller) Symbol(opts *bind.CallOpts) (string, error) {
	var out []interface{}
	err := _RegRelay.contract.Call(opts, &out, "symbol")

	if err != nil {
		return *new(string), err
	}

	out0 := *abi.ConvertType(out[0], new(string)).(*string)

	return out0, err

}

// Symbol is a free data retrieval call binding the contract method 0x95d89b41.
//
// Solidity: function symbol() pure returns(string)
func (_RegRelay *RegRelaySession) Symbol() (string, error) {
	return _RegRelay.Contract.Symbol(&_RegRelay.CallOpts)
}

// Symbol is a free data retrieval call binding the contract method 0x95d89b41.
//
// Solidity: function symbol() pure returns(string)
func (_RegRelay *RegRelayCallerSession) Symbol() (string, error) {
	return _RegRelay.Contract.Symbol(&_RegRelay.CallOpts)
}

// TokenURI is a free data retrieval call binding the contract method 0xc87b56dd.
//
// Solidity: function tokenURI(uint256 id) view returns(string)
func (_RegRelay *RegRelayCaller) TokenURI(opts *bind.CallOpts, id *big.Int) (string, error) {
	var out []interface{}
	err := _RegRelay.contract.Call(opts, &out, "tokenURI", id)

	if err != nil {
		return *new(string), err
	}

	out0 := *abi.ConvertType(out[0], new(string)).(*string)

	return out0, err

}

// TokenURI is a free data retrieval call binding the contract method 0xc87b56dd.
//
// Solidity: function tokenURI(uint256 id) view returns(string)
func (_RegRelay *RegRelaySession) TokenURI(id *big.Int) (string, error) {
	return _RegRelay.Contract.TokenURI(&_RegRelay.CallOpts, id)
}

// TokenURI is a free data retrieval call binding the contract method 0xc87b56dd.
//
// Solidity: function tokenURI(uint256 id) view returns(string)
func (_RegRelay *RegRelayCallerSession) TokenURI(id *big.Int) (string, error) {
	return _RegRelay.Contract.TokenURI(&_RegRelay.CallOpts, id)
}

// Approve is a paid mutator transaction binding the contract method 0x095ea7b3.
//
// Solidity: function approve(address account, uint256 id) payable returns()
func (_RegRelay *RegRelayTransactor) Approve(opts *bind.TransactOpts, account common.Address, id *big.Int) (*types.Transaction, error) {
	return _RegRelay.contract.Transact(opts, "approve", account, id)
}

// Approve is a paid mutator transaction binding the contract method 0x095ea7b3.
//
// Solidity: function approve(address account, uint256 id) payable returns()
func (_RegRelay *RegRelaySession) Approve(account common.Address, id *big.Int) (*types.Transaction, error) {
	return _RegRelay.Contract.Approve(&_RegRelay.TransactOpts, account, id)
}

// Approve is a paid mutator transaction binding the contract method 0x095ea7b3.
//
// Solidity: function approve(address account, uint256 id) payable returns()
func (_RegRelay *RegRelayTransactorSession) Approve(account common.Address, id *big.Int) (*types.Transaction, error) {
	return _RegRelay.Contract.Approve(&_RegRelay.TransactOpts, account, id)
}

// Mint is a paid mutator transaction binding the contract method 0xe67e402c.
//
// Solidity: function mint(uint256 newRelayId, address relay, string uri) returns()
func (_RegRelay *RegRelayTransactor) Mint(opts *bind.TransactOpts, newRelayId *big.Int, relay common.Address, uri string) (*types.Transaction, error) {
	return _RegRelay.contract.Transact(opts, "mint", newRelayId, relay, uri)
}

// Mint is a paid mutator transaction binding the contract method 0xe67e402c.
//
// Solidity: function mint(uint256 newRelayId, address relay, string uri) returns()
func (_RegRelay *RegRelaySession) Mint(newRelayId *big.Int, relay common.Address, uri string) (*types.Transaction, error) {
	return _RegRelay.Contract.Mint(&_RegRelay.TransactOpts, newRelayId, relay, uri)
}

// Mint is a paid mutator transaction binding the contract method 0xe67e402c.
//
// Solidity: function mint(uint256 newRelayId, address relay, string uri) returns()
func (_RegRelay *RegRelayTransactorSession) Mint(newRelayId *big.Int, relay common.Address, uri string) (*types.Transaction, error) {
	return _RegRelay.Contract.Mint(&_RegRelay.TransactOpts, newRelayId, relay, uri)
}

// SafeTransferFrom is a paid mutator transaction binding the contract method 0x42842e0e.
//
// Solidity: function safeTransferFrom(address from, address to, uint256 id) payable returns()
func (_RegRelay *RegRelayTransactor) SafeTransferFrom(opts *bind.TransactOpts, from common.Address, to common.Address, id *big.Int) (*types.Transaction, error) {
	return _RegRelay.contract.Transact(opts, "safeTransferFrom", from, to, id)
}

// SafeTransferFrom is a paid mutator transaction binding the contract method 0x42842e0e.
//
// Solidity: function safeTransferFrom(address from, address to, uint256 id) payable returns()
func (_RegRelay *RegRelaySession) SafeTransferFrom(from common.Address, to common.Address, id *big.Int) (*types.Transaction, error) {
	return _RegRelay.Contract.SafeTransferFrom(&_RegRelay.TransactOpts, from, to, id)
}

// SafeTransferFrom is a paid mutator transaction binding the contract method 0x42842e0e.
//
// Solidity: function safeTransferFrom(address from, address to, uint256 id) payable returns()
func (_RegRelay *RegRelayTransactorSession) SafeTransferFrom(from common.Address, to common.Address, id *big.Int) (*types.Transaction, error) {
	return _RegRelay.Contract.SafeTransferFrom(&_RegRelay.TransactOpts, from, to, id)
}

// SafeTransferFrom0 is a paid mutator transaction binding the contract method 0xb88d4fde.
//
// Solidity: function safeTransferFrom(address from, address to, uint256 id, bytes data) payable returns()
func (_RegRelay *RegRelayTransactor) SafeTransferFrom0(opts *bind.TransactOpts, from common.Address, to common.Address, id *big.Int, data []byte) (*types.Transaction, error) {
	return _RegRelay.contract.Transact(opts, "safeTransferFrom0", from, to, id, data)
}

// SafeTransferFrom0 is a paid mutator transaction binding the contract method 0xb88d4fde.
//
// Solidity: function safeTransferFrom(address from, address to, uint256 id, bytes data) payable returns()
func (_RegRelay *RegRelaySession) SafeTransferFrom0(from common.Address, to common.Address, id *big.Int, data []byte) (*types.Transaction, error) {
	return _RegRelay.Contract.SafeTransferFrom0(&_RegRelay.TransactOpts, from, to, id, data)
}

// SafeTransferFrom0 is a paid mutator transaction binding the contract method 0xb88d4fde.
//
// Solidity: function safeTransferFrom(address from, address to, uint256 id, bytes data) payable returns()
func (_RegRelay *RegRelayTransactorSession) SafeTransferFrom0(from common.Address, to common.Address, id *big.Int, data []byte) (*types.Transaction, error) {
	return _RegRelay.Contract.SafeTransferFrom0(&_RegRelay.TransactOpts, from, to, id, data)
}

// SetApprovalForAll is a paid mutator transaction binding the contract method 0xa22cb465.
//
// Solidity: function setApprovalForAll(address operator, bool isApproved) returns()
func (_RegRelay *RegRelayTransactor) SetApprovalForAll(opts *bind.TransactOpts, operator common.Address, isApproved bool) (*types.Transaction, error) {
	return _RegRelay.contract.Transact(opts, "setApprovalForAll", operator, isApproved)
}

// SetApprovalForAll is a paid mutator transaction binding the contract method 0xa22cb465.
//
// Solidity: function setApprovalForAll(address operator, bool isApproved) returns()
func (_RegRelay *RegRelaySession) SetApprovalForAll(operator common.Address, isApproved bool) (*types.Transaction, error) {
	return _RegRelay.Contract.SetApprovalForAll(&_RegRelay.TransactOpts, operator, isApproved)
}

// SetApprovalForAll is a paid mutator transaction binding the contract method 0xa22cb465.
//
// Solidity: function setApprovalForAll(address operator, bool isApproved) returns()
func (_RegRelay *RegRelayTransactorSession) SetApprovalForAll(operator common.Address, isApproved bool) (*types.Transaction, error) {
	return _RegRelay.Contract.SetApprovalForAll(&_RegRelay.TransactOpts, operator, isApproved)
}

// TransferFrom is a paid mutator transaction binding the contract method 0x23b872dd.
//
// Solidity: function transferFrom(address from, address to, uint256 id) payable returns()
func (_RegRelay *RegRelayTransactor) TransferFrom(opts *bind.TransactOpts, from common.Address, to common.Address, id *big.Int) (*types.Transaction, error) {
	return _RegRelay.contract.Transact(opts, "transferFrom", from, to, id)
}

// TransferFrom is a paid mutator transaction binding the contract method 0x23b872dd.
//
// Solidity: function transferFrom(address from, address to, uint256 id) payable returns()
func (_RegRelay *RegRelaySession) TransferFrom(from common.Address, to common.Address, id *big.Int) (*types.Transaction, error) {
	return _RegRelay.Contract.TransferFrom(&_RegRelay.TransactOpts, from, to, id)
}

// TransferFrom is a paid mutator transaction binding the contract method 0x23b872dd.
//
// Solidity: function transferFrom(address from, address to, uint256 id) payable returns()
func (_RegRelay *RegRelayTransactorSession) TransferFrom(from common.Address, to common.Address, id *big.Int) (*types.Transaction, error) {
	return _RegRelay.Contract.TransferFrom(&_RegRelay.TransactOpts, from, to, id)
}

// UpdateURI is a paid mutator transaction binding the contract method 0x31d41c69.
//
// Solidity: function updateURI(uint256 relayId, string uri) returns()
func (_RegRelay *RegRelayTransactor) UpdateURI(opts *bind.TransactOpts, relayId *big.Int, uri string) (*types.Transaction, error) {
	return _RegRelay.contract.Transact(opts, "updateURI", relayId, uri)
}

// UpdateURI is a paid mutator transaction binding the contract method 0x31d41c69.
//
// Solidity: function updateURI(uint256 relayId, string uri) returns()
func (_RegRelay *RegRelaySession) UpdateURI(relayId *big.Int, uri string) (*types.Transaction, error) {
	return _RegRelay.Contract.UpdateURI(&_RegRelay.TransactOpts, relayId, uri)
}

// UpdateURI is a paid mutator transaction binding the contract method 0x31d41c69.
//
// Solidity: function updateURI(uint256 relayId, string uri) returns()
func (_RegRelay *RegRelayTransactorSession) UpdateURI(relayId *big.Int, uri string) (*types.Transaction, error) {
	return _RegRelay.Contract.UpdateURI(&_RegRelay.TransactOpts, relayId, uri)
}

// RegRelayApprovalIterator is returned from FilterApproval and is used to iterate over the raw logs and unpacked data for Approval events raised by the RegRelay contract.
type RegRelayApprovalIterator struct {
	Event *RegRelayApproval // Event containing the contract specifics and raw log

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
func (it *RegRelayApprovalIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(RegRelayApproval)
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
		it.Event = new(RegRelayApproval)
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
func (it *RegRelayApprovalIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *RegRelayApprovalIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// RegRelayApproval represents a Approval event raised by the RegRelay contract.
type RegRelayApproval struct {
	Owner   common.Address
	Account common.Address
	Id      *big.Int
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterApproval is a free log retrieval operation binding the contract event 0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925.
//
// Solidity: event Approval(address indexed owner, address indexed account, uint256 indexed id)
func (_RegRelay *RegRelayFilterer) FilterApproval(opts *bind.FilterOpts, owner []common.Address, account []common.Address, id []*big.Int) (*RegRelayApprovalIterator, error) {

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

	logs, sub, err := _RegRelay.contract.FilterLogs(opts, "Approval", ownerRule, accountRule, idRule)
	if err != nil {
		return nil, err
	}
	return &RegRelayApprovalIterator{contract: _RegRelay.contract, event: "Approval", logs: logs, sub: sub}, nil
}

// WatchApproval is a free log subscription operation binding the contract event 0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925.
//
// Solidity: event Approval(address indexed owner, address indexed account, uint256 indexed id)
func (_RegRelay *RegRelayFilterer) WatchApproval(opts *bind.WatchOpts, sink chan<- *RegRelayApproval, owner []common.Address, account []common.Address, id []*big.Int) (event.Subscription, error) {

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

	logs, sub, err := _RegRelay.contract.WatchLogs(opts, "Approval", ownerRule, accountRule, idRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(RegRelayApproval)
				if err := _RegRelay.contract.UnpackLog(event, "Approval", log); err != nil {
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
func (_RegRelay *RegRelayFilterer) ParseApproval(log types.Log) (*RegRelayApproval, error) {
	event := new(RegRelayApproval)
	if err := _RegRelay.contract.UnpackLog(event, "Approval", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// RegRelayApprovalForAllIterator is returned from FilterApprovalForAll and is used to iterate over the raw logs and unpacked data for ApprovalForAll events raised by the RegRelay contract.
type RegRelayApprovalForAllIterator struct {
	Event *RegRelayApprovalForAll // Event containing the contract specifics and raw log

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
func (it *RegRelayApprovalForAllIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(RegRelayApprovalForAll)
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
		it.Event = new(RegRelayApprovalForAll)
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
func (it *RegRelayApprovalForAllIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *RegRelayApprovalForAllIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// RegRelayApprovalForAll represents a ApprovalForAll event raised by the RegRelay contract.
type RegRelayApprovalForAll struct {
	Owner      common.Address
	Operator   common.Address
	IsApproved bool
	Raw        types.Log // Blockchain specific contextual infos
}

// FilterApprovalForAll is a free log retrieval operation binding the contract event 0x17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31.
//
// Solidity: event ApprovalForAll(address indexed owner, address indexed operator, bool isApproved)
func (_RegRelay *RegRelayFilterer) FilterApprovalForAll(opts *bind.FilterOpts, owner []common.Address, operator []common.Address) (*RegRelayApprovalForAllIterator, error) {

	var ownerRule []interface{}
	for _, ownerItem := range owner {
		ownerRule = append(ownerRule, ownerItem)
	}
	var operatorRule []interface{}
	for _, operatorItem := range operator {
		operatorRule = append(operatorRule, operatorItem)
	}

	logs, sub, err := _RegRelay.contract.FilterLogs(opts, "ApprovalForAll", ownerRule, operatorRule)
	if err != nil {
		return nil, err
	}
	return &RegRelayApprovalForAllIterator{contract: _RegRelay.contract, event: "ApprovalForAll", logs: logs, sub: sub}, nil
}

// WatchApprovalForAll is a free log subscription operation binding the contract event 0x17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31.
//
// Solidity: event ApprovalForAll(address indexed owner, address indexed operator, bool isApproved)
func (_RegRelay *RegRelayFilterer) WatchApprovalForAll(opts *bind.WatchOpts, sink chan<- *RegRelayApprovalForAll, owner []common.Address, operator []common.Address) (event.Subscription, error) {

	var ownerRule []interface{}
	for _, ownerItem := range owner {
		ownerRule = append(ownerRule, ownerItem)
	}
	var operatorRule []interface{}
	for _, operatorItem := range operator {
		operatorRule = append(operatorRule, operatorItem)
	}

	logs, sub, err := _RegRelay.contract.WatchLogs(opts, "ApprovalForAll", ownerRule, operatorRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(RegRelayApprovalForAll)
				if err := _RegRelay.contract.UnpackLog(event, "ApprovalForAll", log); err != nil {
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
func (_RegRelay *RegRelayFilterer) ParseApprovalForAll(log types.Log) (*RegRelayApprovalForAll, error) {
	event := new(RegRelayApprovalForAll)
	if err := _RegRelay.contract.UnpackLog(event, "ApprovalForAll", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// RegRelayTransferIterator is returned from FilterTransfer and is used to iterate over the raw logs and unpacked data for Transfer events raised by the RegRelay contract.
type RegRelayTransferIterator struct {
	Event *RegRelayTransfer // Event containing the contract specifics and raw log

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
func (it *RegRelayTransferIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(RegRelayTransfer)
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
		it.Event = new(RegRelayTransfer)
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
func (it *RegRelayTransferIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *RegRelayTransferIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// RegRelayTransfer represents a Transfer event raised by the RegRelay contract.
type RegRelayTransfer struct {
	From common.Address
	To   common.Address
	Id   *big.Int
	Raw  types.Log // Blockchain specific contextual infos
}

// FilterTransfer is a free log retrieval operation binding the contract event 0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef.
//
// Solidity: event Transfer(address indexed from, address indexed to, uint256 indexed id)
func (_RegRelay *RegRelayFilterer) FilterTransfer(opts *bind.FilterOpts, from []common.Address, to []common.Address, id []*big.Int) (*RegRelayTransferIterator, error) {

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

	logs, sub, err := _RegRelay.contract.FilterLogs(opts, "Transfer", fromRule, toRule, idRule)
	if err != nil {
		return nil, err
	}
	return &RegRelayTransferIterator{contract: _RegRelay.contract, event: "Transfer", logs: logs, sub: sub}, nil
}

// WatchTransfer is a free log subscription operation binding the contract event 0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef.
//
// Solidity: event Transfer(address indexed from, address indexed to, uint256 indexed id)
func (_RegRelay *RegRelayFilterer) WatchTransfer(opts *bind.WatchOpts, sink chan<- *RegRelayTransfer, from []common.Address, to []common.Address, id []*big.Int) (event.Subscription, error) {

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

	logs, sub, err := _RegRelay.contract.WatchLogs(opts, "Transfer", fromRule, toRule, idRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(RegRelayTransfer)
				if err := _RegRelay.contract.UnpackLog(event, "Transfer", log); err != nil {
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
func (_RegRelay *RegRelayFilterer) ParseTransfer(log types.Log) (*RegRelayTransfer, error) {
	event := new(RegRelayTransfer)
	if err := _RegRelay.contract.UnpackLog(event, "Transfer", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}
