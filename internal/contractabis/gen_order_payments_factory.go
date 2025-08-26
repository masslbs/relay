// SPDX-FileCopyrightText: 2025 Mass Labs
//
// SPDX-License-Identifier: GPL-3.0-or-later

// Generated from abi/OrderPaymentsFactory.json - git at f63b17d8e1cd94dad81589183326739febe3f9c9

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

// OrderPaymentBinding is an auto generated low-level Go binding around an user-defined struct.
type OrderPaymentBinding struct {
	ChainId          *big.Int
	ShopId           *big.Int
	OrderId          *big.Int
	ReceivingAddress common.Address
}

// OrderPaymentsFactoryMetaData contains all meta data concerning the OrderPaymentsFactory contract.
var OrderPaymentsFactoryMetaData = &bind.MetaData{
	ABI: "[{\"type\":\"function\",\"name\":\"deployOrderPayment\",\"inputs\":[{\"name\":\"binding\",\"type\":\"tuple\",\"internalType\":\"structOrderPaymentBinding\",\"components\":[{\"name\":\"chainId\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"shopId\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"orderId\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"receivingAddress\",\"type\":\"address\",\"internalType\":\"addresspayable\"}]}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"getBytecodeHash\",\"inputs\":[{\"name\":\"receivingAddress\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"getOrderPaymentAddress\",\"inputs\":[{\"name\":\"binding\",\"type\":\"tuple\",\"internalType\":\"structOrderPaymentBinding\",\"components\":[{\"name\":\"chainId\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"shopId\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"orderId\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"receivingAddress\",\"type\":\"address\",\"internalType\":\"addresspayable\"}]}],\"outputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"address\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"getSalt\",\"inputs\":[{\"name\":\"binding\",\"type\":\"tuple\",\"internalType\":\"structOrderPaymentBinding\",\"components\":[{\"name\":\"chainId\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"shopId\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"orderId\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"receivingAddress\",\"type\":\"address\",\"internalType\":\"addresspayable\"}]}],\"outputs\":[{\"name\":\"\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"stateMutability\":\"pure\"}]",
}

// OrderPaymentsFactoryABI is the input ABI used to generate the binding from.
// Deprecated: Use OrderPaymentsFactoryMetaData.ABI instead.
var OrderPaymentsFactoryABI = OrderPaymentsFactoryMetaData.ABI

// OrderPaymentsFactory is an auto generated Go binding around an Ethereum contract.
type OrderPaymentsFactory struct {
	OrderPaymentsFactoryCaller     // Read-only binding to the contract
	OrderPaymentsFactoryTransactor // Write-only binding to the contract
	OrderPaymentsFactoryFilterer   // Log filterer for contract events
}

// OrderPaymentsFactoryCaller is an auto generated read-only Go binding around an Ethereum contract.
type OrderPaymentsFactoryCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// OrderPaymentsFactoryTransactor is an auto generated write-only Go binding around an Ethereum contract.
type OrderPaymentsFactoryTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// OrderPaymentsFactoryFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type OrderPaymentsFactoryFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// OrderPaymentsFactorySession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type OrderPaymentsFactorySession struct {
	Contract     *OrderPaymentsFactory // Generic contract binding to set the session for
	CallOpts     bind.CallOpts         // Call options to use throughout this session
	TransactOpts bind.TransactOpts     // Transaction auth options to use throughout this session
}

// OrderPaymentsFactoryCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type OrderPaymentsFactoryCallerSession struct {
	Contract *OrderPaymentsFactoryCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts               // Call options to use throughout this session
}

// OrderPaymentsFactoryTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type OrderPaymentsFactoryTransactorSession struct {
	Contract     *OrderPaymentsFactoryTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts               // Transaction auth options to use throughout this session
}

// OrderPaymentsFactoryRaw is an auto generated low-level Go binding around an Ethereum contract.
type OrderPaymentsFactoryRaw struct {
	Contract *OrderPaymentsFactory // Generic contract binding to access the raw methods on
}

// OrderPaymentsFactoryCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type OrderPaymentsFactoryCallerRaw struct {
	Contract *OrderPaymentsFactoryCaller // Generic read-only contract binding to access the raw methods on
}

// OrderPaymentsFactoryTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type OrderPaymentsFactoryTransactorRaw struct {
	Contract *OrderPaymentsFactoryTransactor // Generic write-only contract binding to access the raw methods on
}

// NewOrderPaymentsFactory creates a new instance of OrderPaymentsFactory, bound to a specific deployed contract.
func NewOrderPaymentsFactory(address common.Address, backend bind.ContractBackend) (*OrderPaymentsFactory, error) {
	contract, err := bindOrderPaymentsFactory(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &OrderPaymentsFactory{OrderPaymentsFactoryCaller: OrderPaymentsFactoryCaller{contract: contract}, OrderPaymentsFactoryTransactor: OrderPaymentsFactoryTransactor{contract: contract}, OrderPaymentsFactoryFilterer: OrderPaymentsFactoryFilterer{contract: contract}}, nil
}

// NewOrderPaymentsFactoryCaller creates a new read-only instance of OrderPaymentsFactory, bound to a specific deployed contract.
func NewOrderPaymentsFactoryCaller(address common.Address, caller bind.ContractCaller) (*OrderPaymentsFactoryCaller, error) {
	contract, err := bindOrderPaymentsFactory(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &OrderPaymentsFactoryCaller{contract: contract}, nil
}

// NewOrderPaymentsFactoryTransactor creates a new write-only instance of OrderPaymentsFactory, bound to a specific deployed contract.
func NewOrderPaymentsFactoryTransactor(address common.Address, transactor bind.ContractTransactor) (*OrderPaymentsFactoryTransactor, error) {
	contract, err := bindOrderPaymentsFactory(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &OrderPaymentsFactoryTransactor{contract: contract}, nil
}

// NewOrderPaymentsFactoryFilterer creates a new log filterer instance of OrderPaymentsFactory, bound to a specific deployed contract.
func NewOrderPaymentsFactoryFilterer(address common.Address, filterer bind.ContractFilterer) (*OrderPaymentsFactoryFilterer, error) {
	contract, err := bindOrderPaymentsFactory(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &OrderPaymentsFactoryFilterer{contract: contract}, nil
}

// bindOrderPaymentsFactory binds a generic wrapper to an already deployed contract.
func bindOrderPaymentsFactory(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := OrderPaymentsFactoryMetaData.GetAbi()
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, *parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_OrderPaymentsFactory *OrderPaymentsFactoryRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _OrderPaymentsFactory.Contract.OrderPaymentsFactoryCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_OrderPaymentsFactory *OrderPaymentsFactoryRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _OrderPaymentsFactory.Contract.OrderPaymentsFactoryTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_OrderPaymentsFactory *OrderPaymentsFactoryRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _OrderPaymentsFactory.Contract.OrderPaymentsFactoryTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_OrderPaymentsFactory *OrderPaymentsFactoryCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _OrderPaymentsFactory.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_OrderPaymentsFactory *OrderPaymentsFactoryTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _OrderPaymentsFactory.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_OrderPaymentsFactory *OrderPaymentsFactoryTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _OrderPaymentsFactory.Contract.contract.Transact(opts, method, params...)
}

// GetBytecodeHash is a free data retrieval call binding the contract method 0x0d4da8f0.
//
// Solidity: function getBytecodeHash(address receivingAddress) pure returns(bytes32)
func (_OrderPaymentsFactory *OrderPaymentsFactoryCaller) GetBytecodeHash(opts *bind.CallOpts, receivingAddress common.Address) ([32]byte, error) {
	var out []interface{}
	err := _OrderPaymentsFactory.contract.Call(opts, &out, "getBytecodeHash", receivingAddress)

	if err != nil {
		return *new([32]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([32]byte)).(*[32]byte)

	return out0, err

}

// GetBytecodeHash is a free data retrieval call binding the contract method 0x0d4da8f0.
//
// Solidity: function getBytecodeHash(address receivingAddress) pure returns(bytes32)
func (_OrderPaymentsFactory *OrderPaymentsFactorySession) GetBytecodeHash(receivingAddress common.Address) ([32]byte, error) {
	return _OrderPaymentsFactory.Contract.GetBytecodeHash(&_OrderPaymentsFactory.CallOpts, receivingAddress)
}

// GetBytecodeHash is a free data retrieval call binding the contract method 0x0d4da8f0.
//
// Solidity: function getBytecodeHash(address receivingAddress) pure returns(bytes32)
func (_OrderPaymentsFactory *OrderPaymentsFactoryCallerSession) GetBytecodeHash(receivingAddress common.Address) ([32]byte, error) {
	return _OrderPaymentsFactory.Contract.GetBytecodeHash(&_OrderPaymentsFactory.CallOpts, receivingAddress)
}

// GetOrderPaymentAddress is a free data retrieval call binding the contract method 0x64eb68b4.
//
// Solidity: function getOrderPaymentAddress((uint256,uint256,uint256,address) binding) view returns(address)
func (_OrderPaymentsFactory *OrderPaymentsFactoryCaller) GetOrderPaymentAddress(opts *bind.CallOpts, binding OrderPaymentBinding) (common.Address, error) {
	var out []interface{}
	err := _OrderPaymentsFactory.contract.Call(opts, &out, "getOrderPaymentAddress", binding)

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// GetOrderPaymentAddress is a free data retrieval call binding the contract method 0x64eb68b4.
//
// Solidity: function getOrderPaymentAddress((uint256,uint256,uint256,address) binding) view returns(address)
func (_OrderPaymentsFactory *OrderPaymentsFactorySession) GetOrderPaymentAddress(binding OrderPaymentBinding) (common.Address, error) {
	return _OrderPaymentsFactory.Contract.GetOrderPaymentAddress(&_OrderPaymentsFactory.CallOpts, binding)
}

// GetOrderPaymentAddress is a free data retrieval call binding the contract method 0x64eb68b4.
//
// Solidity: function getOrderPaymentAddress((uint256,uint256,uint256,address) binding) view returns(address)
func (_OrderPaymentsFactory *OrderPaymentsFactoryCallerSession) GetOrderPaymentAddress(binding OrderPaymentBinding) (common.Address, error) {
	return _OrderPaymentsFactory.Contract.GetOrderPaymentAddress(&_OrderPaymentsFactory.CallOpts, binding)
}

// GetSalt is a free data retrieval call binding the contract method 0x512edd62.
//
// Solidity: function getSalt((uint256,uint256,uint256,address) binding) pure returns(bytes32)
func (_OrderPaymentsFactory *OrderPaymentsFactoryCaller) GetSalt(opts *bind.CallOpts, binding OrderPaymentBinding) ([32]byte, error) {
	var out []interface{}
	err := _OrderPaymentsFactory.contract.Call(opts, &out, "getSalt", binding)

	if err != nil {
		return *new([32]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([32]byte)).(*[32]byte)

	return out0, err

}

// GetSalt is a free data retrieval call binding the contract method 0x512edd62.
//
// Solidity: function getSalt((uint256,uint256,uint256,address) binding) pure returns(bytes32)
func (_OrderPaymentsFactory *OrderPaymentsFactorySession) GetSalt(binding OrderPaymentBinding) ([32]byte, error) {
	return _OrderPaymentsFactory.Contract.GetSalt(&_OrderPaymentsFactory.CallOpts, binding)
}

// GetSalt is a free data retrieval call binding the contract method 0x512edd62.
//
// Solidity: function getSalt((uint256,uint256,uint256,address) binding) pure returns(bytes32)
func (_OrderPaymentsFactory *OrderPaymentsFactoryCallerSession) GetSalt(binding OrderPaymentBinding) ([32]byte, error) {
	return _OrderPaymentsFactory.Contract.GetSalt(&_OrderPaymentsFactory.CallOpts, binding)
}

// DeployOrderPayment is a paid mutator transaction binding the contract method 0xd3b4af0b.
//
// Solidity: function deployOrderPayment((uint256,uint256,uint256,address) binding) returns()
func (_OrderPaymentsFactory *OrderPaymentsFactoryTransactor) DeployOrderPayment(opts *bind.TransactOpts, binding OrderPaymentBinding) (*types.Transaction, error) {
	return _OrderPaymentsFactory.contract.Transact(opts, "deployOrderPayment", binding)
}

// DeployOrderPayment is a paid mutator transaction binding the contract method 0xd3b4af0b.
//
// Solidity: function deployOrderPayment((uint256,uint256,uint256,address) binding) returns()
func (_OrderPaymentsFactory *OrderPaymentsFactorySession) DeployOrderPayment(binding OrderPaymentBinding) (*types.Transaction, error) {
	return _OrderPaymentsFactory.Contract.DeployOrderPayment(&_OrderPaymentsFactory.TransactOpts, binding)
}

// DeployOrderPayment is a paid mutator transaction binding the contract method 0xd3b4af0b.
//
// Solidity: function deployOrderPayment((uint256,uint256,uint256,address) binding) returns()
func (_OrderPaymentsFactory *OrderPaymentsFactoryTransactorSession) DeployOrderPayment(binding OrderPaymentBinding) (*types.Transaction, error) {
	return _OrderPaymentsFactory.Contract.DeployOrderPayment(&_OrderPaymentsFactory.TransactOpts, binding)
}
