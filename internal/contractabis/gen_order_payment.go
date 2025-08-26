// SPDX-FileCopyrightText: 2025 Mass Labs
//
// SPDX-License-Identifier: GPL-3.0-or-later

// Generated from abi/OrderPayment.json - git at f63b17d8e1cd94dad81589183326739febe3f9c9

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

// OrderPaymentMetaData contains all meta data concerning the OrderPayment contract.
var OrderPaymentMetaData = &bind.MetaData{
	ABI: "[{\"type\":\"constructor\",\"inputs\":[{\"name\":\"_receivingAddress\",\"type\":\"address\",\"internalType\":\"addresspayable\"}],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"sweep\",\"inputs\":[{\"name\":\"token\",\"type\":\"address\",\"internalType\":\"contractERC20\"},{\"name\":\"hookCallData\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"sweepERC20\",\"inputs\":[{\"name\":\"token\",\"type\":\"address\",\"internalType\":\"contractERC20\"},{\"name\":\"hookCallData\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"sweepEth\",\"inputs\":[{\"name\":\"hookCallData\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"}]",
}

// OrderPaymentABI is the input ABI used to generate the binding from.
// Deprecated: Use OrderPaymentMetaData.ABI instead.
var OrderPaymentABI = OrderPaymentMetaData.ABI

// OrderPayment is an auto generated Go binding around an Ethereum contract.
type OrderPayment struct {
	OrderPaymentCaller     // Read-only binding to the contract
	OrderPaymentTransactor // Write-only binding to the contract
	OrderPaymentFilterer   // Log filterer for contract events
}

// OrderPaymentCaller is an auto generated read-only Go binding around an Ethereum contract.
type OrderPaymentCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// OrderPaymentTransactor is an auto generated write-only Go binding around an Ethereum contract.
type OrderPaymentTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// OrderPaymentFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type OrderPaymentFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// OrderPaymentSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type OrderPaymentSession struct {
	Contract     *OrderPayment     // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// OrderPaymentCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type OrderPaymentCallerSession struct {
	Contract *OrderPaymentCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts       // Call options to use throughout this session
}

// OrderPaymentTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type OrderPaymentTransactorSession struct {
	Contract     *OrderPaymentTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts       // Transaction auth options to use throughout this session
}

// OrderPaymentRaw is an auto generated low-level Go binding around an Ethereum contract.
type OrderPaymentRaw struct {
	Contract *OrderPayment // Generic contract binding to access the raw methods on
}

// OrderPaymentCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type OrderPaymentCallerRaw struct {
	Contract *OrderPaymentCaller // Generic read-only contract binding to access the raw methods on
}

// OrderPaymentTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type OrderPaymentTransactorRaw struct {
	Contract *OrderPaymentTransactor // Generic write-only contract binding to access the raw methods on
}

// NewOrderPayment creates a new instance of OrderPayment, bound to a specific deployed contract.
func NewOrderPayment(address common.Address, backend bind.ContractBackend) (*OrderPayment, error) {
	contract, err := bindOrderPayment(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &OrderPayment{OrderPaymentCaller: OrderPaymentCaller{contract: contract}, OrderPaymentTransactor: OrderPaymentTransactor{contract: contract}, OrderPaymentFilterer: OrderPaymentFilterer{contract: contract}}, nil
}

// NewOrderPaymentCaller creates a new read-only instance of OrderPayment, bound to a specific deployed contract.
func NewOrderPaymentCaller(address common.Address, caller bind.ContractCaller) (*OrderPaymentCaller, error) {
	contract, err := bindOrderPayment(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &OrderPaymentCaller{contract: contract}, nil
}

// NewOrderPaymentTransactor creates a new write-only instance of OrderPayment, bound to a specific deployed contract.
func NewOrderPaymentTransactor(address common.Address, transactor bind.ContractTransactor) (*OrderPaymentTransactor, error) {
	contract, err := bindOrderPayment(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &OrderPaymentTransactor{contract: contract}, nil
}

// NewOrderPaymentFilterer creates a new log filterer instance of OrderPayment, bound to a specific deployed contract.
func NewOrderPaymentFilterer(address common.Address, filterer bind.ContractFilterer) (*OrderPaymentFilterer, error) {
	contract, err := bindOrderPayment(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &OrderPaymentFilterer{contract: contract}, nil
}

// bindOrderPayment binds a generic wrapper to an already deployed contract.
func bindOrderPayment(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := OrderPaymentMetaData.GetAbi()
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, *parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_OrderPayment *OrderPaymentRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _OrderPayment.Contract.OrderPaymentCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_OrderPayment *OrderPaymentRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _OrderPayment.Contract.OrderPaymentTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_OrderPayment *OrderPaymentRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _OrderPayment.Contract.OrderPaymentTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_OrderPayment *OrderPaymentCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _OrderPayment.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_OrderPayment *OrderPaymentTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _OrderPayment.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_OrderPayment *OrderPaymentTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _OrderPayment.Contract.contract.Transact(opts, method, params...)
}

// Sweep is a paid mutator transaction binding the contract method 0xd96b6eb2.
//
// Solidity: function sweep(address token, bytes hookCallData) returns()
func (_OrderPayment *OrderPaymentTransactor) Sweep(opts *bind.TransactOpts, token common.Address, hookCallData []byte) (*types.Transaction, error) {
	return _OrderPayment.contract.Transact(opts, "sweep", token, hookCallData)
}

// Sweep is a paid mutator transaction binding the contract method 0xd96b6eb2.
//
// Solidity: function sweep(address token, bytes hookCallData) returns()
func (_OrderPayment *OrderPaymentSession) Sweep(token common.Address, hookCallData []byte) (*types.Transaction, error) {
	return _OrderPayment.Contract.Sweep(&_OrderPayment.TransactOpts, token, hookCallData)
}

// Sweep is a paid mutator transaction binding the contract method 0xd96b6eb2.
//
// Solidity: function sweep(address token, bytes hookCallData) returns()
func (_OrderPayment *OrderPaymentTransactorSession) Sweep(token common.Address, hookCallData []byte) (*types.Transaction, error) {
	return _OrderPayment.Contract.Sweep(&_OrderPayment.TransactOpts, token, hookCallData)
}

// SweepERC20 is a paid mutator transaction binding the contract method 0xd00bd6e6.
//
// Solidity: function sweepERC20(address token, bytes hookCallData) returns()
func (_OrderPayment *OrderPaymentTransactor) SweepERC20(opts *bind.TransactOpts, token common.Address, hookCallData []byte) (*types.Transaction, error) {
	return _OrderPayment.contract.Transact(opts, "sweepERC20", token, hookCallData)
}

// SweepERC20 is a paid mutator transaction binding the contract method 0xd00bd6e6.
//
// Solidity: function sweepERC20(address token, bytes hookCallData) returns()
func (_OrderPayment *OrderPaymentSession) SweepERC20(token common.Address, hookCallData []byte) (*types.Transaction, error) {
	return _OrderPayment.Contract.SweepERC20(&_OrderPayment.TransactOpts, token, hookCallData)
}

// SweepERC20 is a paid mutator transaction binding the contract method 0xd00bd6e6.
//
// Solidity: function sweepERC20(address token, bytes hookCallData) returns()
func (_OrderPayment *OrderPaymentTransactorSession) SweepERC20(token common.Address, hookCallData []byte) (*types.Transaction, error) {
	return _OrderPayment.Contract.SweepERC20(&_OrderPayment.TransactOpts, token, hookCallData)
}

// SweepEth is a paid mutator transaction binding the contract method 0x5216bf4d.
//
// Solidity: function sweepEth(bytes hookCallData) returns()
func (_OrderPayment *OrderPaymentTransactor) SweepEth(opts *bind.TransactOpts, hookCallData []byte) (*types.Transaction, error) {
	return _OrderPayment.contract.Transact(opts, "sweepEth", hookCallData)
}

// SweepEth is a paid mutator transaction binding the contract method 0x5216bf4d.
//
// Solidity: function sweepEth(bytes hookCallData) returns()
func (_OrderPayment *OrderPaymentSession) SweepEth(hookCallData []byte) (*types.Transaction, error) {
	return _OrderPayment.Contract.SweepEth(&_OrderPayment.TransactOpts, hookCallData)
}

// SweepEth is a paid mutator transaction binding the contract method 0x5216bf4d.
//
// Solidity: function sweepEth(bytes hookCallData) returns()
func (_OrderPayment *OrderPaymentTransactorSession) SweepEth(hookCallData []byte) (*types.Transaction, error) {
	return _OrderPayment.Contract.SweepEth(&_OrderPayment.TransactOpts, hookCallData)
}
