// SPDX-FileCopyrightText: 2024 Mass Labs
//
// SPDX-License-Identifier: MIT

// Generated from abi/PaymentFactory.json - git at dfca5599fdf0e533fb6aebeceb379122332fe8a3

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

// PaymentFactoryMetaData contains all meta data concerning the PaymentFactory contract.
var PaymentFactoryMetaData = &bind.MetaData{
	ABI: "[{\"type\":\"function\",\"name\":\"batch\",\"inputs\":[{\"name\":\"merchants\",\"type\":\"address[]\",\"internalType\":\"addresspayable[]\"},{\"name\":\"proofs\",\"type\":\"address[]\",\"internalType\":\"addresspayable[]\"},{\"name\":\"amounts\",\"type\":\"uint256[]\",\"internalType\":\"uint256[]\"},{\"name\":\"currencys\",\"type\":\"address[]\",\"internalType\":\"address[]\"},{\"name\":\"recieptHashes\",\"type\":\"bytes32[]\",\"internalType\":\"bytes32[]\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"getBytecode\",\"inputs\":[{\"name\":\"merchant\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"proof\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"amount\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"currency\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"getPaymentAddress\",\"inputs\":[{\"name\":\"merchant\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"proof\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"amount\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"currency\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"recieptHash\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"outputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"address\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"processPayment\",\"inputs\":[{\"name\":\"merchant\",\"type\":\"address\",\"internalType\":\"addresspayable\"},{\"name\":\"proof\",\"type\":\"address\",\"internalType\":\"addresspayable\"},{\"name\":\"amount\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"currency\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"recieptHash\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"}]",
}

// PaymentFactoryABI is the input ABI used to generate the binding from.
// Deprecated: Use PaymentFactoryMetaData.ABI instead.
var PaymentFactoryABI = PaymentFactoryMetaData.ABI

// PaymentFactory is an auto generated Go binding around an Ethereum contract.
type PaymentFactory struct {
	PaymentFactoryCaller     // Read-only binding to the contract
	PaymentFactoryTransactor // Write-only binding to the contract
	PaymentFactoryFilterer   // Log filterer for contract events
}

// PaymentFactoryCaller is an auto generated read-only Go binding around an Ethereum contract.
type PaymentFactoryCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// PaymentFactoryTransactor is an auto generated write-only Go binding around an Ethereum contract.
type PaymentFactoryTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// PaymentFactoryFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type PaymentFactoryFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// PaymentFactorySession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type PaymentFactorySession struct {
	Contract     *PaymentFactory   // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// PaymentFactoryCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type PaymentFactoryCallerSession struct {
	Contract *PaymentFactoryCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts         // Call options to use throughout this session
}

// PaymentFactoryTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type PaymentFactoryTransactorSession struct {
	Contract     *PaymentFactoryTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts         // Transaction auth options to use throughout this session
}

// PaymentFactoryRaw is an auto generated low-level Go binding around an Ethereum contract.
type PaymentFactoryRaw struct {
	Contract *PaymentFactory // Generic contract binding to access the raw methods on
}

// PaymentFactoryCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type PaymentFactoryCallerRaw struct {
	Contract *PaymentFactoryCaller // Generic read-only contract binding to access the raw methods on
}

// PaymentFactoryTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type PaymentFactoryTransactorRaw struct {
	Contract *PaymentFactoryTransactor // Generic write-only contract binding to access the raw methods on
}

// NewPaymentFactory creates a new instance of PaymentFactory, bound to a specific deployed contract.
func NewPaymentFactory(address common.Address, backend bind.ContractBackend) (*PaymentFactory, error) {
	contract, err := bindPaymentFactory(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &PaymentFactory{PaymentFactoryCaller: PaymentFactoryCaller{contract: contract}, PaymentFactoryTransactor: PaymentFactoryTransactor{contract: contract}, PaymentFactoryFilterer: PaymentFactoryFilterer{contract: contract}}, nil
}

// NewPaymentFactoryCaller creates a new read-only instance of PaymentFactory, bound to a specific deployed contract.
func NewPaymentFactoryCaller(address common.Address, caller bind.ContractCaller) (*PaymentFactoryCaller, error) {
	contract, err := bindPaymentFactory(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &PaymentFactoryCaller{contract: contract}, nil
}

// NewPaymentFactoryTransactor creates a new write-only instance of PaymentFactory, bound to a specific deployed contract.
func NewPaymentFactoryTransactor(address common.Address, transactor bind.ContractTransactor) (*PaymentFactoryTransactor, error) {
	contract, err := bindPaymentFactory(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &PaymentFactoryTransactor{contract: contract}, nil
}

// NewPaymentFactoryFilterer creates a new log filterer instance of PaymentFactory, bound to a specific deployed contract.
func NewPaymentFactoryFilterer(address common.Address, filterer bind.ContractFilterer) (*PaymentFactoryFilterer, error) {
	contract, err := bindPaymentFactory(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &PaymentFactoryFilterer{contract: contract}, nil
}

// bindPaymentFactory binds a generic wrapper to an already deployed contract.
func bindPaymentFactory(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := PaymentFactoryMetaData.GetAbi()
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, *parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_PaymentFactory *PaymentFactoryRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _PaymentFactory.Contract.PaymentFactoryCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_PaymentFactory *PaymentFactoryRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _PaymentFactory.Contract.PaymentFactoryTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_PaymentFactory *PaymentFactoryRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _PaymentFactory.Contract.PaymentFactoryTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_PaymentFactory *PaymentFactoryCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _PaymentFactory.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_PaymentFactory *PaymentFactoryTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _PaymentFactory.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_PaymentFactory *PaymentFactoryTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _PaymentFactory.Contract.contract.Transact(opts, method, params...)
}

// GetBytecode is a free data retrieval call binding the contract method 0x85a2a8b6.
//
// Solidity: function getBytecode(address merchant, address proof, uint256 amount, address currency) view returns(bytes)
func (_PaymentFactory *PaymentFactoryCaller) GetBytecode(opts *bind.CallOpts, merchant common.Address, proof common.Address, amount *big.Int, currency common.Address) ([]byte, error) {
	var out []interface{}
	err := _PaymentFactory.contract.Call(opts, &out, "getBytecode", merchant, proof, amount, currency)

	if err != nil {
		return *new([]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([]byte)).(*[]byte)

	return out0, err

}

// GetBytecode is a free data retrieval call binding the contract method 0x85a2a8b6.
//
// Solidity: function getBytecode(address merchant, address proof, uint256 amount, address currency) view returns(bytes)
func (_PaymentFactory *PaymentFactorySession) GetBytecode(merchant common.Address, proof common.Address, amount *big.Int, currency common.Address) ([]byte, error) {
	return _PaymentFactory.Contract.GetBytecode(&_PaymentFactory.CallOpts, merchant, proof, amount, currency)
}

// GetBytecode is a free data retrieval call binding the contract method 0x85a2a8b6.
//
// Solidity: function getBytecode(address merchant, address proof, uint256 amount, address currency) view returns(bytes)
func (_PaymentFactory *PaymentFactoryCallerSession) GetBytecode(merchant common.Address, proof common.Address, amount *big.Int, currency common.Address) ([]byte, error) {
	return _PaymentFactory.Contract.GetBytecode(&_PaymentFactory.CallOpts, merchant, proof, amount, currency)
}

// GetPaymentAddress is a free data retrieval call binding the contract method 0x262b325a.
//
// Solidity: function getPaymentAddress(address merchant, address proof, uint256 amount, address currency, bytes32 recieptHash) view returns(address)
func (_PaymentFactory *PaymentFactoryCaller) GetPaymentAddress(opts *bind.CallOpts, merchant common.Address, proof common.Address, amount *big.Int, currency common.Address, recieptHash [32]byte) (common.Address, error) {
	var out []interface{}
	err := _PaymentFactory.contract.Call(opts, &out, "getPaymentAddress", merchant, proof, amount, currency, recieptHash)

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// GetPaymentAddress is a free data retrieval call binding the contract method 0x262b325a.
//
// Solidity: function getPaymentAddress(address merchant, address proof, uint256 amount, address currency, bytes32 recieptHash) view returns(address)
func (_PaymentFactory *PaymentFactorySession) GetPaymentAddress(merchant common.Address, proof common.Address, amount *big.Int, currency common.Address, recieptHash [32]byte) (common.Address, error) {
	return _PaymentFactory.Contract.GetPaymentAddress(&_PaymentFactory.CallOpts, merchant, proof, amount, currency, recieptHash)
}

// GetPaymentAddress is a free data retrieval call binding the contract method 0x262b325a.
//
// Solidity: function getPaymentAddress(address merchant, address proof, uint256 amount, address currency, bytes32 recieptHash) view returns(address)
func (_PaymentFactory *PaymentFactoryCallerSession) GetPaymentAddress(merchant common.Address, proof common.Address, amount *big.Int, currency common.Address, recieptHash [32]byte) (common.Address, error) {
	return _PaymentFactory.Contract.GetPaymentAddress(&_PaymentFactory.CallOpts, merchant, proof, amount, currency, recieptHash)
}

// Batch is a paid mutator transaction binding the contract method 0x5bfa6eae.
//
// Solidity: function batch(address[] merchants, address[] proofs, uint256[] amounts, address[] currencys, bytes32[] recieptHashes) returns()
func (_PaymentFactory *PaymentFactoryTransactor) Batch(opts *bind.TransactOpts, merchants []common.Address, proofs []common.Address, amounts []*big.Int, currencys []common.Address, recieptHashes [][32]byte) (*types.Transaction, error) {
	return _PaymentFactory.contract.Transact(opts, "batch", merchants, proofs, amounts, currencys, recieptHashes)
}

// Batch is a paid mutator transaction binding the contract method 0x5bfa6eae.
//
// Solidity: function batch(address[] merchants, address[] proofs, uint256[] amounts, address[] currencys, bytes32[] recieptHashes) returns()
func (_PaymentFactory *PaymentFactorySession) Batch(merchants []common.Address, proofs []common.Address, amounts []*big.Int, currencys []common.Address, recieptHashes [][32]byte) (*types.Transaction, error) {
	return _PaymentFactory.Contract.Batch(&_PaymentFactory.TransactOpts, merchants, proofs, amounts, currencys, recieptHashes)
}

// Batch is a paid mutator transaction binding the contract method 0x5bfa6eae.
//
// Solidity: function batch(address[] merchants, address[] proofs, uint256[] amounts, address[] currencys, bytes32[] recieptHashes) returns()
func (_PaymentFactory *PaymentFactoryTransactorSession) Batch(merchants []common.Address, proofs []common.Address, amounts []*big.Int, currencys []common.Address, recieptHashes [][32]byte) (*types.Transaction, error) {
	return _PaymentFactory.Contract.Batch(&_PaymentFactory.TransactOpts, merchants, proofs, amounts, currencys, recieptHashes)
}

// ProcessPayment is a paid mutator transaction binding the contract method 0xf470433f.
//
// Solidity: function processPayment(address merchant, address proof, uint256 amount, address currency, bytes32 recieptHash) returns()
func (_PaymentFactory *PaymentFactoryTransactor) ProcessPayment(opts *bind.TransactOpts, merchant common.Address, proof common.Address, amount *big.Int, currency common.Address, recieptHash [32]byte) (*types.Transaction, error) {
	return _PaymentFactory.contract.Transact(opts, "processPayment", merchant, proof, amount, currency, recieptHash)
}

// ProcessPayment is a paid mutator transaction binding the contract method 0xf470433f.
//
// Solidity: function processPayment(address merchant, address proof, uint256 amount, address currency, bytes32 recieptHash) returns()
func (_PaymentFactory *PaymentFactorySession) ProcessPayment(merchant common.Address, proof common.Address, amount *big.Int, currency common.Address, recieptHash [32]byte) (*types.Transaction, error) {
	return _PaymentFactory.Contract.ProcessPayment(&_PaymentFactory.TransactOpts, merchant, proof, amount, currency, recieptHash)
}

// ProcessPayment is a paid mutator transaction binding the contract method 0xf470433f.
//
// Solidity: function processPayment(address merchant, address proof, uint256 amount, address currency, bytes32 recieptHash) returns()
func (_PaymentFactory *PaymentFactoryTransactorSession) ProcessPayment(merchant common.Address, proof common.Address, amount *big.Int, currency common.Address, recieptHash [32]byte) (*types.Transaction, error) {
	return _PaymentFactory.Contract.ProcessPayment(&_PaymentFactory.TransactOpts, merchant, proof, amount, currency, recieptHash)
}
