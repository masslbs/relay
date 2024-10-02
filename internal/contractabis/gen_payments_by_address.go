// SPDX-FileCopyrightText: 2024 Mass Labs
//
// SPDX-License-Identifier: GPL-3.0-or-later

// Generated from abi/PaymentsByAddress.json - git at 127cb6df298a3bfe093b75e80e46a3baaa1a8db1

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

// PaymentRequest is an auto generated low-level Go binding around an user-defined struct.
type PaymentRequest struct {
	ChainId           *big.Int
	Ttl               *big.Int
	Order             [32]byte
	Currency          common.Address
	Amount            *big.Int
	PayeeAddress      common.Address
	IsPaymentEndpoint bool
	ShopId            *big.Int
	ShopSignature     []byte
}

// PaymentsByAddressMetaData contains all meta data concerning the PaymentsByAddress contract.
var PaymentsByAddressMetaData = &bind.MetaData{
	ABI: "[{\"type\":\"constructor\",\"inputs\":[{\"name\":\"permit2\",\"type\":\"address\",\"internalType\":\"contractIPermit2\"}],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"batch\",\"inputs\":[{\"name\":\"payments\",\"type\":\"tuple[]\",\"internalType\":\"structPaymentRequest[]\",\"components\":[{\"name\":\"chainId\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"ttl\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"order\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"currency\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"amount\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"payeeAddress\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"isPaymentEndpoint\",\"type\":\"bool\",\"internalType\":\"bool\"},{\"name\":\"shopId\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"shopSignature\",\"type\":\"bytes\",\"internalType\":\"bytes\"}]},{\"name\":\"refunds\",\"type\":\"address[]\",\"internalType\":\"addresspayable[]\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"getBytecode\",\"inputs\":[{\"name\":\"payment\",\"type\":\"tuple\",\"internalType\":\"structPaymentRequest\",\"components\":[{\"name\":\"chainId\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"ttl\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"order\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"currency\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"amount\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"payeeAddress\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"isPaymentEndpoint\",\"type\":\"bool\",\"internalType\":\"bool\"},{\"name\":\"shopId\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"shopSignature\",\"type\":\"bytes\",\"internalType\":\"bytes\"}]},{\"name\":\"refund\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"getPaymentAddress\",\"inputs\":[{\"name\":\"payment\",\"type\":\"tuple\",\"internalType\":\"structPaymentRequest\",\"components\":[{\"name\":\"chainId\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"ttl\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"order\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"currency\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"amount\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"payeeAddress\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"isPaymentEndpoint\",\"type\":\"bool\",\"internalType\":\"bool\"},{\"name\":\"shopId\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"shopSignature\",\"type\":\"bytes\",\"internalType\":\"bytes\"}]},{\"name\":\"refund\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"address\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"getPaymentId\",\"inputs\":[{\"name\":\"payment\",\"type\":\"tuple\",\"internalType\":\"structPaymentRequest\",\"components\":[{\"name\":\"chainId\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"ttl\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"order\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"currency\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"amount\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"payeeAddress\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"isPaymentEndpoint\",\"type\":\"bool\",\"internalType\":\"bool\"},{\"name\":\"shopId\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"shopSignature\",\"type\":\"bytes\",\"internalType\":\"bytes\"}]}],\"outputs\":[{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"hasPaymentBeenMade\",\"inputs\":[{\"name\":\"from\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"payment\",\"type\":\"tuple\",\"internalType\":\"structPaymentRequest\",\"components\":[{\"name\":\"chainId\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"ttl\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"order\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"currency\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"amount\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"payeeAddress\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"isPaymentEndpoint\",\"type\":\"bool\",\"internalType\":\"bool\"},{\"name\":\"shopId\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"shopSignature\",\"type\":\"bytes\",\"internalType\":\"bytes\"}]}],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"multiPay\",\"inputs\":[{\"name\":\"payments\",\"type\":\"tuple[]\",\"internalType\":\"structPaymentRequest[]\",\"components\":[{\"name\":\"chainId\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"ttl\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"order\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"currency\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"amount\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"payeeAddress\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"isPaymentEndpoint\",\"type\":\"bool\",\"internalType\":\"bool\"},{\"name\":\"shopId\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"shopSignature\",\"type\":\"bytes\",\"internalType\":\"bytes\"}]},{\"name\":\"permit2Sigs\",\"type\":\"bytes[]\",\"internalType\":\"bytes[]\"}],\"outputs\":[],\"stateMutability\":\"payable\"},{\"type\":\"function\",\"name\":\"pay\",\"inputs\":[{\"name\":\"payment\",\"type\":\"tuple\",\"internalType\":\"structPaymentRequest\",\"components\":[{\"name\":\"chainId\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"ttl\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"order\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"currency\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"amount\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"payeeAddress\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"isPaymentEndpoint\",\"type\":\"bool\",\"internalType\":\"bool\"},{\"name\":\"shopId\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"shopSignature\",\"type\":\"bytes\",\"internalType\":\"bytes\"}]}],\"outputs\":[],\"stateMutability\":\"payable\"},{\"type\":\"function\",\"name\":\"payNative\",\"inputs\":[{\"name\":\"payment\",\"type\":\"tuple\",\"internalType\":\"structPaymentRequest\",\"components\":[{\"name\":\"chainId\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"ttl\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"order\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"currency\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"amount\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"payeeAddress\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"isPaymentEndpoint\",\"type\":\"bool\",\"internalType\":\"bool\"},{\"name\":\"shopId\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"shopSignature\",\"type\":\"bytes\",\"internalType\":\"bytes\"}]}],\"outputs\":[],\"stateMutability\":\"payable\"},{\"type\":\"function\",\"name\":\"payToken\",\"inputs\":[{\"name\":\"payment\",\"type\":\"tuple\",\"internalType\":\"structPaymentRequest\",\"components\":[{\"name\":\"chainId\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"ttl\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"order\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"currency\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"amount\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"payeeAddress\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"isPaymentEndpoint\",\"type\":\"bool\",\"internalType\":\"bool\"},{\"name\":\"shopId\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"shopSignature\",\"type\":\"bytes\",\"internalType\":\"bytes\"}]},{\"name\":\"permit2signature\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"payTokenPreApproved\",\"inputs\":[{\"name\":\"payment\",\"type\":\"tuple\",\"internalType\":\"structPaymentRequest\",\"components\":[{\"name\":\"chainId\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"ttl\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"order\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"currency\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"amount\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"payeeAddress\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"isPaymentEndpoint\",\"type\":\"bool\",\"internalType\":\"bool\"},{\"name\":\"shopId\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"shopSignature\",\"type\":\"bytes\",\"internalType\":\"bytes\"}]}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"processPayment\",\"inputs\":[{\"name\":\"payment\",\"type\":\"tuple\",\"internalType\":\"structPaymentRequest\",\"components\":[{\"name\":\"chainId\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"ttl\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"order\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"currency\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"amount\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"payeeAddress\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"isPaymentEndpoint\",\"type\":\"bool\",\"internalType\":\"bool\"},{\"name\":\"shopId\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"shopSignature\",\"type\":\"bytes\",\"internalType\":\"bytes\"}]},{\"name\":\"refund\",\"type\":\"address\",\"internalType\":\"addresspayable\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"revertPayment\",\"inputs\":[{\"name\":\"from\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"payment\",\"type\":\"tuple\",\"internalType\":\"structPaymentRequest\",\"components\":[{\"name\":\"chainId\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"ttl\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"order\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"currency\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"amount\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"payeeAddress\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"isPaymentEndpoint\",\"type\":\"bool\",\"internalType\":\"bool\"},{\"name\":\"shopId\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"shopSignature\",\"type\":\"bytes\",\"internalType\":\"bytes\"}]}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"event\",\"name\":\"PaymentMade\",\"inputs\":[{\"name\":\"paymentId\",\"type\":\"uint256\",\"indexed\":true,\"internalType\":\"uint256\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"SweepFailed\",\"inputs\":[{\"name\":\"payment\",\"type\":\"tuple\",\"indexed\":false,\"internalType\":\"structPaymentRequest\",\"components\":[{\"name\":\"chainId\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"ttl\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"order\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"currency\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"amount\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"payeeAddress\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"isPaymentEndpoint\",\"type\":\"bool\",\"internalType\":\"bool\"},{\"name\":\"shopId\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"shopSignature\",\"type\":\"bytes\",\"internalType\":\"bytes\"}]}],\"anonymous\":false},{\"type\":\"error\",\"name\":\"InvalidPaymentAmount\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"InvalidPaymentToken\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"NotPayee\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"PayeeRefusedPayment\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"PaymentAlreadyMade\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"PaymentExpired\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"PaymentNotMade\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"WrongChain\",\"inputs\":[]}]",
}

// PaymentsByAddressABI is the input ABI used to generate the binding from.
// Deprecated: Use PaymentsByAddressMetaData.ABI instead.
var PaymentsByAddressABI = PaymentsByAddressMetaData.ABI

// PaymentsByAddress is an auto generated Go binding around an Ethereum contract.
type PaymentsByAddress struct {
	PaymentsByAddressCaller     // Read-only binding to the contract
	PaymentsByAddressTransactor // Write-only binding to the contract
	PaymentsByAddressFilterer   // Log filterer for contract events
}

// PaymentsByAddressCaller is an auto generated read-only Go binding around an Ethereum contract.
type PaymentsByAddressCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// PaymentsByAddressTransactor is an auto generated write-only Go binding around an Ethereum contract.
type PaymentsByAddressTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// PaymentsByAddressFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type PaymentsByAddressFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// PaymentsByAddressSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type PaymentsByAddressSession struct {
	Contract     *PaymentsByAddress // Generic contract binding to set the session for
	CallOpts     bind.CallOpts      // Call options to use throughout this session
	TransactOpts bind.TransactOpts  // Transaction auth options to use throughout this session
}

// PaymentsByAddressCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type PaymentsByAddressCallerSession struct {
	Contract *PaymentsByAddressCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts            // Call options to use throughout this session
}

// PaymentsByAddressTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type PaymentsByAddressTransactorSession struct {
	Contract     *PaymentsByAddressTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts            // Transaction auth options to use throughout this session
}

// PaymentsByAddressRaw is an auto generated low-level Go binding around an Ethereum contract.
type PaymentsByAddressRaw struct {
	Contract *PaymentsByAddress // Generic contract binding to access the raw methods on
}

// PaymentsByAddressCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type PaymentsByAddressCallerRaw struct {
	Contract *PaymentsByAddressCaller // Generic read-only contract binding to access the raw methods on
}

// PaymentsByAddressTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type PaymentsByAddressTransactorRaw struct {
	Contract *PaymentsByAddressTransactor // Generic write-only contract binding to access the raw methods on
}

// NewPaymentsByAddress creates a new instance of PaymentsByAddress, bound to a specific deployed contract.
func NewPaymentsByAddress(address common.Address, backend bind.ContractBackend) (*PaymentsByAddress, error) {
	contract, err := bindPaymentsByAddress(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &PaymentsByAddress{PaymentsByAddressCaller: PaymentsByAddressCaller{contract: contract}, PaymentsByAddressTransactor: PaymentsByAddressTransactor{contract: contract}, PaymentsByAddressFilterer: PaymentsByAddressFilterer{contract: contract}}, nil
}

// NewPaymentsByAddressCaller creates a new read-only instance of PaymentsByAddress, bound to a specific deployed contract.
func NewPaymentsByAddressCaller(address common.Address, caller bind.ContractCaller) (*PaymentsByAddressCaller, error) {
	contract, err := bindPaymentsByAddress(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &PaymentsByAddressCaller{contract: contract}, nil
}

// NewPaymentsByAddressTransactor creates a new write-only instance of PaymentsByAddress, bound to a specific deployed contract.
func NewPaymentsByAddressTransactor(address common.Address, transactor bind.ContractTransactor) (*PaymentsByAddressTransactor, error) {
	contract, err := bindPaymentsByAddress(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &PaymentsByAddressTransactor{contract: contract}, nil
}

// NewPaymentsByAddressFilterer creates a new log filterer instance of PaymentsByAddress, bound to a specific deployed contract.
func NewPaymentsByAddressFilterer(address common.Address, filterer bind.ContractFilterer) (*PaymentsByAddressFilterer, error) {
	contract, err := bindPaymentsByAddress(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &PaymentsByAddressFilterer{contract: contract}, nil
}

// bindPaymentsByAddress binds a generic wrapper to an already deployed contract.
func bindPaymentsByAddress(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := PaymentsByAddressMetaData.GetAbi()
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, *parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_PaymentsByAddress *PaymentsByAddressRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _PaymentsByAddress.Contract.PaymentsByAddressCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_PaymentsByAddress *PaymentsByAddressRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _PaymentsByAddress.Contract.PaymentsByAddressTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_PaymentsByAddress *PaymentsByAddressRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _PaymentsByAddress.Contract.PaymentsByAddressTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_PaymentsByAddress *PaymentsByAddressCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _PaymentsByAddress.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_PaymentsByAddress *PaymentsByAddressTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _PaymentsByAddress.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_PaymentsByAddress *PaymentsByAddressTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _PaymentsByAddress.Contract.contract.Transact(opts, method, params...)
}

// GetBytecode is a free data retrieval call binding the contract method 0x10bc0131.
//
// Solidity: function getBytecode((uint256,uint256,bytes32,address,uint256,address,bool,uint256,bytes) payment, address refund) view returns(bytes)
func (_PaymentsByAddress *PaymentsByAddressCaller) GetBytecode(opts *bind.CallOpts, payment PaymentRequest, refund common.Address) ([]byte, error) {
	var out []interface{}
	err := _PaymentsByAddress.contract.Call(opts, &out, "getBytecode", payment, refund)

	if err != nil {
		return *new([]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([]byte)).(*[]byte)

	return out0, err

}

// GetBytecode is a free data retrieval call binding the contract method 0x10bc0131.
//
// Solidity: function getBytecode((uint256,uint256,bytes32,address,uint256,address,bool,uint256,bytes) payment, address refund) view returns(bytes)
func (_PaymentsByAddress *PaymentsByAddressSession) GetBytecode(payment PaymentRequest, refund common.Address) ([]byte, error) {
	return _PaymentsByAddress.Contract.GetBytecode(&_PaymentsByAddress.CallOpts, payment, refund)
}

// GetBytecode is a free data retrieval call binding the contract method 0x10bc0131.
//
// Solidity: function getBytecode((uint256,uint256,bytes32,address,uint256,address,bool,uint256,bytes) payment, address refund) view returns(bytes)
func (_PaymentsByAddress *PaymentsByAddressCallerSession) GetBytecode(payment PaymentRequest, refund common.Address) ([]byte, error) {
	return _PaymentsByAddress.Contract.GetBytecode(&_PaymentsByAddress.CallOpts, payment, refund)
}

// GetPaymentAddress is a free data retrieval call binding the contract method 0xf287ea05.
//
// Solidity: function getPaymentAddress((uint256,uint256,bytes32,address,uint256,address,bool,uint256,bytes) payment, address refund) view returns(address)
func (_PaymentsByAddress *PaymentsByAddressCaller) GetPaymentAddress(opts *bind.CallOpts, payment PaymentRequest, refund common.Address) (common.Address, error) {
	var out []interface{}
	err := _PaymentsByAddress.contract.Call(opts, &out, "getPaymentAddress", payment, refund)

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// GetPaymentAddress is a free data retrieval call binding the contract method 0xf287ea05.
//
// Solidity: function getPaymentAddress((uint256,uint256,bytes32,address,uint256,address,bool,uint256,bytes) payment, address refund) view returns(address)
func (_PaymentsByAddress *PaymentsByAddressSession) GetPaymentAddress(payment PaymentRequest, refund common.Address) (common.Address, error) {
	return _PaymentsByAddress.Contract.GetPaymentAddress(&_PaymentsByAddress.CallOpts, payment, refund)
}

// GetPaymentAddress is a free data retrieval call binding the contract method 0xf287ea05.
//
// Solidity: function getPaymentAddress((uint256,uint256,bytes32,address,uint256,address,bool,uint256,bytes) payment, address refund) view returns(address)
func (_PaymentsByAddress *PaymentsByAddressCallerSession) GetPaymentAddress(payment PaymentRequest, refund common.Address) (common.Address, error) {
	return _PaymentsByAddress.Contract.GetPaymentAddress(&_PaymentsByAddress.CallOpts, payment, refund)
}

// GetPaymentId is a free data retrieval call binding the contract method 0xb371e542.
//
// Solidity: function getPaymentId((uint256,uint256,bytes32,address,uint256,address,bool,uint256,bytes) payment) pure returns(uint256)
func (_PaymentsByAddress *PaymentsByAddressCaller) GetPaymentId(opts *bind.CallOpts, payment PaymentRequest) (*big.Int, error) {
	var out []interface{}
	err := _PaymentsByAddress.contract.Call(opts, &out, "getPaymentId", payment)

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// GetPaymentId is a free data retrieval call binding the contract method 0xb371e542.
//
// Solidity: function getPaymentId((uint256,uint256,bytes32,address,uint256,address,bool,uint256,bytes) payment) pure returns(uint256)
func (_PaymentsByAddress *PaymentsByAddressSession) GetPaymentId(payment PaymentRequest) (*big.Int, error) {
	return _PaymentsByAddress.Contract.GetPaymentId(&_PaymentsByAddress.CallOpts, payment)
}

// GetPaymentId is a free data retrieval call binding the contract method 0xb371e542.
//
// Solidity: function getPaymentId((uint256,uint256,bytes32,address,uint256,address,bool,uint256,bytes) payment) pure returns(uint256)
func (_PaymentsByAddress *PaymentsByAddressCallerSession) GetPaymentId(payment PaymentRequest) (*big.Int, error) {
	return _PaymentsByAddress.Contract.GetPaymentId(&_PaymentsByAddress.CallOpts, payment)
}

// HasPaymentBeenMade is a free data retrieval call binding the contract method 0x50106593.
//
// Solidity: function hasPaymentBeenMade(address from, (uint256,uint256,bytes32,address,uint256,address,bool,uint256,bytes) payment) view returns(bool)
func (_PaymentsByAddress *PaymentsByAddressCaller) HasPaymentBeenMade(opts *bind.CallOpts, from common.Address, payment PaymentRequest) (bool, error) {
	var out []interface{}
	err := _PaymentsByAddress.contract.Call(opts, &out, "hasPaymentBeenMade", from, payment)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// HasPaymentBeenMade is a free data retrieval call binding the contract method 0x50106593.
//
// Solidity: function hasPaymentBeenMade(address from, (uint256,uint256,bytes32,address,uint256,address,bool,uint256,bytes) payment) view returns(bool)
func (_PaymentsByAddress *PaymentsByAddressSession) HasPaymentBeenMade(from common.Address, payment PaymentRequest) (bool, error) {
	return _PaymentsByAddress.Contract.HasPaymentBeenMade(&_PaymentsByAddress.CallOpts, from, payment)
}

// HasPaymentBeenMade is a free data retrieval call binding the contract method 0x50106593.
//
// Solidity: function hasPaymentBeenMade(address from, (uint256,uint256,bytes32,address,uint256,address,bool,uint256,bytes) payment) view returns(bool)
func (_PaymentsByAddress *PaymentsByAddressCallerSession) HasPaymentBeenMade(from common.Address, payment PaymentRequest) (bool, error) {
	return _PaymentsByAddress.Contract.HasPaymentBeenMade(&_PaymentsByAddress.CallOpts, from, payment)
}

// Batch is a paid mutator transaction binding the contract method 0x09396302.
//
// Solidity: function batch((uint256,uint256,bytes32,address,uint256,address,bool,uint256,bytes)[] payments, address[] refunds) returns()
func (_PaymentsByAddress *PaymentsByAddressTransactor) Batch(opts *bind.TransactOpts, payments []PaymentRequest, refunds []common.Address) (*types.Transaction, error) {
	return _PaymentsByAddress.contract.Transact(opts, "batch", payments, refunds)
}

// Batch is a paid mutator transaction binding the contract method 0x09396302.
//
// Solidity: function batch((uint256,uint256,bytes32,address,uint256,address,bool,uint256,bytes)[] payments, address[] refunds) returns()
func (_PaymentsByAddress *PaymentsByAddressSession) Batch(payments []PaymentRequest, refunds []common.Address) (*types.Transaction, error) {
	return _PaymentsByAddress.Contract.Batch(&_PaymentsByAddress.TransactOpts, payments, refunds)
}

// Batch is a paid mutator transaction binding the contract method 0x09396302.
//
// Solidity: function batch((uint256,uint256,bytes32,address,uint256,address,bool,uint256,bytes)[] payments, address[] refunds) returns()
func (_PaymentsByAddress *PaymentsByAddressTransactorSession) Batch(payments []PaymentRequest, refunds []common.Address) (*types.Transaction, error) {
	return _PaymentsByAddress.Contract.Batch(&_PaymentsByAddress.TransactOpts, payments, refunds)
}

// MultiPay is a paid mutator transaction binding the contract method 0xcbe6a16e.
//
// Solidity: function multiPay((uint256,uint256,bytes32,address,uint256,address,bool,uint256,bytes)[] payments, bytes[] permit2Sigs) payable returns()
func (_PaymentsByAddress *PaymentsByAddressTransactor) MultiPay(opts *bind.TransactOpts, payments []PaymentRequest, permit2Sigs [][]byte) (*types.Transaction, error) {
	return _PaymentsByAddress.contract.Transact(opts, "multiPay", payments, permit2Sigs)
}

// MultiPay is a paid mutator transaction binding the contract method 0xcbe6a16e.
//
// Solidity: function multiPay((uint256,uint256,bytes32,address,uint256,address,bool,uint256,bytes)[] payments, bytes[] permit2Sigs) payable returns()
func (_PaymentsByAddress *PaymentsByAddressSession) MultiPay(payments []PaymentRequest, permit2Sigs [][]byte) (*types.Transaction, error) {
	return _PaymentsByAddress.Contract.MultiPay(&_PaymentsByAddress.TransactOpts, payments, permit2Sigs)
}

// MultiPay is a paid mutator transaction binding the contract method 0xcbe6a16e.
//
// Solidity: function multiPay((uint256,uint256,bytes32,address,uint256,address,bool,uint256,bytes)[] payments, bytes[] permit2Sigs) payable returns()
func (_PaymentsByAddress *PaymentsByAddressTransactorSession) MultiPay(payments []PaymentRequest, permit2Sigs [][]byte) (*types.Transaction, error) {
	return _PaymentsByAddress.Contract.MultiPay(&_PaymentsByAddress.TransactOpts, payments, permit2Sigs)
}

// Pay is a paid mutator transaction binding the contract method 0x3850cae5.
//
// Solidity: function pay((uint256,uint256,bytes32,address,uint256,address,bool,uint256,bytes) payment) payable returns()
func (_PaymentsByAddress *PaymentsByAddressTransactor) Pay(opts *bind.TransactOpts, payment PaymentRequest) (*types.Transaction, error) {
	return _PaymentsByAddress.contract.Transact(opts, "pay", payment)
}

// Pay is a paid mutator transaction binding the contract method 0x3850cae5.
//
// Solidity: function pay((uint256,uint256,bytes32,address,uint256,address,bool,uint256,bytes) payment) payable returns()
func (_PaymentsByAddress *PaymentsByAddressSession) Pay(payment PaymentRequest) (*types.Transaction, error) {
	return _PaymentsByAddress.Contract.Pay(&_PaymentsByAddress.TransactOpts, payment)
}

// Pay is a paid mutator transaction binding the contract method 0x3850cae5.
//
// Solidity: function pay((uint256,uint256,bytes32,address,uint256,address,bool,uint256,bytes) payment) payable returns()
func (_PaymentsByAddress *PaymentsByAddressTransactorSession) Pay(payment PaymentRequest) (*types.Transaction, error) {
	return _PaymentsByAddress.Contract.Pay(&_PaymentsByAddress.TransactOpts, payment)
}

// PayNative is a paid mutator transaction binding the contract method 0x4b47b447.
//
// Solidity: function payNative((uint256,uint256,bytes32,address,uint256,address,bool,uint256,bytes) payment) payable returns()
func (_PaymentsByAddress *PaymentsByAddressTransactor) PayNative(opts *bind.TransactOpts, payment PaymentRequest) (*types.Transaction, error) {
	return _PaymentsByAddress.contract.Transact(opts, "payNative", payment)
}

// PayNative is a paid mutator transaction binding the contract method 0x4b47b447.
//
// Solidity: function payNative((uint256,uint256,bytes32,address,uint256,address,bool,uint256,bytes) payment) payable returns()
func (_PaymentsByAddress *PaymentsByAddressSession) PayNative(payment PaymentRequest) (*types.Transaction, error) {
	return _PaymentsByAddress.Contract.PayNative(&_PaymentsByAddress.TransactOpts, payment)
}

// PayNative is a paid mutator transaction binding the contract method 0x4b47b447.
//
// Solidity: function payNative((uint256,uint256,bytes32,address,uint256,address,bool,uint256,bytes) payment) payable returns()
func (_PaymentsByAddress *PaymentsByAddressTransactorSession) PayNative(payment PaymentRequest) (*types.Transaction, error) {
	return _PaymentsByAddress.Contract.PayNative(&_PaymentsByAddress.TransactOpts, payment)
}

// PayToken is a paid mutator transaction binding the contract method 0xdc13cfe1.
//
// Solidity: function payToken((uint256,uint256,bytes32,address,uint256,address,bool,uint256,bytes) payment, bytes permit2signature) returns()
func (_PaymentsByAddress *PaymentsByAddressTransactor) PayToken(opts *bind.TransactOpts, payment PaymentRequest, permit2signature []byte) (*types.Transaction, error) {
	return _PaymentsByAddress.contract.Transact(opts, "payToken", payment, permit2signature)
}

// PayToken is a paid mutator transaction binding the contract method 0xdc13cfe1.
//
// Solidity: function payToken((uint256,uint256,bytes32,address,uint256,address,bool,uint256,bytes) payment, bytes permit2signature) returns()
func (_PaymentsByAddress *PaymentsByAddressSession) PayToken(payment PaymentRequest, permit2signature []byte) (*types.Transaction, error) {
	return _PaymentsByAddress.Contract.PayToken(&_PaymentsByAddress.TransactOpts, payment, permit2signature)
}

// PayToken is a paid mutator transaction binding the contract method 0xdc13cfe1.
//
// Solidity: function payToken((uint256,uint256,bytes32,address,uint256,address,bool,uint256,bytes) payment, bytes permit2signature) returns()
func (_PaymentsByAddress *PaymentsByAddressTransactorSession) PayToken(payment PaymentRequest, permit2signature []byte) (*types.Transaction, error) {
	return _PaymentsByAddress.Contract.PayToken(&_PaymentsByAddress.TransactOpts, payment, permit2signature)
}

// PayTokenPreApproved is a paid mutator transaction binding the contract method 0xa190fc26.
//
// Solidity: function payTokenPreApproved((uint256,uint256,bytes32,address,uint256,address,bool,uint256,bytes) payment) returns()
func (_PaymentsByAddress *PaymentsByAddressTransactor) PayTokenPreApproved(opts *bind.TransactOpts, payment PaymentRequest) (*types.Transaction, error) {
	return _PaymentsByAddress.contract.Transact(opts, "payTokenPreApproved", payment)
}

// PayTokenPreApproved is a paid mutator transaction binding the contract method 0xa190fc26.
//
// Solidity: function payTokenPreApproved((uint256,uint256,bytes32,address,uint256,address,bool,uint256,bytes) payment) returns()
func (_PaymentsByAddress *PaymentsByAddressSession) PayTokenPreApproved(payment PaymentRequest) (*types.Transaction, error) {
	return _PaymentsByAddress.Contract.PayTokenPreApproved(&_PaymentsByAddress.TransactOpts, payment)
}

// PayTokenPreApproved is a paid mutator transaction binding the contract method 0xa190fc26.
//
// Solidity: function payTokenPreApproved((uint256,uint256,bytes32,address,uint256,address,bool,uint256,bytes) payment) returns()
func (_PaymentsByAddress *PaymentsByAddressTransactorSession) PayTokenPreApproved(payment PaymentRequest) (*types.Transaction, error) {
	return _PaymentsByAddress.Contract.PayTokenPreApproved(&_PaymentsByAddress.TransactOpts, payment)
}

// ProcessPayment is a paid mutator transaction binding the contract method 0xa30ccdcb.
//
// Solidity: function processPayment((uint256,uint256,bytes32,address,uint256,address,bool,uint256,bytes) payment, address refund) returns()
func (_PaymentsByAddress *PaymentsByAddressTransactor) ProcessPayment(opts *bind.TransactOpts, payment PaymentRequest, refund common.Address) (*types.Transaction, error) {
	return _PaymentsByAddress.contract.Transact(opts, "processPayment", payment, refund)
}

// ProcessPayment is a paid mutator transaction binding the contract method 0xa30ccdcb.
//
// Solidity: function processPayment((uint256,uint256,bytes32,address,uint256,address,bool,uint256,bytes) payment, address refund) returns()
func (_PaymentsByAddress *PaymentsByAddressSession) ProcessPayment(payment PaymentRequest, refund common.Address) (*types.Transaction, error) {
	return _PaymentsByAddress.Contract.ProcessPayment(&_PaymentsByAddress.TransactOpts, payment, refund)
}

// ProcessPayment is a paid mutator transaction binding the contract method 0xa30ccdcb.
//
// Solidity: function processPayment((uint256,uint256,bytes32,address,uint256,address,bool,uint256,bytes) payment, address refund) returns()
func (_PaymentsByAddress *PaymentsByAddressTransactorSession) ProcessPayment(payment PaymentRequest, refund common.Address) (*types.Transaction, error) {
	return _PaymentsByAddress.Contract.ProcessPayment(&_PaymentsByAddress.TransactOpts, payment, refund)
}

// RevertPayment is a paid mutator transaction binding the contract method 0xe6422a26.
//
// Solidity: function revertPayment(address from, (uint256,uint256,bytes32,address,uint256,address,bool,uint256,bytes) payment) returns()
func (_PaymentsByAddress *PaymentsByAddressTransactor) RevertPayment(opts *bind.TransactOpts, from common.Address, payment PaymentRequest) (*types.Transaction, error) {
	return _PaymentsByAddress.contract.Transact(opts, "revertPayment", from, payment)
}

// RevertPayment is a paid mutator transaction binding the contract method 0xe6422a26.
//
// Solidity: function revertPayment(address from, (uint256,uint256,bytes32,address,uint256,address,bool,uint256,bytes) payment) returns()
func (_PaymentsByAddress *PaymentsByAddressSession) RevertPayment(from common.Address, payment PaymentRequest) (*types.Transaction, error) {
	return _PaymentsByAddress.Contract.RevertPayment(&_PaymentsByAddress.TransactOpts, from, payment)
}

// RevertPayment is a paid mutator transaction binding the contract method 0xe6422a26.
//
// Solidity: function revertPayment(address from, (uint256,uint256,bytes32,address,uint256,address,bool,uint256,bytes) payment) returns()
func (_PaymentsByAddress *PaymentsByAddressTransactorSession) RevertPayment(from common.Address, payment PaymentRequest) (*types.Transaction, error) {
	return _PaymentsByAddress.Contract.RevertPayment(&_PaymentsByAddress.TransactOpts, from, payment)
}

// PaymentsByAddressPaymentMadeIterator is returned from FilterPaymentMade and is used to iterate over the raw logs and unpacked data for PaymentMade events raised by the PaymentsByAddress contract.
type PaymentsByAddressPaymentMadeIterator struct {
	Event *PaymentsByAddressPaymentMade // Event containing the contract specifics and raw log

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
func (it *PaymentsByAddressPaymentMadeIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(PaymentsByAddressPaymentMade)
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
		it.Event = new(PaymentsByAddressPaymentMade)
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
func (it *PaymentsByAddressPaymentMadeIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *PaymentsByAddressPaymentMadeIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// PaymentsByAddressPaymentMade represents a PaymentMade event raised by the PaymentsByAddress contract.
type PaymentsByAddressPaymentMade struct {
	PaymentId *big.Int
	Raw       types.Log // Blockchain specific contextual infos
}

// FilterPaymentMade is a free log retrieval operation binding the contract event 0x5c27da06a5b3369b2147d80c56b4a888379dbb6967be863136d243fd05c00cf5.
//
// Solidity: event PaymentMade(uint256 indexed paymentId)
func (_PaymentsByAddress *PaymentsByAddressFilterer) FilterPaymentMade(opts *bind.FilterOpts, paymentId []*big.Int) (*PaymentsByAddressPaymentMadeIterator, error) {

	var paymentIdRule []interface{}
	for _, paymentIdItem := range paymentId {
		paymentIdRule = append(paymentIdRule, paymentIdItem)
	}

	logs, sub, err := _PaymentsByAddress.contract.FilterLogs(opts, "PaymentMade", paymentIdRule)
	if err != nil {
		return nil, err
	}
	return &PaymentsByAddressPaymentMadeIterator{contract: _PaymentsByAddress.contract, event: "PaymentMade", logs: logs, sub: sub}, nil
}

// WatchPaymentMade is a free log subscription operation binding the contract event 0x5c27da06a5b3369b2147d80c56b4a888379dbb6967be863136d243fd05c00cf5.
//
// Solidity: event PaymentMade(uint256 indexed paymentId)
func (_PaymentsByAddress *PaymentsByAddressFilterer) WatchPaymentMade(opts *bind.WatchOpts, sink chan<- *PaymentsByAddressPaymentMade, paymentId []*big.Int) (event.Subscription, error) {

	var paymentIdRule []interface{}
	for _, paymentIdItem := range paymentId {
		paymentIdRule = append(paymentIdRule, paymentIdItem)
	}

	logs, sub, err := _PaymentsByAddress.contract.WatchLogs(opts, "PaymentMade", paymentIdRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(PaymentsByAddressPaymentMade)
				if err := _PaymentsByAddress.contract.UnpackLog(event, "PaymentMade", log); err != nil {
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

// ParsePaymentMade is a log parse operation binding the contract event 0x5c27da06a5b3369b2147d80c56b4a888379dbb6967be863136d243fd05c00cf5.
//
// Solidity: event PaymentMade(uint256 indexed paymentId)
func (_PaymentsByAddress *PaymentsByAddressFilterer) ParsePaymentMade(log types.Log) (*PaymentsByAddressPaymentMade, error) {
	event := new(PaymentsByAddressPaymentMade)
	if err := _PaymentsByAddress.contract.UnpackLog(event, "PaymentMade", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// PaymentsByAddressSweepFailedIterator is returned from FilterSweepFailed and is used to iterate over the raw logs and unpacked data for SweepFailed events raised by the PaymentsByAddress contract.
type PaymentsByAddressSweepFailedIterator struct {
	Event *PaymentsByAddressSweepFailed // Event containing the contract specifics and raw log

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
func (it *PaymentsByAddressSweepFailedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(PaymentsByAddressSweepFailed)
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
		it.Event = new(PaymentsByAddressSweepFailed)
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
func (it *PaymentsByAddressSweepFailedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *PaymentsByAddressSweepFailedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// PaymentsByAddressSweepFailed represents a SweepFailed event raised by the PaymentsByAddress contract.
type PaymentsByAddressSweepFailed struct {
	Payment PaymentRequest
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterSweepFailed is a free log retrieval operation binding the contract event 0xe9ba2e59859f36ccb2a53fdbb92f73291c09378719a5911d9b53d6e3eb6bd4a5.
//
// Solidity: event SweepFailed((uint256,uint256,bytes32,address,uint256,address,bool,uint256,bytes) payment)
func (_PaymentsByAddress *PaymentsByAddressFilterer) FilterSweepFailed(opts *bind.FilterOpts) (*PaymentsByAddressSweepFailedIterator, error) {

	logs, sub, err := _PaymentsByAddress.contract.FilterLogs(opts, "SweepFailed")
	if err != nil {
		return nil, err
	}
	return &PaymentsByAddressSweepFailedIterator{contract: _PaymentsByAddress.contract, event: "SweepFailed", logs: logs, sub: sub}, nil
}

// WatchSweepFailed is a free log subscription operation binding the contract event 0xe9ba2e59859f36ccb2a53fdbb92f73291c09378719a5911d9b53d6e3eb6bd4a5.
//
// Solidity: event SweepFailed((uint256,uint256,bytes32,address,uint256,address,bool,uint256,bytes) payment)
func (_PaymentsByAddress *PaymentsByAddressFilterer) WatchSweepFailed(opts *bind.WatchOpts, sink chan<- *PaymentsByAddressSweepFailed) (event.Subscription, error) {

	logs, sub, err := _PaymentsByAddress.contract.WatchLogs(opts, "SweepFailed")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(PaymentsByAddressSweepFailed)
				if err := _PaymentsByAddress.contract.UnpackLog(event, "SweepFailed", log); err != nil {
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

// ParseSweepFailed is a log parse operation binding the contract event 0xe9ba2e59859f36ccb2a53fdbb92f73291c09378719a5911d9b53d6e3eb6bd4a5.
//
// Solidity: event SweepFailed((uint256,uint256,bytes32,address,uint256,address,bool,uint256,bytes) payment)
func (_PaymentsByAddress *PaymentsByAddressFilterer) ParseSweepFailed(log types.Log) (*PaymentsByAddressSweepFailed, error) {
	event := new(PaymentsByAddressSweepFailed)
	if err := _PaymentsByAddress.contract.UnpackLog(event, "SweepFailed", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}
