# Cross Net Virtual Machine (XSVM)

Cross Net Asset Transfers README Overview

[Background](#lux-subnets-and-custom-vms)

[Introduction](#introduction)

[Usage](#how-it-works)

[Running](#running-the-vm)

[Demo](#cross-subnet-transaction-example)

## Lux Nets and Custom VMs

Lux is a network composed of multiple sub-networks (called [subnets][Net])
that each contain any number of blockchains. Each blockchain is an instance of a
[Virtual Machine
(VM)](https://build.lux.network/docs/quick-start/virtual-machines), much like an
object in an object-oriented language is an instance of a class. That is, the VM
defines the behavior of the blockchain where it is instantiated. For example,
[Go Ethereum Virtual Machine (EVM)][Geth] is a VM that is instantiated by the [C-Chain]. Likewise, one could deploy another instance of the EVM as their own blockchain (to take this to its logical conclusion).

## Introduction

Just as [Geth] powers the [C-Chain], XSVM can be used to power its own blockchain in a Lux [Net]. Instead of providing a place to execute Solidity smart contracts, however, XSVM enables asset transfers for assets originating on its own chain or other XSVM chains on other subnets.

## How it Works

XSVM utilizes Lux Node's [interchain messaging] package to create and authenticate Net Messages.

### Transfer

If you want to send an asset to someone, you can use a `tx.Transfer` to send to any address.

### Export

If you want to send this chain's native asset to a different subnet, you can use a `tx.Export` to send to any address on a destination chain. You may also use a `tx.Export` to return the destination chain's native asset.

### Import

To receive assets from another chain's `tx.Export`, you must issue a `tx.Import`. Note that, similarly to a bridge, the security of the other chain's native asset is tied to the other chain. The security of all other assets on this chain are unrelated to the other chain.

### Fees

Currently there are no fees enforced in the XSVM.

### xsvm

#### Install

```bash
git clone https://github.com/luxfi/node.git;
cd node;
go install -v ./vms/example/xsvm/cmd/xsvm;
```

#### Usage

```
Runs an XSVM plugin

Usage:
  xsvm [flags]
  xsvm [command]

Available Commands:
  account     Displays the state of the requested account
  chain       Manages XS chains
  completion  Generate the autocompletion script for the specified shell
  help        Help about any command
  issue       Issues transactions
  version     Prints out the version
  versionjson Prints out the version in json format

Flags:
  -h, --help   help for xsvm

Use "xsvm [command] --help" for more information about a command.
```

### [Golang SDK](https://github.com/luxfi/node/blob/master/vms/example/xsvm/api/client.go)

```golang
// Client defines xsvm client operations.
type Client interface {
  Network(
    ctx context.Context,
    options ...rpc.Option,
  ) (uint32, ids.ID, ids.ID, error)
  Genesis(
    ctx context.Context,
    options ...rpc.Option,
  ) (*genesis.Genesis, error)
  Nonce(
    ctx context.Context,
    address ids.ShortID,
    options ...rpc.Option,
  ) (uint64, error)
  Balance(
    ctx context.Context,
    address ids.ShortID,
    assetID ids.ID,
    options ...rpc.Option,
  ) (uint64, error)
  Loan(
    ctx context.Context,
    chainID ids.ID,
    options ...rpc.Option,
  ) (uint64, error)
  IssueTx(
    ctx context.Context,
    tx *tx.Tx,
    options ...rpc.Option,
  ) (ids.ID, error)
  LastAccepted(
    ctx context.Context,
    options ...rpc.Option,
  ) (ids.ID, *block.Stateless, error)
  Block(
    ctx context.Context,
    blkID ids.ID,
    options ...rpc.Option,
   (*block.Stateless, error)
  Message(
    ctx context.Context,
    txID ids.ID,
    options ...rpc.Option,
  ) (*warp.UnsignedMessage, []byte, error)
}
```

### Public Endpoints

#### xsvm.network

```
<<< POST
{
  "jsonrpc": "2.0",
  "method": "xsvm.network",
  "params":{},
  "id": 1
}
>>> {"networkID":<uint32>, "subnetID":<ID>, "chainID":<ID>}
```

For example:

```bash
curl --location --request POST 'http://34.235.54.228:9630/ext/bc/28iioW2fYMBnKv24VG5nw9ifY2PsFuwuhxhyzxZB5MmxDd3rnT' \
--header 'Content-Type: application/json' \
--data-raw '{
    "jsonrpc": "2.0",
    "method": "xsvm.network",
    "params":{},
    "id": 1
}'
```

> `{"jsonrpc":"2.0","result":{"networkID":1000000,"subnetID":"2gToFoYXURMQ6y4ZApFuRZN1HurGcDkwmtvkcMHNHcYarvsJN1","chainID":"28iioW2fYMBnKv24VG5nw9ifY2PsFuwuhxhyzxZB5MmxDd3rnT"},"id":1}`

#### xsvm.genesis

```
<<< POST
{
  "jsonrpc": "2.0",
  "method": "xsvm.genesis",
  "params":{},
  "id": 1
}
>>> {"genesis":<genesis file>}
```

#### xsvm.nonce

```
<<< POST
{
  "jsonrpc": "2.0",
  "method": "xsvm.nonce",
  "params":{
    "address":<cb58 encoded>
  },
  "id": 1
}
>>> {"nonce":<uint64>}
```

#### xsvm.balance

```
<<< POST
{
  "jsonrpc": "2.0",
  "method": "xsvm.balance",
  "params":{
    "address":<cb58 encoded>,
    "assetID":<cb58 encoded>
  },
  "id": 1
}
>>> {"balance":<uint64>}
```

#### xsvm.loan

```
<<< POST
{
  "jsonrpc": "2.0",
  "method": "xsvm.loan",
  "params":{
    "chainID":<cb58 encoded>
  },
  "id": 1
}
>>> {"amount":<uint64>}
```

#### xsvm.issueTx

```
<<< POST
{
  "jsonrpc": "2.0",
  "method": "xsvm.issueTx",
  "params":{
    "tx":<bytes>
  },
  "id": 1
}
>>> {"txID":<cb58 encoded>}
```

#### xsvm.lastAccepted

```
<<< POST
{
  "jsonrpc": "2.0",
  "method": "xsvm.lastAccepted",
  "params":{},
  "id": 1
}
>>> {"blockID":<cb58 encoded>, "block":<json>}
```

#### xsvm.block

```
<<< POST
{
  "jsonrpc": "2.0",
  "method": "xsvm.block",
  "params":{
    "blockID":<cb58 encoded>
  },
  "id": 1
}
>>> {"block":<json>}
```

#### xsvm.message

```
<<< POST
{
  "jsonrpc": "2.0",
  "method": "xsvm.message",
  "params":{
    "txID":<cb58 encoded>
  },
  "id": 1
}
>>> {"message":<json>, "signature":<bytes>}
```

## Running the VM

To build the VM, run `./scripts/build_xsvm.sh`.

### Deploying Your Own Network

Anyone can deploy their own instance of the XSVM as a subnet on Lux. All you need to do is compile it, create a genesis, and send a few txs to the
P-Chain.

You can do this by following the [subnet tutorial] or by using the [subnet-cli].

[interchain messaging]: https://github.com/luxfi/node/tree/master/vms/platformvm/warp/README.md
[subnet tutorial]: https://build.lux.network/docs/tooling/create-lux-l1
[Geth]: https://github.com/luxfi/geth
[C-Chain]: https://build.lux.network/docs/quick-start/primary-network#c-chain
[Net]: https://build.lux.network/docs/lux-l1s

## Cross Net Transaction Example

The following example shows how to interact with the XSVM to send and receive native assets across subnets.

### Overview of Steps

1. Create & deploy Net A
2. Create  & deploy Net B
3. Issue an **export** Tx on Net A
4. Issue an **import** Tx on Net B
5. Confirm Txs processed correctly

> **Note:**  This demo requires [lux-cli](https://github.com/luxfi/lux-cli) version > 1.0.5, [xsvm](https://github.com/luxfi/xsvm) version > 1.0.2 and [lux-network-runner](https://github.com/luxfi/lux-network-runner) v1.3.5.

### Create and Deploy Net A, Net B

Using the lux-cli, this step deploys two subnets running the XSVM. Net A will act as the sender in this demo, and Net B will act as the receiver.

Steps

Build the [XSVM](https://github.com/luxfi/xsvm)

### Create a genesis file

```bash
xsvm chain genesis --encoding binary > xsvm.genesis
```

### Create Net A and Net B

```bash
lux subnet create subnetA --custom --genesis <path_to_genesis> --vm <path_to_vm_binary>
lux subnet create subnetB --custom --genesis <path_to_genesis> --vm <path_to_vm_binary>
```

### Deploy Net A and Net B

```bash
lux subnet deploy subnetA --local
lux subnet deploy subnetB --local
```

### Issue Export Tx from Net A

The NetID and ChainIDs are stored in the sidecar.json files in your lux-cli directory. Typically this is located at $HOME/.lux/subnets/

```bash
xsvm issue export --source-chain-id <NetA.BlockchainID> --amount <export_amount> --destination-chain-id <NetB.BlockchainID>
```

Save the TxID printed out by running the export command.

### Issue Import Tx from Net B

> Note: The import tx requires **linear++** consensus to be activated on the importing chain. A chain requires ~3 blocks to be produced for linear++ to start.
> Run `xsvm issue transfer --chain-id <NetB.BlockchainID> --amount 1000`  to issue simple Txs on NetB

```bash
xsvm issue import --source-chain-id <NetA.BlockchainID> --destination-chain-id <NetB.BlockchainID> --tx-id <exportTxID> --source-uris <source_uris>
```

> The <source_uris> can be found by running `lux network status`. The default URIs are
"http://localhost:9630,http://localhost:9652,http://localhost:9654,http://localhost:9656,http://localhost:9658"

**Account Values**
To check proper execution, use the `xsvm account` command to check balances.

Verify the balance on NetA decreased by your export amount using

```bash
xsvm account --chain-id <NetA.BlockchainID>
```

Now verify chain A's assets were successfully imported to NetB

```bash
xsvm account --chain-id <NetB.BlockchainID> --asset-id <NetA.BlockchainID>
```
