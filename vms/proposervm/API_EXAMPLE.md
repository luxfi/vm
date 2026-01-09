# ProposerVM GetProposedHeight API

## Overview

The `GetProposedHeight` API endpoint returns the P-Chain height that would be proposed for the next block built on the current preferred block.

## Endpoint

```
/ext/bc/<CHAIN_ID>/proposervm
```

## Method

```
proposervm.getProposedHeight
```

## Parameters

None

## Response

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "proposedHeight": 12345
  }
}
```

Where:
- `proposedHeight` (uint64): The P-Chain height that would be used for the next block

## Example Usage

### cURL

```bash
curl -X POST --data '{
    "jsonrpc":"2.0",
    "id"     :1,
    "method" :"proposervm.getProposedHeight",
    "params" :{}
}' -H 'content-type:application/json;' http://127.0.0.1:9650/ext/bc/C/proposervm
```

### Response

```json
{
  "jsonrpc": "2.0",
  "result": {
    "proposedHeight": 12345
  },
  "id": 1
}
```

## Implementation Details

The proposed P-Chain height is calculated as:
```
proposedHeight = max(currentPChainHeight, parentPChainHeight)
```

Where:
- `currentPChainHeight` is obtained from the validator state
- `parentPChainHeight` is the P-Chain height of the preferred block

This ensures monotonic increases in P-Chain height across the blockchain.

## Use Cases

1. **Block Building Prediction**: Determine the P-Chain height that will be used before building a block
2. **Validator Set Queries**: Know which validator set will be active for the next block
3. **Network Monitoring**: Track P-Chain height synchronization across chains
4. **Testing & Debugging**: Verify P-Chain height selection logic
