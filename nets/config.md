---
tags: [Nodes]
description: Reference for all available Net config options and flags.
sidebar_label: Net Configs
pagination_label: Net Configs
sidebar_position: 2
---

# Net Configs

It is possible to provide parameters for a Net. Parameters here apply to all
chains in the specified Net.

Lux Node looks for files specified with `{subnetID}.json` under
`--subnet-config-dir` as documented
[here](/nodes/configure/node-config-flags.md#subnet-configs).

Here is an example of Net config file:

```json
{
  "validatorOnly": false,
  "consensusParameters": {
    "k": 25,
    "alpha": 18
  }
}
```

## Parameters

### Private Net

#### `validatorOnly` (bool)

If `true` this node does not expose Net blockchain contents to non-validators
via P2P messages. Defaults to `false`.

Lux Nets are public by default. It means that every node can sync and
listen ongoing transactions/blocks in Nets, even they're not validating the
listened Net.

Net validators can choose not to publish contents of blockchains via this
configuration. If a node sets `validatorOnly` to true, the node exchanges
messages only with this Net's validators. Other peers will not be able to
learn contents of this Net from this node.

:::tip

This is a node-specific configuration. Every validator of this Net has to use
this configuration in order to create a full private Net.

:::

#### `allowedNodes` (string list)

If `validatorOnly=true` this allows explicitly specified NodeIDs to be allowed
to sync the Net regardless of validator status. Defaults to be empty.

:::tip

This is a node-specific configuration. Every validator of this Net has to use
this configuration in order to properly allow a node in the private Net.

:::

#### `proposerMinBlockDelay` (duration)

The minimum delay performed when building linear++ blocks. Default is set to 1 second.

As one of the ways to control network congestion, Linear++ will only build a
block `proposerMinBlockDelay` after the parent block's timestamp. Some
high-performance custom VM may find this too strict. This flag allows tuning the
frequency at which blocks are built.

### Consensus Parameters

Net configs supports loading new consensus parameters. JSON keys are
different from their matching `CLI` keys. These parameters must be grouped under
`consensusParameters` key. The consensus parameters of a Net default to the
same values used for the Primary Network, which are given [CLI Consensus Parameters](/nodes/configure/node-config-flags.md#consensus-parameters).

| CLI Key                          | JSON Key              |
| :------------------------------- | :-------------------- |
| --consensus-sample-size               | k                     |
| --consensus-quorum-size               | alpha                 |
| --consensus-commit-threshold          | `beta`                |
| --consensus-concurrent-repolls        | concurrentRepolls     |
| --consensus-optimal-processing        | `optimalProcessing`   |
| --consensus-max-processing            | maxOutstandingItems   |
| --consensus-max-time-processing       | maxItemProcessingTime |
| --consensus-lux-batch-size      | `batchSize`           |
| --consensus-lux-num-parents     | `parentSize`          |

### Gossip Configs

It's possible to define different Gossip configurations for each Net without
changing values for Primary Network. JSON keys of these
parameters are different from their matching `CLI` keys. These parameters
default to the same values used for the Primary Network. For more information
see [CLI Gossip Configs](/nodes/configure/node-config-flags.md#gossiping).

| CLI Key                                                 | JSON Key                               |
| :------------------------------------------------------ | :------------------------------------- |
| --consensus-accepted-frontier-gossip-validator-size     | gossipAcceptedFrontierValidatorSize    |
| --consensus-accepted-frontier-gossip-non-validator-size | gossipAcceptedFrontierNonValidatorSize |
| --consensus-accepted-frontier-gossip-peer-size          | gossipAcceptedFrontierPeerSize         |
| --consensus-on-accept-gossip-validator-size             | gossipOnAcceptValidatorSize            |
| --consensus-on-accept-gossip-non-validator-size         | gossipOnAcceptNonValidatorSize         |
| --consensus-on-accept-gossip-peer-size                  | gossipOnAcceptPeerSize                 |
