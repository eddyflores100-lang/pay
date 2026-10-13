# MPP channel versions

MPP sessions default to the existing V1 payment-channel program. V2 is an
experimental, opt-in deployment with immutable funding and distribution hooks.
Existing channels do not migrate when you change the server configuration.

## Select V2

For a devnet server with MPP sessions already configured, set:

```sh
export PAY_PAYMENT_CHANNELS_PROGRAM_ID=CHNLxBtXw7VPqd5GMcbtVoEbn4ehyaSoiHj56Ao5sWkJ
export PAY_MPP_CHANNEL_VERSION=2
```

Restart the server with its existing devnet configuration. The session challenge
advertises `channelProgram` and `channelVersion`. These settings alone create
ordinary payer-funded V2 channels without hooks; they do not enable Coinflow.
The selected program must be deployed on the configured network.

To keep V1, leave both variables unset. Its program is
`CHNLxYvVA28MJP9PrFuDXccuoGXAx7jBacfLEkahyGsX`. An absent version means V1,
not “infer the version from the program.” Invalid addresses, unsupported
versions and mismatched program/version pairs fail instead of falling back.

## Configure hooks

| Variable | Used by | Value |
| --- | --- | --- |
| `PAY_MPP_CHANNEL_HOOKS` | Merchant server | JSON object with optional `preFund`, `postFund`, `preDistribute`, `postDistribute` descriptors |
| `PAY_MPP_TRUSTED_CHANNEL_HOOKS` | Pay client / MCP | Exact approved descriptor configuration, using the same JSON shape |

Each descriptor contains `programId`, an eight-byte `entrypoint` array,
`accounts` (ordered `{address, writable}` entries), and `staticData` (bytes).
At most four extra accounts and 32 static-data bytes are supported per hook.
There is no extra-account signer flag. Transaction size and compute limits
still apply; not every combination at these per-hook bounds fits a transaction.

Configure only a deployed adapter whose authority and custody rules you have
reviewed. Pay rejects advertised hook configuration before wallet approval
unless it exactly matches the local trusted configuration. Trusting a program
name is insufficient: accounts, permissions and static data must also match.
Even an explicitly advertised empty `{}` configuration requires a matching
client policy; omitting hook configuration requires no hook approval.

Hooks execute as CPIs inside `open`/`topUp` or `distribute`/`withdrawPayer`.
Once installed, they cannot be omitted from later operations. A callback failure
fails the transaction, including its token transfers. A configured distribution
hook still runs when no principal is refunded; a credit adapter must issue no
credits for that case.

## Recovery

Keep the persisted session configuration and channel records. They bind the
program, ABI version and hook policy used at opening. V2 recovery must validate
the account owner and on-chain hook commitment against that stored policy.
Changing process defaults must not reinterpret an existing channel.

Chain-only adoption is not supported for V2: public channel state does not
reconstruct the original merchant policy and consumer authentication binding.
Retain access to the V1 deployment and its configuration while V1 channels are
still active.

## Scope

This integration supports MPP sessions. Direct-transfer MPP charge and x402
behavior are unchanged. Channel-backed charge, Coinflow transaction preparation,
and a production credit-redemption/recredit adapter are not implemented here.
Program hooks alone do not confer permission to debit or mint issuer credits.
