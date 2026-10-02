# Protocol-29 exchange arithmetic, offer liabilities, and migration

## Status and scope

The repair described in this note is protocol 29, introduced by stellar-core
commit
[`cb257d2810`](https://github.com/stellar/stellar-core/commit/cb257d2810bb3ca78e7d50d05af1fbaf7ef96a54)
("Improve DEX offer crossing accuracy"). The model first described it as a
protocol-28 change gated by two `exchangeV10` flags; that option record
survives as a proof kernel, as explained below.

In the shipped design there are no flags. `exchangeV10`,
`exchangeV10WithoutPriceErrorThresholds` and `adjustOffer` take a `uint32_t`
ledger version, and `protocolVersionStartsFrom(v, ProtocolVersion::V_29)`
selects the repaired arithmetic. Both repairs are enabled together; there is no
reachable configuration in which only one applies. In the Isabelle model the
option record survives only as a proof kernel, and
`exchange_options_at_version` is the whole protocol mapping:

```text
ledger version < 29   ->  legacy_exchange_options    (both False)
ledger version >= 29  ->  repaired_exchange_options  (both True)
```

`mixed_exchange_options_are_unreachable` records that no ledger version
selects a one-sided repair, so the two mixed settings are diagnostic mutants
rather than protocol versions.

The single arithmetic refactor protocol 29 makes is the helper boundary. The
relaxed-value calculation and the final round-down division now live together
in `calculateOfferAmountFromValue`, which returns the signed offer amount. The
model has `calculate_offer_amount_from_value` as its direct counterpart, and
`calculate_offer_amount_from_value_eq_value_then_divide` proves it equal to the
older relaxed-value-then-divide sequence, so the existing repaired proof stack
carries over unchanged.

The note also separates two changes that have very different ledger-upgrade
consequences:

1. activating protocol 29 while retaining the existing `INT64_MAX`
   saturation clamp; and
2. removing that clamp and changing the meaning of unrestricted exchange and
   persistent offer liabilities.

The first change can be migration-free. The second cannot be assumed to be.

This note concerns arithmetic and liability semantics. The distinct question
of whether crossing a resting offer should use all of the maker's live buying
headroom or only the offer's booked buying liability is covered in
`formal/docs/resting-offer-receive-cap.md`.
## The two repaired branches

`exchangeV10` receives four amount limits. Protocol 29 repairs two
mirror-image cases in which converting an exact receive limit into a scaled
value by multiplication loses the final fractional unit before a later
division. Both branches are round-down branches, and both now call
`calculateOfferAmountFromValue`.

- The non-staying wheat branch, taken when the wheat offer is consumed and
  wheat is the more valuable asset, where `maxSheepReceive` is an exact cap on
  the number of sheep units the wheat seller may receive. It calls
  `calculateOfferAmountFromValue(price.n, price.d, maxWheatSend,
  maxSheepReceive)`.
- The mirrored wheat-stays branch under normal rounding, taken when sheep is
  at least as valuable, where `maxWheatReceive` is an exact cap on the number
  of wheat units the sheep seller may receive. It calls
  `calculateOfferAmountFromValue(price.d, price.n, maxSheepSend,
  maxWheatReceive)` with the swapped price and caps.

The `wheatStays` decision itself is unchanged: it still compares the two
unadjusted plain offer values. Strict-send is outside both changed branches,
and strict-receive uses only the first.

For a price denominator `d` and a receive cap `R`, the plain offer-value
calculation uses:

```text
R * d
```

The exact-cap calculation normally uses:

```text
R * d + d - 1
```

This is the greatest scaled value whose division by `d`, rounded down, still
produces at most `R` whole units.

The options deliberately do not change the initial `wheatStays` comparison.
They change amount calculation only after that verdict has been chosen.

## Current call-site split

In the current implementation, ledger-level adjustment and
crossing derive both flags from the ledger version:

```text
posting adjustOffer       both flags true
crossing adjustOffer      both flags true
exchangeV10 while crossing both flags true
```

Liability projection does not currently do this. The following calculations
call `exchangeV10WithoutPriceErrorThresholds` without either Boolean argument,
so both default to false:

- `ManageSellOfferOpFrame::getOfferSellingLiabilities`;
- `ManageSellOfferOpFrame::getOfferBuyingLiabilities`;
- `ManageBuyOfferOpFrame::getOfferSellingLiabilities`;
- `ManageBuyOfferOpFrame::getOfferBuyingLiabilities`;
- `getOfferSellingLiabilities` for a stored ledger offer; and
- `getOfferBuyingLiabilities` for a stored ledger offer.

This creates two categories of liability calculation:

1. **Persistent stored-offer liabilities.** These are acquired into aggregate
   account or trustline liability fields and later released when the offer is
   changed, crossed, or removed.
2. **Request-time liabilities.** These are temporary values used by
   `ManageSellOffer` or `ManageBuyOffer` preflight before a residual offer is
   adjusted and possibly stored.

The migration analysis is different for these two categories.

## The `INT64_MAX` saturation clamp

`calculateOfferValueWithExactReceiveCap` contains one additional minimum:

```text
receive value = min(R * d + d - 1, INT64_MAX * d)
```

When `R` is `INT64_MAX`, this restores the plain value exactly:

```text
min(INT64_MAX * d + d - 1, INT64_MAX * d)
  = INT64_MAX * d
```

The clamp is not needed to prevent `uint128_t` overflow. The products and the
additional `d - 1` fit in the intermediate type for valid input ranges. Its
purpose is semantic compatibility: an exact-cap calculation against a
maximally capable counterparty produces the same value as the historical
flag-free liability calculation.

The formal model records this property in
`exact_receive_cap_collapses_at_unlimited_receive`.

The symmetric flag is also inert for an unrestricted liability projection.
With the opposing send and receive limits both set to `INT64_MAX`, the offer
being projected cannot be the strictly larger side. The wheat-stays branch in
which the mirrored wheat-stays repair matters is therefore unreachable.

Together, these facts imply:

```text
stored-offer liabilities with both flags true and the clamp retained
  = stored-offer liabilities with both flags false
```

## Why passing both flags everywhere can be migration-free

Under protocol 29 every relevant liability call uses both
options as true, while the saturation clamp remains unchanged.

Persistent stored-offer liabilities do not change. Every stored offer is
projected against an unrestricted counterparty, the exact receive cap
collapses to the plain cap at `INT64_MAX`, and the symmetric branch is
unreachable. Consequently:

- an offer acquired before the protocol transition has the same recomputed
  liability after the transition;
- `releaseLiabilities` subtracts exactly the amount originally acquired;
- aggregate account and trustline liabilities remain correct;
- no ledger-wide offer scan or liability recomputation is needed;
- no per-offer creation-version marker is needed; and
- no ledger-entry or XDR change is needed.

The same equality applies to `ManageSellOffer` request liabilities because its
raw sell request is also projected against `INT64_MAX` on the counterparty
limits.

This makes the following a coherent migration-free protocol-29 arrangement:

```text
adjustment                    both flags true
crossing                      both flags true
ManageSell request projection both flags true, unchanged result
stored-offer projection       both flags true, unchanged result
```

Passing the flags still has value even where the result is unchanged: it makes
the selected protocol semantics explicit at every call site and turns the
unchanged-result claim into a proved property rather than an implicit reliance
on default arguments.

## ManageBuy request-time liabilities are different

`ManageBuyOffer` projects its raw request using the submitted buy amount as a
finite receive cap. The `INT64_MAX` collapse therefore does not apply, and
the non-staying wheat repair can change the temporary preflight liabilities.

For example, take a submitted ManageBuy price of `100/101` and a buy amount of
one. The canonical resting sell price is `101/100`.

The flag-free request projection first converts the one-unit receive cap to a
scaled value of 100, then divides by 101:

```text
flag-free scaled cap = 1 * 100 = 100
flag-free amount     = floor(100 / 101) = 0
flag-free liabilities = 0 selling / 0 buying
```

The exact-cap projection includes all scaled values that still round down to
one received unit:

```text
exact scaled cap = 1 * 100 + 100 - 1 = 199
exact amount     = floor(199 / 101) = 1
exact liabilities = 1 selling / 1 buying
```

A later exact-cap adjustment can therefore create the one-for-one offer because
its effective-price error is below one percent.

The current path can therefore have this shape:

```text
request preflight liabilities 0 / 0
exact-cap adjustment creates amount 1
stored-offer acquisition reserves 1 / 1
```

The inconsistency can also change the operation result. Suppose the account is
authorized, has enough reserve and one unit of buying headroom, but has zero
available balance of the selling asset. The current flag-free preflight asks
whether zero available balance is less than zero selling liability. It is not,
so the request passes the `UNDERFUNDED` check. The later exact-cap posting path
sees the real zero send capacity, adjusts the offer amount to zero, and returns
`MANAGE_BUY_OFFER_SUCCESS` with `MANAGE_OFFER_DELETED` and no residual offer.

With consistent exact-cap projection, preflight would calculate a selling
liability of one. Zero available balance is less than one, so the same request
would immediately return `MANAGE_BUY_OFFER_UNDERFUNDED`.

Later adjustment and checked liability acquisition still enforce the live
ledger limits, so the mismatch is not by itself a persistent underreservation.
The oddity is instead that one operation is first treated as requiring no
capacity and is later treated as a genuine one-unit offer; in the unfunded
case, that disagreement changes `UNDERFUNDED` into successful creation of no
offer.

Passing both flags to ManageBuy request projection may therefore change
protocol-28 operation results. This is an ordinary protocol-behavior change,
not a migration problem: the request-time values are not stored in aggregate
ledger liabilities. It needs dedicated compatibility review and tests, but no
recomputation of pre-existing ledger state.

As in stored-offer projection, the mirrored wheat-stays repair is not expected to
change this particular calculation because the opposing offer is unrestricted
and the wheat-stays branch is unreachable. Passing it is still appropriate for
a uniform protocol-options interface.

## Why removing the clamp is a different change

Removing the clamp gives the exact-cap formula its natural unit-cap meaning
even when the receive cap is `INT64_MAX`. It permits an exact rational value
slightly above `INT64_MAX` when the actual rounded amount received remains
exactly `INT64_MAX`.

For example, let:

```text
M = INT64_MAX
price = 3/2
amount = (2*M + 1) / 3
```

Then:

```text
amount * 3/2 = M + 1/2
floor(amount * 3/2) = M
```

Without the clamp, an exact-cap unrestricted adjustment can retain the full
`amount` and receive `M`. Under the current flag-free stored-liability formula,
the same offer projects to:

```text
selling liability = amount - 1
buying liability  = M - 1
```

The offer would have one unreserved unit on both sides. The owner could use
that apparent spare capacity in another operation, after which the
preventative crossing adjustment could shrink the offer. This breaks the
intended relationship between an adjusted offer and the liabilities that back
it, even if the preventative adjustment remains a final balance-safety guard.

Removing the clamp is coherent only if persistent liability projection changes
at the same time. That creates an upgrade problem because account and trustline
liabilities are aggregate fields. Existing offers were acquired using the old
formula, while a post-upgrade `releaseLiabilities` call would recompute and try
to subtract the new formula.

A no-clamp protocol would therefore need an explicit migration strategy, such
as:

- recomputing all offers and all aggregate liabilities at the protocol
  boundary;
- adjusting or removing every existing offer and reacquiring its liabilities;
  or
- recording which liability semantics each offer uses, requiring persistent
  version metadata.

It would also need a policy for accounts that cannot cover the larger migrated
liabilities.

## Consequence for the abstract specification

`Offer_Exchange_Specification.max_unrestricted_exchange` currently contains
the condition:

```text
wheat * price <= int64_max
```

This is stronger than merely requiring the rounded sheep amount to fit in a
signed 64-bit ledger amount. It mirrors the current C++ saturation policy at
an unrestricted receive cap and is therefore needed by the existing posting
refinement.

The separate condition:

```text
sheep / price <= int64_max
```

is logically redundant when the definition already requires both
`wheat = ceiling(sheep / price)` and `wheat <= int64_max`.

The specification choices track the two implementation alternatives:

- **Both flags everywhere, clamp retained:** keep
  `wheat * price <= int64_max`; the persistent liability formula and migration
  behavior remain unchanged.
- **Both flags everywhere, clamp removed:** remove that rational saturation
  condition and redefine persistent liabilities using the same no-clamp
  exact-cap semantics; account for the resulting migration obligation.

Passing both flags everywhere does not by itself justify removing the abstract
condition. The decisive question is whether the `INT64_MAX` clamp remains.

## Recommended migration-free change

For a protocol-29 implementation that prioritizes consistent call semantics
without changing persistent ledger state:

1. Introduce one protocol-selected exchange-options value rather than relying
   on omitted default Boolean arguments.
2. Thread both flags through adjustment, crossing, request liability
   projection, and stored-offer liability projection.
3. Retain the `INT64_MAX` clamp.
4. Prove that stored-offer and ManageSell request liabilities are unchanged.
5. Characterize the changed ManageBuy request outcomes and decide whether the
   improved preflight consistency is intended.
6. Add differential cases covering both flags at all liability call sites,
   including finite ManageBuy receive caps and `INT64_MAX` saturation.

This proposal is a semantic cleanup plus a ManageBuy preflight change. It is
not a persistent-liability migration.

Removing the clamp should be evaluated separately as a new liability-semantics
protocol with explicit migration requirements.


## What the model establishes for protocol 29

The Isabelle model now carries the following, all checked:

- `calculate_offer_amount_from_value` as the direct model of
  `calculateOfferAmountFromValue`, with an equivalence bridge to the earlier
  relaxed-value-then-divide form;
- `exchange_options_at_version` as the sole protocol mapping, with reduction
  theorems `exchange_v10_legacy` / `exchange_v10_repaired` and their
  pre-threshold and adjustment counterparts, so protocol-28 preservation is a
  theorem rather than test evidence;
- `pre_thresholds_options_irrelevant_at_unlimited_caps`, from which
  `offer_selling_liabilities_version_independent`,
  `offer_buying_liabilities_version_independent` and
  `persistent_liabilities_agree_across_activation` follow: a stored offer has
  the same booked liabilities at every ledger version, so activation needs no
  liability rewrite and no stored-offer migration pass;
- a protocol-29 property catalogue specializing maximality, adjustment
  stability, the full-take property, and ideal refinement, together with
  `fully_taken_posted_offer_exchanges_posted_amount_p28_false`, which shows the
  repaired property genuinely fails at protocol 28; and
- the migration ladder restated at the boundary, with its reachability limits
  stated in the "Reachability boundary" subsection of
  `Offer_Exchange_Migration.thy`.

The compatibility argument depends on the retained `INT64_MAX * priceD` clamp
inside the helper. Removing that clamp is a separate change and would
invalidate `persistent_liabilities_agree_across_activation`.

## Deliberately out of scope

The same commit also adds a pre-protocol-29 overlay filter for offers that can
only clear for zero: `priceErrorBoundHoldsForFullClear`, `offerCanClearForZero`,
and the operation, transaction, passive-offer, deletion and fee-bump overlay
hooks that use them. None of that is modeled or proved here. It needs its own
model, proof plan, differential dimension, and review.
