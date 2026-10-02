# Resting-offer receive capacity and buying liabilities

## Status and scope

This note records a discrepancy between the abstract crossing specification and
the current C++ implementation of a single protocol-28 order-book crossing. It
is concerned only with normal offer crossing when both
`exactReceiveCap` and `symmetricExactReceiveCap` are enabled. It does not cover
multiple book offers, liquidity pools, self-cross filtering, frozen offers, or
sponsorship bookkeeping.

The discrepancy is not a balance-safety failure. It concerns which capacity is
used to decide whether the resting offer or the incoming offer stays, and hence
which direction the integer exchange rounds.

## Summary

A stored sell offer explicitly contains a maximum amount to sell and a price.
Its maximum full-cross payment in the buying asset is derived from those two
values and is booked as its buying liability.

The abstract specification treats that buying liability as an offer-local
receive cap. The C++ implementation does not. After releasing the offer's
liabilities, C++ passes all of the maker's resulting live buying headroom to
`exchangeV10`.

Consequently, spare maker headroom can increase the resting offer's calculated
capacity, change which offer is said to stay, change the rounding direction,
and reduce a valid positive trade to zero. The offer amount still bounds the
resting offer, so spare headroom cannot make it arbitrarily large; the problem
can arise from a difference of only one scaled integer unit.

## The C++ crossing calculation

For a resting offer that sells wheat and buys sheep, `crossOfferV10` performs
the following steps in `src/transactions/OfferExchange.cpp`:

1. Release the offer's selling and buying liabilities.
2. Run the preventative `adjustOffer` against the released maker state.
3. Calculate the maker-side limits.
4. Call `exchangeV10`.
5. Move balances.
6. Remove the offer or adjust its remainder and reacquire liabilities.

The maker-side limits at step 3 are asymmetric:

```cpp
int64_t maxWheatSend =
    canSellAtMost(header, accountB, wheat, wheatLineAccountB);
maxWheatSend = std::min({offer.amount, maxWheatSend});

int64_t maxSheepReceive =
    canBuyAtMost(header, accountB, sheep, sheepLineAccountB);
```

Thus the effective limits are:

```text
maker wheat-send cap = min(stored offer amount, live wheat capacity)
maker sheep-receive cap = all live sheep headroom after release
```

`exchangeV10WithoutPriceErrorThresholds` then compares the two offers using
scaled integer values:

```text
resting value = min(max wheat send * price numerator,
                    max sheep receive * price denominator)

incoming value = min(max sheep send * price denominator,
                     max wheat receive * price numerator)

resting offer stays exactly when resting value > incoming value
```

Although all released headroom is passed into this calculation, the stored
offer amount still bounds the first term. Large headroom therefore makes the
receive limit non-binding; it does not make a one-unit offer appear to contain
thousands of units.

## The abstract specification

`Offer_Exchange_Specification.exchange_caps` instead calculates the maker's
limits as:

```text
maker wheat-send cap =
  min(offer's unrestricted wheat amount,
      live wheat capacity after release)

maker sheep-receive cap =
  min(offer's unrestricted sheep amount,
      live sheep headroom after release)
```

The unrestricted wheat and sheep amounts are also the offer's selling and
buying liabilities.

For a well-formed maker state, releasing an offer's liability adds that amount
back to the corresponding available capacity:

```text
available wheat after release =
  available wheat before release + offer selling liability

sheep headroom after release =
  sheep headroom before release + offer buying liability
```

The capacities before release are nonnegative. Therefore both specification
minima select their first arguments for a correctly posted offer. Under its
intended preconditions, the specification is effectively saying:

```text
maker wheat-send cap = offer selling liability
maker sheep-receive cap = offer buying liability
```

Spare maker capacity is deliberately excluded from the resting offer's size.

## Minimal example

Consider a maker who posts an offer selling 1 wheat at a sheep-per-wheat price
of `101/100`.

The maker initially has:

```text
wheat balance = 1
wheat selling liabilities = 0
sheep balance = 0
sheep trustline limit = 2
sheep buying liabilities = 0
```

An unrestricted full cross exchanges 1 wheat for 1 sheep after integer
rounding. Posting therefore creates the one-wheat offer and books:

```text
wheat selling liability = 1
sheep buying liability = 1
```

Now an active incoming offer sells 1 sheep at the reciprocal price. Its owner
has 1 sheep available and ample wheat headroom. The offers cross at equality.

### Specification result

After releasing the resting offer's buying liability, the maker has 2 sheep of
live headroom. The specification nevertheless caps this offer at its booked
payment of 1 sheep:

```text
maker sheep-receive cap = min(1, 2) = 1
```

The scaled capacities are then:

```text
resting value = min(1 * 101, 1 * 100) = 100
incoming value = min(1 * 100, ample capacity) = 100
```

The values tie, so the resting offer does not stay. The full-take rounding
direction produces a trade of 1 wheat for 1 sheep, within the one-percent
price-error bound.

### C++ result

C++ passes the entire released headroom of 2 sheep:

```text
resting value = min(1 * 101, 2 * 100) = 101
incoming value = min(1 * 100, ample capacity) = 100
```

The resting offer is now considered larger and therefore stays. Rounding
favors the staying resting offer. One sheep is insufficient to buy one whole
wheat at `101/100` in that branch, so the computed exchange is zero wheat for
zero sheep.

Changing the maker's headroom from 2 to 1000 does not make the resting value
larger than 101:

```text
headroom 1:    min(1 * 101,    1 * 100) = 100
headroom 2:    min(1 * 101,    2 * 100) = 101
headroom 1000: min(1 * 101, 1000 * 100) = 101
```

The discrepancy is the one-unit change from the rounded liability-backed value
of 100 to the offer's nominal scaled value of 101. That one unit flips which
offer stays.

The resulting non-monotonic chain is:

```text
more maker receiving headroom
-> larger calculated resting capacity
-> different offer marked as staying
-> different rounding direction
-> smaller trade, possibly zero
```

## Why both exact-cap flags do not eliminate the discrepancy

The two exact-cap repairs change amount calculation in two branches of
`exchangeV10WithoutPriceErrorThresholds`. They deliberately do not change the
initial `wheatStays` comparison, which continues to use the plain scaled offer
values.

In the example above, live headroom has already changed `wheatStays` from false
to true before either repaired amount calculation can help. The example is in
the wheat-stays branch with a price numerator greater than its denominator, so
neither repaired full-take branch restores the one-for-one trade. The mismatch
therefore remains when both flags are true.

## Origin of the asymmetry

There is a coherent reason for the original shape of the exchange code:

- A sell offer explicitly stores a maximum amount to sell, so `offer.amount`
  is naturally a hard selling cap.
- A sell offer does not explicitly store a maximum amount to receive. Its
  payment follows from its price, and the buying trustline's headroom is the
  ledger-safety cap.
- Buying liabilities are derived reservations, not fields of the offer entry.

The code history also shows that the asymmetric `crossOfferV10` capacity
calculation existed when `exchangeV10` was introduced, before liabilities were
wrapped around the crossing path. Liability integration subsequently added
release and reacquisition while preserving the existing exchange limits. The
resulting composition is:

```text
release the offer's reservation
-> run the pre-existing crossing algorithm with live capacities
-> reserve liabilities for any remainder
```

This explains how the asymmetry arose. It does not establish that spare maker
headroom was intentionally meant to affect which offer stays. In exact
arithmetic, extra receive capacity above what the offer needs would normally be
irrelevant because the stored selling amount still bounds the offer. The
observable behavior arises from integer truncation and the staying-side
rounding rule.

## Proposed conceptual interpretation

A stored sell offer can instead be interpreted as asserting two offer-local
bounds:

```text
maximum amount sold = stored offer amount

maximum amount received =
  payment produced by an unrestricted full cross of that amount
  at the stored price
```

The second value is exactly the offer's buying liability. It need not be added
to the ledger entry because it can be recomputed bit-precisely from the stored
amount and price.

Under this interpretation, crossing uses:

```text
maker wheat-send cap =
  min(stored amount, live wheat capacity)

maker sheep-receive cap =
  min(recomputed offer buying liability, live sheep headroom)
```

For a well-formed offer just after its liabilities are released, these become
the stored amount and its buying liability. Unrelated spare headroom cannot
change the offer's apparent size or rounding role.

This gives liabilities a stronger meaning than they have in the current C++:

> An offer liability is both capacity protected from other ledger operations
> and the offer-local execution budget used while crossing that offer.

## Migration and protocol activation

This repair does not require a ledger-state migration, provided it changes
only the crossing cap and leaves the offer-liability formula unchanged. An
existing offer already contributes its recomputed buying liability to the
aggregate liabilities of its account or trustline. The crossing path releases
that amount before the exchange and acquires the newly computed liabilities of
any remainder afterward. Using the same recomputed amount as an offer-local
execution cap does not change the stored offer, the aggregate liability fields,
or the amount released and reacquired.

The implementation should retain the live-headroom bound rather than replace
it outright. After the preventative `adjustOffer`, the effective cap should be:

```text
maker sheep-receive cap =
  min(recomputed buying liability of the adjusted offer,
      live sheep headroom after release)
```

Computing the liability after `adjustOffer` makes the execution budget match
the amount that will actually be offered. Intersecting it with live headroom
preserves the existing defensive balance-safety check if the ledger state is
unexpectedly inconsistent.

The repair must nevertheless be introduced behind a protocol-version gate.
Offers already present at activation may subsequently produce different trade
amounts, rounding directions, claim atoms, or taken-versus-partial results.
That is an intentional consensus-behavior transition applied to existing
offers, not a migration of their persisted state. It requires protocol-boundary
tests, but no offer scan, liability recomputation, per-offer version marker, or
XDR change.

This conclusion depends on keeping liability semantics stable. If the same
protocol change also altered `getOfferBuyingLiabilities`--for example by
removing the unrestricted-receive saturation clamp--then releasing an old
offer could subtract a different amount from the one originally acquired. Such
a liability-formula change has a separate migration problem and should not be
conflated with this crossing-cap repair.

## Partial fills and remaining offers

After a partial fill, the remaining stored amount must be adjusted against the
post-trade balances and limits, its unrestricted payment recomputed, and its
new liabilities acquired. Integer rounding can make the payment received by a
partial fill interact subtly with the liability required by the remainder.
The existing post-cross `adjustOffer` step may therefore need to shrink or
remove the remainder before liabilities are reacquired.

A full abstract state-transition specification should say explicitly:

- how much of the original receive budget a partial fill consumes;
- how the receive budget of the remaining amount is derived;
- when post-cross adjustment shortens or removes the remainder; and
- whether `resting_offer_stays` describes only the arithmetic verdict or also
  guarantees that a nonzero offer remains in the book.

The current high-level specification returns only `trade option`, so it can
express the amount discrepancy but not all of these post-cross effects.

## Consequence for refinement

A general refinement theorem from the current C++ crossing calculation to
`Offer_Exchange_Specification.cross_sell_wheat_offer` is false, even when:

- the resting offer is crossed immediately in the state produced by posting;
- both parties and both offers are well formed;
- the incoming offer crosses at the reciprocal resting price; and
- both exact-cap flags are true.

There are three possible resolutions:

1. **Treat the abstract behavior as normative.** Cap the C++ maker receive
   limit by the recomputed offer buying liability behind an appropriate
   protocol gate, then prove refinement to that repaired implementation.
2. **Treat current C++ behavior as normative.** Change the specification to use
   all live maker headroom and accept that spare headroom may affect the staying
   verdict and rounding outcome.
3. **Restrict the refinement domain.** Require the maker's released headroom to
   equal the offer's buying liability. This avoids the discrepancy but excludes
   ordinary well-funded makers and does not provide a satisfactory general
   refinement theorem.

The first option matches the current abstract specification and makes offer
execution depend on the capacity reserved for that offer. The second is the
bit-precise description of the present C++ path. Choosing between them is a
protocol-design decision rather than a proof-engineering detail.
