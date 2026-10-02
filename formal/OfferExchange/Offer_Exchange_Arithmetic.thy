theory Offer_Exchange_Arithmetic
  imports "HOL-Library.Word" "HOL-Library.Monad_Syntax"
begin
section \<open>Exchange arithmetic\<close>

text \<open>
  The export check of the Isabelle tooling audits, alongside the code equations
  of the exported model, every fact collected under \<open>export_audit\<close>: the
  theorems that connect the exported code-level definitions to what was proved
  about them must depend on no oracle and on no project axiom that is not a
  definition. Theories add their refinement and equivalence theorems to it.
\<close>

named_theorems export_audit
  "facts the export check audits together with the exported code equations"

text \<open>
  This theory gives an executable, bit-precise model of the arithmetic used by
  \<open>exchangeV10\<close>.  It first presents the modeled operations and their main
  properties, then proves those properties in the same order so that the
  definitions and their verification can be read side by side.
\<close>

subsection \<open>The model and its main properties\<close>

text \<open>
  This first section presents the model in full and, at its end, states the
  properties that the remaining sections prove.  Nothing is proved here, so
  the model can be read on its own and compared line by line with
  \<open>OfferExchange.cpp\<close>.

  The definitions stay close to the C++ they model: the same branch
  structure, the same order of calls, and bit-precise arithmetic on 32-, 64-,
  and 128-bit words.  The error monad below stands for the C++ control flow
  that a failed assertion, a detected overflow, or an explicit \<open>throw\<close>
  interrupts.  Alongside each modeled function there is a specification
  phrased over unbounded integers; the proofs then show that the two agree.
\<close>

subsubsection \<open>Fixed-width C++ arithmetic\<close>

type_synonym int32 = "32 word"
type_synonym int64 = "64 word"
type_synonym uint128 = "128 word"

abbreviation int64_max_int :: int
  \<comment> \<open>C++: \<open>INT64_MAX\<close>\<close>
  where "int64_max_int \<equiv> 9223372036854775807"

text \<open>
  @{term int64_max_int} is the value of the C++ constant \<open>INT64_MAX\<close> as an
  unbounded integer, that is @{term "(2::int) ^ 63 - 1"}.  It is an
  abbreviation rather than a definition so that every arithmetic step still
  sees the plain numeral.  The companion constant \<open>int64_max\<close> defined below
  is the signed 64-bit word with that bit pattern.
\<close>

datatype cxx_error =
    Cxx_Assertion_Failed
  | Cxx_Overflow
  | Cxx_Runtime_Error

datatype 'a cxx_result =
    Cxx_Ok 'a
  | Cxx_Err cxx_error

fun cxx_bind ::
    "'a cxx_result \<Rightarrow> ('a \<Rightarrow> 'b cxx_result) \<Rightarrow> 'b cxx_result"
  where
    "cxx_bind (Cxx_Ok x) f = f x"
  | "cxx_bind (Cxx_Err e) f = Cxx_Err e"

adhoc_overloading
  Monad_Syntax.bind \<rightleftharpoons> cxx_bind

text \<open>
  The operation @{const cxx_bind} is an executable exception-style bind.
  A value built with @{const Cxx_Err} is propagated unchanged, while a value
  built with @{const Cxx_Ok} is passed to the next computation.  The overload
  enables do notation in executable definitions below.
\<close>

lemma cxx_bind_assoc:
  "cxx_bind (cxx_bind m f) g = cxx_bind m (\<lambda>x. cxx_bind (f x) g)"
  \<comment> \<open>Sequencing is associative, so a computation may be repackaged as a
    helper that performs several steps without changing its result.\<close>
  text \<open>
    Proof sketch: an error in @{term m} is propagated by both sides, and an
    @{const Cxx_Ok} value is passed to the same continuation by both sides,
    so a case distinction on @{term m} closes the goal.
  \<close>
  by (cases m) simp_all

subsubsection \<open>Wide multiplication\<close>

text \<open>
  This models the C++ function \<open>bigMultiply\<close> from
  \<open>util/numeric.cpp\<close>. Its arguments have the bit patterns of C++
  \<open>int64_t\<close> values, so
  they are interpreted with @{const sint}.  The implementation asserts that
  both arguments are non-negative, widens them to unsigned 128-bit values,
  and multiplies them.  Two non-negative signed 64-bit values have a product
  below $2^{126}$, so the 128-bit multiplication cannot wrap.
\<close>

definition big_multiply ::
    "int64 \<Rightarrow> int64 \<Rightarrow> uint128 cxx_result"
  \<comment> \<open>C++: \<open>bigMultiply\<close> (\<open>util/numeric.cpp\<close>)\<close>
  where
    "big_multiply a b =
      (if sint a < 0 \<or> sint b < 0 then
         Cxx_Err Cxx_Assertion_Failed
       else
         Cxx_Ok (word_of_int (sint a * sint b)))"

subsubsection \<open>Checked division\<close>

datatype cxx_rounding =
    Cxx_Round_Down
  | Cxx_Round_Up

fun rounded_quotient ::
    "int \<Rightarrow> int \<Rightarrow> cxx_rounding \<Rightarrow> int"
  where
    "rounded_quotient numerator divisor Cxx_Round_Down =
      numerator div divisor"
  | "rounded_quotient numerator divisor Cxx_Round_Up =
      (numerator + divisor - 1) div divisor"

text \<open>
  The two definitions below model the throwing public helpers
  \<open>bigDivideOrThrow\<close> and \<open>bigDivideOrThrow128\<close> from
  \<open>util/numeric.cpp\<close>.  The ordinary helper widens a product of signed 64-bit
  operands.  The 128-bit helper additionally preserves the explicit guard
  that prevents the numerator used for round-up from wrapping before
  division.
\<close>

definition big_divide_or_throw ::
    "int64 \<Rightarrow> int64 \<Rightarrow> int64 \<Rightarrow> cxx_rounding \<Rightarrow>
      int64 cxx_result"
  \<comment> \<open>C++: \<open>bigDivideOrThrow\<close> (\<open>util/numeric.cpp\<close>)\<close>
  where
    "big_divide_or_throw a b c rounding =
      (if sint a < 0 \<or> sint b < 0 \<or> sint c \<le> 0 then
         Cxx_Err Cxx_Assertion_Failed
       else
         let quotient =
           rounded_quotient (sint a * sint b) (sint c) rounding
         in if quotient > int64_max_int then
              Cxx_Err Cxx_Overflow
            else
              Cxx_Ok (word_of_int quotient))"

definition big_divide_or_throw128 ::
    "uint128 \<Rightarrow> int64 \<Rightarrow> cxx_rounding \<Rightarrow> int64 cxx_result"
  \<comment> \<open>C++: \<open>bigDivideOrThrow128\<close> (\<open>util/numeric.cpp\<close>)\<close>
  where
    "big_divide_or_throw128 a b rounding =
      (if sint b \<le> 0 then
         Cxx_Err Cxx_Assertion_Failed
       else if rounding = Cxx_Round_Up \<and>
           uint a > (2 :: int) ^ 128 - 1 - (sint b - 1) then
         Cxx_Err Cxx_Overflow
       else
         let quotient = rounded_quotient (uint a) (sint b) rounding
         in if quotient > int64_max_int then
              Cxx_Err Cxx_Overflow
            else
              Cxx_Ok (word_of_int quotient))"

subsubsection \<open>Price error bound\<close>

text \<open>
  The definition below is the direct model of \<open>checkPriceErrorBound\<close>
  (\<open>OfferExchange.cpp\<close>).  The C++ function first scales each signed
  32-bit price component by one
  hundred in signed 64-bit arithmetic.  It then compares two unsigned
  128-bit products.  If the caller permits unbounded error in favor of wheat,
  the favorable direction returns immediately; otherwise the absolute
  difference must be no greater than the unscaled wheat value.
\<close>

definition check_price_error_bound ::
    "int32 \<Rightarrow> int32 \<Rightarrow> int64 \<Rightarrow> int64 \<Rightarrow>
      bool \<Rightarrow> bool cxx_result"
  \<comment> \<open>C++: \<open>checkPriceErrorBound\<close> (\<open>OfferExchange.cpp\<close>)\<close>
  where
    "check_price_error_bound price_n price_d wheat_receive sheep_send
        can_favor_wheat = do {
       lhs \<leftarrow> big_multiply
         (word_of_int (100 * sint price_n)) wheat_receive;
       rhs \<leftarrow> big_multiply
         (word_of_int (100 * sint price_d)) sheep_send;
       if can_favor_wheat \<and> rhs > lhs then
         Cxx_Ok True
       else
         let abs_diff = (if lhs > rhs then lhs - rhs else rhs - lhs)
         in do {
           cap \<leftarrow> big_multiply (scast price_n) wheat_receive;
           Cxx_Ok (abs_diff \<le> cap)
         }
     }"

definition price_error_bound_spec ::
    "int32 \<Rightarrow> int32 \<Rightarrow> int64 \<Rightarrow> int64 \<Rightarrow> bool \<Rightarrow> bool"
  where
    "price_error_bound_spec price_n price_d wheat_receive sheep_send
        can_favor_wheat =
      (let lhs = 100 * sint price_n * sint wheat_receive;
           rhs = 100 * sint price_d * sint sheep_send;
           cap = sint price_n * sint wheat_receive
       in (can_favor_wheat \<and> rhs > lhs) \<or> abs (lhs - rhs) \<le> cap)"

text \<open>
  @{const price_error_bound_spec} is the intended mathematical reading of the
  bit-precise test above, stated over the exact integers denoted by the
  arguments rather than over 128-bit words.
\<close>

subsubsection \<open>Price-error application\<close>

datatype exchange_rounding =
    Exchange_Normal
  | Exchange_Strict_Send
  | Exchange_Strict_Receive

record exchange_options =
  exact_receive_cap :: bool
  symmetric_exact_receive_cap :: bool

text \<open>
  @{type exchange_options} groups protocol-gated choices passed through the
  exchange model.  A record literal such as
  @{term "\<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = False\<rparr>"}
  makes the selected behavior explicit at
  each call site and leaves room for additional options without adding more
  positional Boolean arguments.  The @{const exact_receive_cap} field models
  the C++ parameter \<open>exactReceiveCap\<close>, which repairs the sheep-stays,
  wheat-more-valuable normal branch; the
  @{const symmetric_exact_receive_cap} field models the C++ parameter
  \<open>symmetricExactReceiveCap\<close>, which applies the mirror-image repair to the
  wheat-stays, sheep-more-valuable normal branch.
\<close>

text \<open>
  The three constructors of @{type exchange_rounding} correspond to
  \<open>NORMAL\<close>, \<open>PATH_PAYMENT_STRICT_SEND\<close>, and
  \<open>PATH_PAYMENT_STRICT_RECEIVE\<close>.  The result record retains the two signed
  64-bit amount bit patterns and the unchanged decision about which offer
  remains.
\<close>

record exchange_result_v10 =
  num_wheat_received :: int64
  num_sheep_send :: int64
  result_wheat_stays :: bool

definition make_exchange_result ::
    "int64 \<Rightarrow> int64 \<Rightarrow> bool \<Rightarrow> exchange_result_v10"
  where
    "make_exchange_result wheat_receive sheep_send wheat_stays =
      \<lparr>num_wheat_received = wheat_receive,
       num_sheep_send = sheep_send,
       result_wheat_stays = wheat_stays\<rparr>"

definition favored_seller_ok ::
    "int32 \<Rightarrow> int32 \<Rightarrow> int64 \<Rightarrow> int64 \<Rightarrow> bool \<Rightarrow> bool"
  where
    "favored_seller_ok price_n price_d wheat_receive sheep_send wheat_stays =
      (let wheat_value = sint wheat_receive * sint price_n;
           sheep_value = sint sheep_send * sint price_d
       in if wheat_stays
          then wheat_value \<le> sheep_value
          else sheep_value \<le> wheat_value)"

text \<open>
  This definition follows the branch and mutation order of
  \<open>applyPriceErrorThresholds\<close>.  In particular, arithmetic assertions are
  reached only when both amounts are positive, and the non-positive
  strict-send branch tests the raw sheep word for zero exactly as C++ does.
\<close>

definition apply_price_error_thresholds ::
    "int32 \<Rightarrow> int32 \<Rightarrow> int64 \<Rightarrow> int64 \<Rightarrow> bool \<Rightarrow>
      exchange_rounding \<Rightarrow> exchange_result_v10 cxx_result"
  \<comment> \<open>C++: \<open>applyPriceErrorThresholds\<close> (\<open>OfferExchange.cpp\<close>)\<close>
  where
    "apply_price_error_thresholds price_n price_d wheat_receive sheep_send
        wheat_stays rounding =
      (if 0 < sint wheat_receive \<and> 0 < sint sheep_send then do {
         wheat_value \<leftarrow> big_multiply wheat_receive (scast price_n);
         sheep_value \<leftarrow> big_multiply sheep_send (scast price_d);
         if (wheat_stays \<and> sheep_value < wheat_value) \<or>
             (\<not> wheat_stays \<and> sheep_value > wheat_value)
         then Cxx_Err Cxx_Runtime_Error
         else if rounding = Exchange_Normal then do {
           within_bound \<leftarrow>
             check_price_error_bound price_n price_d wheat_receive sheep_send
               False;
           if within_bound
           then Cxx_Ok
             (make_exchange_result wheat_receive sheep_send wheat_stays)
           else Cxx_Ok (make_exchange_result 0 0 wheat_stays)
         } else do {
           within_bound \<leftarrow>
             check_price_error_bound price_n price_d wheat_receive sheep_send
               True;
           if within_bound
           then Cxx_Ok
             (make_exchange_result wheat_receive sheep_send wheat_stays)
           else Cxx_Err Cxx_Runtime_Error
         }
       } else if rounding = Exchange_Strict_Send then
         if sheep_send = 0
         then Cxx_Err Cxx_Runtime_Error
         else Cxx_Ok
           (make_exchange_result wheat_receive sheep_send wheat_stays)
       else Cxx_Ok (make_exchange_result 0 0 wheat_stays))"

definition apply_price_error_thresholds_spec ::
    "int32 \<Rightarrow> int32 \<Rightarrow> int64 \<Rightarrow> int64 \<Rightarrow> bool \<Rightarrow>
      exchange_rounding \<Rightarrow> exchange_result_v10 cxx_result"
  where
    "apply_price_error_thresholds_spec price_n price_d wheat_receive sheep_send
        wheat_stays rounding =
      (let original =
          make_exchange_result wheat_receive sheep_send wheat_stays;
         zero = make_exchange_result 0 0 wheat_stays
       in if \<not> (0 < sint wheat_receive \<and> 0 < sint sheep_send) then
            if rounding = Exchange_Strict_Send then
              if sheep_send = 0 then Cxx_Err Cxx_Runtime_Error
              else Cxx_Ok original
            else Cxx_Ok zero
          else if sint price_n < 0 \<or> sint price_d < 0 then
            Cxx_Err Cxx_Assertion_Failed
          else if \<not> favored_seller_ok price_n price_d wheat_receive sheep_send
              wheat_stays
          then Cxx_Err Cxx_Runtime_Error
          else if rounding = Exchange_Normal then
            Cxx_Ok
              (if price_error_bound_spec price_n price_d wheat_receive
                    sheep_send False
               then original else zero)
          else if price_error_bound_spec price_n price_d wheat_receive
              sheep_send True
          then Cxx_Ok original
          else Cxx_Err Cxx_Runtime_Error)"

text \<open>
  @{const apply_price_error_thresholds_spec} restates the same function as a
  single decision tree over exact integers, with no monadic sequencing left.
\<close>

subsubsection \<open>Offer value\<close>

text \<open>
  This is the direct model of \<open>calculateOfferValue\<close>.  The signed
  32-bit prices are sign-extended to the signed 64-bit arguments expected by
  @{const big_multiply}.  The final minimum uses the unsigned ordering on
  128-bit words, matching C++ \<open>std::min\<close> on \<open>uint128_t\<close>.
\<close>

definition calculate_offer_value ::
    "int32 \<Rightarrow> int32 \<Rightarrow> int64 \<Rightarrow>
      int64 \<Rightarrow> uint128 cxx_result"
  \<comment> \<open>C++: \<open>calculateOfferValue\<close> (\<open>OfferExchange.cpp\<close>)\<close>
  where
    "calculate_offer_value price_n price_d max_send max_receive = do {
       send_value \<leftarrow> big_multiply max_send (scast price_n);
       receive_value \<leftarrow> big_multiply max_receive (scast price_d);
       Cxx_Ok (min send_value receive_value)
     }"

definition calculate_offer_value_pre ::
    "int32 \<Rightarrow> int32 \<Rightarrow> int64 \<Rightarrow>
      int64 \<Rightarrow> bool"
  where
    "calculate_offer_value_pre price_n price_d max_send max_receive \<longleftrightarrow>
      0 \<le> sint price_n \<and> 0 \<le> sint price_d \<and>
      0 \<le> sint max_send \<and> 0 \<le> sint max_receive"

definition int64_max :: int64
  \<comment> \<open>C++: \<open>INT64_MAX\<close>\<close>
  where "int64_max = word_of_int (2 ^ 63 - 1)"

text \<open>
  @{const int64_max} has the bit pattern of the C++ constant \<open>INT64_MAX\<close>.
\<close>

definition calculate_offer_value_with_exact_receive_cap ::
    "int32 \<Rightarrow> int32 \<Rightarrow> int64 \<Rightarrow>
      int64 \<Rightarrow> uint128 cxx_result"
  \<comment> \<open>proof-only: the value stage of \<open>calculateOfferAmountFromValue\<close>
    (\<open>OfferExchange.cpp\<close>)\<close>
  where
    "calculate_offer_value_with_exact_receive_cap price_n price_d max_send
        max_receive = do {
       send_value \<leftarrow> big_multiply max_send (scast price_n);
       receive_product \<leftarrow> big_multiply max_receive (scast price_d);
       let receive_value = receive_product +
         ucast (scast (price_d - 1) :: int64);
       receive_cap \<leftarrow> big_multiply int64_max (scast price_d);
       Cxx_Ok (min send_value (min receive_value receive_cap))
     }"

text \<open>
  This is the value stage of \<open>calculateOfferAmountFromValue\<close>
  (\<open>OfferExchange.cpp\<close>), split out for proofs.  It is not itself a C++
  function: the implementation-facing model is
  \<open>calculate_offer_amount_from_value\<close> below, which performs this
  calculation and the final round-down division in one helper.  Compared with
  @{const calculate_offer_value}, the receive-side value is relaxed by
  @{term "sint price_d - 1"} before the caller rounds down, so a receive cap
  that is not an exact multiple of the price still admits the last fractional
  lot.  The addend models the C++ cast chain from \<open>priceD - 1\<close> through
  \<open>uint64_t\<close> to \<open>uint128_t\<close>: 32-bit subtraction, sign extension to 64
  bits, zero extension to 128 bits.  The subsequent minimum with
  @{term "big_multiply int64_max (scast price_d)"} restores the plain cap
  when the receive cap is \<open>INT64_MAX\<close>, keeping such offers fixed points of
  adjustment.
\<close>

definition calculate_offer_amount_from_value ::
    "int32 \<Rightarrow> int32 \<Rightarrow> int64 \<Rightarrow>
      int64 \<Rightarrow> int64 cxx_result"
  \<comment> \<open>C++: \<open>calculateOfferAmountFromValue\<close> (\<open>OfferExchange.cpp\<close>)\<close>
  where
    "calculate_offer_amount_from_value price_n price_d max_send
        max_receive = do {
       send_value \<leftarrow> big_multiply max_send (scast price_n);
       receive_product \<leftarrow> big_multiply max_receive (scast price_d);
       let receive_value = receive_product +
         ucast (scast (price_d - 1) :: int64);
       receive_cap \<leftarrow> big_multiply int64_max (scast price_d);
       let capped_receive_value = min receive_value receive_cap;
       let offer_value = min send_value capped_receive_value;
       big_divide_or_throw128 offer_value (scast price_n) Cxx_Round_Down
     }"

text \<open>
  This is the direct model of \<open>calculateOfferAmountFromValue\<close>
  (\<open>OfferExchange.cpp\<close>), the helper introduced for protocol 29.  It keeps the
  C++ sequencing: the send-side product, the receive-side product relaxed by
  \<open>priceD - 1\<close> through the cast chain \<open>int32_t\<close> to \<open>uint64_t\<close> to
  \<open>uint128_t\<close>, the saturation clamp by
  @{term "big_multiply int64_max (scast price_d)"}, the minimum of the send
  and capped receive values, and the final round-down division by
  @{term "sint price_n"}.

  Returning the amount rather than the value is the one structural change
  protocol 29 makes to this part of the arithmetic.  It exists because the
  receive cap a resting offer imposes on itself is its own buying liability
  @{term "(price_n * amount) div price_d"}, and dividing that by the price again
  rounds down a second time, which can lose one unit.  Relaxing the receive
  product by @{term "sint price_d - 1"} before the single round-down division
  compensates for exactly that lost unit, while the clamp keeps an
  \<open>INT64_MAX\<close> receive cap behaving as before.
\<close>

lemma calculate_offer_amount_from_value_eq_value_then_divide [simp]:
  "calculate_offer_amount_from_value price_n price_d max_send max_receive =
     (calculate_offer_value_with_exact_receive_cap price_n price_d max_send
        max_receive \<bind>
      (\<lambda>offer_value.
        big_divide_or_throw128 offer_value (scast price_n) Cxx_Round_Down))"
  \<comment> \<open>The protocol-29 helper is exactly the relaxed offer value followed by
    the round-down division the caller used to perform.\<close>
  text \<open>
    Proof sketch: both sides run the same three multiplications and form the
    same minimum.  They differ only in where the division is sequenced, so
    unfolding the two definitions and reassociating the binds with
    @{thm [source] cxx_bind_assoc} makes them syntactically equal.
  \<close>
  by (simp add: calculate_offer_amount_from_value_def
      calculate_offer_value_with_exact_receive_cap_def Let_def cxx_bind_assoc)

text \<open>
  This equation is the bridge that carries the existing repaired-arithmetic
  results to the protocol-29 interface.  Every proof phrased in terms of the
  relaxed value followed by a division applies verbatim to
  @{const calculate_offer_amount_from_value}, so the protocol-29 helper needs
  no separate development of the underlying arithmetic.

  It is declared a simplification rule so that the existing repaired
  development continues to apply unchanged.  The helper remains the
  implementation-facing definition, and the one exported for code generation,
  because it is what protocol 29 actually computes; the decomposition into a
  relaxed value and a division is a proof device only.
\<close>

subsubsection \<open>Protocol-29 amount examples\<close>

text \<open>
  The examples below are the boundary cases cited by the protocol-29 change
  (stellar-core commit \<open>cb257d2810\<close>), evaluated in the model.  Each
  pairs the protocol-29 helper with the protocol-28 calculation it replaces,
  so the intended change of behavior is explicit and executable.

  A resting offer of \<open>2999\<close> units at price \<open>3/2\<close> books a buying liability of
  @{term "(3 * 2999) div 2"}, that is \<open>4498\<close>.  Re-deriving the amount from
  that liability is exactly the round trip protocol 29 repairs: protocol 28
  returns \<open>2998\<close>, silently shrinking an offer that nothing had consumed,
  while protocol 29 returns the stored \<open>2999\<close>.
\<close>

lemma p29_amount_recovers_offer_at_its_own_buying_liability:
  "calculate_offer_amount_from_value 3 2 2999 4498 = Cxx_Ok 2999"
  by eval

lemma p28_amount_loses_a_unit_at_its_own_buying_liability:
  "(calculate_offer_value 3 2 2999 4498 \<bind>
     (\<lambda>offer_value.
       big_divide_or_throw128 offer_value 3 Cxx_Round_Down)) =
   Cxx_Ok 2998"
  by eval

text \<open>
  The adjustment example uses price \<open>7/3\<close> with a send cap of \<open>428\<close> and a
  receive cap of \<open>998\<close>.  The plain send and receive values are \<open>2996\<close> and
  \<open>2994\<close>, so protocol 28 divides \<open>2994\<close> and returns \<open>427\<close>; protocol 29
  relaxes the receive product to \<open>2996\<close> and returns \<open>428\<close>.
\<close>

lemma p29_adjustment_keeps_the_full_send_cap:
  "calculate_offer_amount_from_value 7 3 428 998 = Cxx_Ok 428"
  by eval

lemma p28_adjustment_reduces_the_send_cap:
  "(calculate_offer_value 7 3 428 998 \<bind>
     (\<lambda>offer_value.
       big_divide_or_throw128 offer_value 7 Cxx_Round_Down)) =
   Cxx_Ok 427"
  by eval

text \<open>
  At an unlimited receive cap the retained clamp makes the two protocols
  agree, which is the property the liability definitions rely on.
\<close>

lemma p29_amount_agrees_with_p28_at_unlimited_receive_cap:
  "calculate_offer_amount_from_value 3 2 2999 int64_max = Cxx_Ok 2999"
  "(calculate_offer_value 3 2 2999 int64_max \<bind>
     (\<lambda>offer_value.
       big_divide_or_throw128 offer_value 3 Cxx_Round_Down)) =
   Cxx_Ok 2999"
  by eval+

subsubsection \<open>Exchange before price-error thresholds\<close>

definition signed_min64 :: "int64 \<Rightarrow> int64 \<Rightarrow> int64"
  \<comment> \<open>C++: \<open>std::min\<close> on \<open>int64_t\<close>\<close>
  where
    "signed_min64 a b = (if sint a \<le> sint b then a else b)"

text \<open>
  @{const signed_min64} models C++ \<open>std::min\<close> on \<open>int64_t\<close> operands: the
  minimum of the two bit patterns in the signed order.
\<close>

definition exchange_v10_amounts ::
    "int32 \<Rightarrow> int32 \<Rightarrow> uint128 \<Rightarrow> uint128 \<Rightarrow>
      int64 \<Rightarrow> int64 \<Rightarrow> int64 \<Rightarrow> int64 \<Rightarrow> bool \<Rightarrow>
      exchange_rounding \<Rightarrow> exchange_options \<Rightarrow>
      (int64 \<times> int64) cxx_result"
  \<comment> \<open>C++: calculation block of \<open>exchangeV10WithoutPriceErrorThresholds\<close>
    (\<open>OfferExchange.cpp\<close>)\<close>
  where
    "exchange_v10_amounts price_n price_d wheat_value sheep_value
        max_wheat_send max_wheat_receive max_sheep_send max_sheep_receive
        wheat_stays rounding options =
      (if wheat_stays then
         if rounding = Exchange_Strict_Send then do {
           wheat_receive \<leftarrow> big_divide_or_throw128 sheep_value
             (scast price_n) Cxx_Round_Down;
           Cxx_Ok
             (wheat_receive, signed_min64 max_sheep_send max_sheep_receive)
         } else if sint price_n > sint price_d \<or>
             rounding = Exchange_Strict_Receive
         then do {
           wheat_receive \<leftarrow> big_divide_or_throw128 sheep_value
             (scast price_n) Cxx_Round_Down;
           sheep_send \<leftarrow> big_divide_or_throw wheat_receive
             (scast price_n) (scast price_d) Cxx_Round_Up;
           Cxx_Ok (wheat_receive, sheep_send)
         } else do {
           sheep_send \<leftarrow>
             (if symmetric_exact_receive_cap options
              then calculate_offer_amount_from_value price_d price_n
                max_sheep_send max_wheat_receive
              else big_divide_or_throw128 sheep_value
                (scast price_d) Cxx_Round_Down);
           wheat_receive \<leftarrow> big_divide_or_throw sheep_send
             (scast price_d) (scast price_n) Cxx_Round_Down;
           Cxx_Ok (wheat_receive, sheep_send)
         }
       else if sint price_n > sint price_d then do {
         wheat_receive \<leftarrow>
           (if exact_receive_cap options
            then calculate_offer_amount_from_value price_n price_d
              max_wheat_send max_sheep_receive
            else big_divide_or_throw128 wheat_value
              (scast price_n) Cxx_Round_Down);
         sheep_send \<leftarrow> big_divide_or_throw wheat_receive
           (scast price_n) (scast price_d) Cxx_Round_Down;
         Cxx_Ok (wheat_receive, sheep_send)
       } else do {
         sheep_send \<leftarrow> big_divide_or_throw128 wheat_value
           (scast price_d) Cxx_Round_Down;
         wheat_receive \<leftarrow> big_divide_or_throw sheep_send
           (scast price_d) (scast price_n) Cxx_Round_Up;
         Cxx_Ok (wheat_receive, sheep_send)
       })"


text \<open>
  @{const exchange_v10_amounts} is the \<open>wheatReceive\<close>/\<open>sheepSend\<close>
  calculation block of
  \<open>exchangeV10WithoutPriceErrorThresholds\<close> (\<open>OfferExchange.cpp\<close>).  Separating the tuple-valued block
  lets the top-level model retain the C++ sequencing while local proofs analyze
  each division branch independently.  The final options argument carries the
  two C++ parameters \<open>exactReceiveCap\<close> and \<open>symmetricExactReceiveCap\<close>.  When
  @{const exact_receive_cap} is set and the sheep offer stays with wheat the
  more valuable asset, the trade is valued by
  @{const calculate_offer_value_with_exact_receive_cap} applied to the resting
  wheat offer's send and receive caps instead of the plain wheat value, exactly
  as in the C++ conditional expression.  When
  @{const symmetric_exact_receive_cap} is set and the wheat offer stays with
  sheep at least as valuable, the mirror call
  @{term "calculate_offer_value_with_exact_receive_cap price_d price_n
    max_sheep_send max_wheat_receive"} replaces the plain sheep value, so the
  taker's wheat-receive cap is treated as an exact unit cap before the
  round-down division by @{term "sint price_d"}.  Both branches keep
  \<open>wheatStays\<close> decided on the two unadjusted offer values.
\<close>

definition exchange_v10_without_price_error_thresholds_with_options ::
    "int32 \<Rightarrow> int32 \<Rightarrow> int64 \<Rightarrow> int64 \<Rightarrow> int64 \<Rightarrow>
      int64 \<Rightarrow> exchange_rounding \<Rightarrow> exchange_options \<Rightarrow>
      exchange_result_v10 cxx_result"
  \<comment> \<open>C++: \<open>exchangeV10WithoutPriceErrorThresholds\<close> (\<open>OfferExchange.cpp\<close>)\<close>
  where
    "exchange_v10_without_price_error_thresholds_with_options price_n price_d
        max_wheat_send max_wheat_receive max_sheep_send max_sheep_receive
        rounding options = do {
      wheat_value \<leftarrow> calculate_offer_value price_n price_d
        max_wheat_send max_sheep_receive;
      sheep_value \<leftarrow> calculate_offer_value price_d price_n
        max_sheep_send max_wheat_receive;
      let wheat_stays = wheat_value > sheep_value;
      amounts \<leftarrow> exchange_v10_amounts price_n price_d wheat_value sheep_value
        max_wheat_send max_wheat_receive max_sheep_send max_sheep_receive
        wheat_stays rounding options;
      let wheat_receive = fst amounts;
      let sheep_send = snd amounts;
      if sint wheat_receive < 0 \<or>
          sint wheat_receive >
            min (sint max_wheat_receive) (sint max_wheat_send)
      then Cxx_Err Cxx_Runtime_Error
      else if sint sheep_send < 0 \<or>
          sint sheep_send >
            min (sint max_sheep_receive) (sint max_sheep_send)
      then Cxx_Err Cxx_Runtime_Error
      else Cxx_Ok
        (make_exchange_result wheat_receive sheep_send wheat_stays)
    }"

text \<open>
  @{const exchange_v10_without_price_error_thresholds_with_options} is the direct model of
  \<open>exchangeV10WithoutPriceErrorThresholds\<close> (\<open>OfferExchange.cpp\<close>): the
  two offer values, the retained-offer decision, the branch block modeled by
  @{const exchange_v10_amounts}, and the final bounds checks on both amounts.
\<close>

definition check_exchange_v10_result ::
    "int64 \<Rightarrow> int64 \<Rightarrow> int64 \<Rightarrow> int64 \<Rightarrow> bool \<Rightarrow>
      (int64 \<times> int64) \<Rightarrow> exchange_result_v10 cxx_result"
  \<comment> \<open>C++: bounds checks of \<open>exchangeV10WithoutPriceErrorThresholds\<close>
    (\<open>OfferExchange.cpp\<close>)\<close>
  where
    "check_exchange_v10_result max_wheat_send max_wheat_receive max_sheep_send
        max_sheep_receive wheat_stays amounts =
      (let wheat_receive = fst amounts;
           sheep_send = snd amounts
       in if sint wheat_receive < 0 \<or>
             sint wheat_receive >
               min (sint max_wheat_receive) (sint max_wheat_send)
          then Cxx_Err Cxx_Runtime_Error
          else if sint sheep_send < 0 \<or>
             sint sheep_send >
               min (sint max_sheep_receive) (sint max_sheep_send)
          then Cxx_Err Cxx_Runtime_Error
          else Cxx_Ok
            (make_exchange_result wheat_receive sheep_send wheat_stays))"

text \<open>
  @{const check_exchange_v10_result} restates the final bounds checks of
  \<open>exchangeV10WithoutPriceErrorThresholds\<close> (\<open>OfferExchange.cpp\<close>)
  as a separate function so that the specification
  below can reuse them verbatim.
\<close>

definition exchange_v10_without_price_error_thresholds_spec ::
    "int32 \<Rightarrow> int32 \<Rightarrow> int64 \<Rightarrow> int64 \<Rightarrow> int64 \<Rightarrow>
      int64 \<Rightarrow> exchange_rounding \<Rightarrow> exchange_options \<Rightarrow>
      exchange_result_v10 cxx_result"
  where
    "exchange_v10_without_price_error_thresholds_spec price_n price_d
        max_wheat_send max_wheat_receive max_sheep_send max_sheep_receive
        rounding options =
      (if calculate_offer_value_pre price_n price_d max_wheat_send
            max_sheep_receive \<and>
          calculate_offer_value_pre price_d price_n max_sheep_send
            max_wheat_receive
       then
         let wheat_value =
           min
             (word_of_int (sint max_wheat_send * sint price_n) ::
               uint128)
             (word_of_int (sint max_sheep_receive * sint price_d));
             sheep_value =
           min
             (word_of_int (sint max_sheep_send * sint price_d) ::
               uint128)
             (word_of_int (sint max_wheat_receive * sint price_n));
             wheat_stays = wheat_value > sheep_value
         in exchange_v10_amounts price_n price_d wheat_value sheep_value
              max_wheat_send max_wheat_receive max_sheep_send
              max_sheep_receive wheat_stays rounding options \<bind>
            check_exchange_v10_result max_wheat_send max_wheat_receive
              max_sheep_send max_sheep_receive wheat_stays
       else Cxx_Err Cxx_Assertion_Failed)"

text \<open>
  The remaining definitions of this subsection describe the same calculation
  at the level of unbounded integers.
\<close>

definition exchange_v10_pre ::
    "int32 \<Rightarrow> int32 \<Rightarrow> int64 \<Rightarrow> int64 \<Rightarrow> int64 \<Rightarrow>
      int64 \<Rightarrow> bool"
  where
    "exchange_v10_pre price_n price_d max_wheat_send max_wheat_receive
        max_sheep_send max_sheep_receive \<longleftrightarrow>
      0 < sint price_n \<and> 0 < sint price_d \<and>
      0 \<le> sint max_wheat_send \<and> 0 \<le> sint max_wheat_receive \<and>
      0 \<le> sint max_sheep_send \<and> 0 \<le> sint max_sheep_receive"

definition exchange_wheat_value_int ::
    "int32 \<Rightarrow> int32 \<Rightarrow> int64 \<Rightarrow> int64 \<Rightarrow> int"
  where
    "exchange_wheat_value_int price_n price_d max_wheat_send
        max_sheep_receive =
      min (sint max_wheat_send * sint price_n)
        (sint max_sheep_receive * sint price_d)"

definition exchange_sheep_value_int ::
    "int32 \<Rightarrow> int32 \<Rightarrow> int64 \<Rightarrow> int64 \<Rightarrow> int"
  where
    "exchange_sheep_value_int price_n price_d max_sheep_send
        max_wheat_receive =
      min (sint max_sheep_send * sint price_d)
        (sint max_wheat_receive * sint price_n)"

definition exchange_v10_amounts_int ::
    "int32 \<Rightarrow> int32 \<Rightarrow> int64 \<Rightarrow> int64 \<Rightarrow> int64 \<Rightarrow>
      int64 \<Rightarrow> exchange_rounding \<Rightarrow> int \<times> int"
  where
    "exchange_v10_amounts_int price_n price_d max_wheat_send
        max_wheat_receive max_sheep_send max_sheep_receive rounding =
      (let wheat_value =
          exchange_wheat_value_int price_n price_d max_wheat_send
            max_sheep_receive;
         sheep_value =
          exchange_sheep_value_int price_n price_d max_sheep_send
            max_wheat_receive;
         wheat_stays = wheat_value > sheep_value
       in if wheat_stays then
            if rounding = Exchange_Strict_Send then
              (sheep_value div sint price_n,
               min (sint max_sheep_send) (sint max_sheep_receive))
            else if sint price_n > sint price_d \<or>
                rounding = Exchange_Strict_Receive
            then
              let wheat_receive = sheep_value div sint price_n
              in (wheat_receive,
                  (wheat_receive * sint price_n + sint price_d - 1)
                    div sint price_d)
            else
              let sheep_send = sheep_value div sint price_d
              in ((sheep_send * sint price_d) div sint price_n, sheep_send)
          else if sint price_n > sint price_d then
            let wheat_receive = wheat_value div sint price_n
            in (wheat_receive,
                (wheat_receive * sint price_n) div sint price_d)
          else
            let sheep_send = wheat_value div sint price_d
            in ((sheep_send * sint price_d + sint price_n - 1)
                  div sint price_n,
                sheep_send))"

text \<open>
  @{const exchange_v10_pre} is the precondition under which the model is
  claimed to be free of assertions and overflow, and
  @{const exchange_v10_amounts_int} is the pair of amounts that the
  calculation is then claimed to produce.
\<close>

subsubsection \<open>Full exchange\<close>

definition exchange_v10_with_options ::
    "int32 \<Rightarrow> int32 \<Rightarrow> int64 \<Rightarrow> int64 \<Rightarrow> int64 \<Rightarrow>
      int64 \<Rightarrow> exchange_rounding \<Rightarrow> exchange_options \<Rightarrow>
      exchange_result_v10 cxx_result"
  \<comment> \<open>C++: \<open>exchangeV10\<close> (\<open>OfferExchange.cpp\<close>)\<close>
  where
    "exchange_v10_with_options price_n price_d max_wheat_send max_wheat_receive
        max_sheep_send max_sheep_receive rounding options = do {
      before_thresholds \<leftarrow>
        exchange_v10_without_price_error_thresholds_with_options price_n price_d
          max_wheat_send max_wheat_receive max_sheep_send max_sheep_receive
          rounding options;
      apply_price_error_thresholds price_n price_d
        (num_wheat_received before_thresholds)
        (num_sheep_send before_thresholds)
        (result_wheat_stays before_thresholds) rounding
    }"

text \<open>
  @{const exchange_v10_with_options} is the direct model of \<open>exchangeV10\<close>
  (\<open>OfferExchange.cpp\<close>).  Its monadic bind preserves the C++ call order and
  propagates every explicit error from the pre-threshold calculation before
  invoking @{const apply_price_error_thresholds}.  The trailing options record
  carries the C++ parameter \<open>exactReceiveCap\<close> and is forwarded unchanged to
  the pre-threshold calculation; the threshold pass never inspects it.
\<close>


subsubsection \<open>Protocol-facing exchange interface\<close>

text \<open>
  The definitions above are option-parametric proof kernels.  They are useful
  because a proof about all four option settings covers both real protocols
  and two diagnostic mutants at once, but the settings are not themselves
  protocol versions.  The layer below is the implementation-facing interface:
  it mirrors the C++ signatures, which take a ledger version, and maps that
  version onto exactly one of the two configurations the protocol can be in.
\<close>

type_synonym uint32 = "32 word"

definition protocol_version_starts_from :: "uint32 \<Rightarrow> uint32 \<Rightarrow> bool"
  \<comment> \<open>C++: \<open>protocolVersionStartsFrom\<close> (\<open>util/ProtocolVersion.cpp\<close>)\<close>
  where
    "protocol_version_starts_from protocol_version from_version \<longleftrightarrow>
       uint from_version \<le> uint protocol_version"

text \<open>
  The C++ ledger version is a \<open>uint32_t\<close> and the comparison
  \<open>protocolVersion >= static_cast<uint32_t>(fromVersion)\<close> is therefore
  unsigned.  The model uses @{const uint}, not @{const sint}, so a version
  with the high bit set compares as a large version rather than a negative
  one, exactly as in C++.
\<close>

definition protocol_version_v29 :: uint32
  \<comment> \<open>C++: \<open>ProtocolVersion::V\<^bold>_29\<close> (\<open>util/ProtocolVersion.h\<close>)\<close>
  where "protocol_version_v29 = 29"

definition legacy_exchange_options :: exchange_options
  where
    "legacy_exchange_options =
      \<lparr>exact_receive_cap = False,
       symmetric_exact_receive_cap = False\<rparr>"

definition repaired_exchange_options :: exchange_options
  where
    "repaired_exchange_options =
      \<lparr>exact_receive_cap = True,
       symmetric_exact_receive_cap = True\<rparr>"

definition exchange_options_at_version :: "uint32 \<Rightarrow> exchange_options"
  where
    "exchange_options_at_version ledger_version =
       (if protocol_version_starts_from ledger_version protocol_version_v29
        then repaired_exchange_options
        else legacy_exchange_options)"

text \<open>
  @{const exchange_options_at_version} is the whole protocol mapping.  Ledger
  versions below 29 select the legacy consensus arithmetic; version 29 and
  later select the repaired arithmetic, in which both round-down branches use
  @{const calculate_offer_amount_from_value}.  The two mixed configurations
  are proof mutants: they are reachable in the kernel but not through this
  mapping, as recorded below.
\<close>

definition exchange_v10_without_price_error_thresholds ::
    "uint32 \<Rightarrow> int32 \<Rightarrow> int32 \<Rightarrow> int64 \<Rightarrow> int64 \<Rightarrow>
      int64 \<Rightarrow> int64 \<Rightarrow> exchange_rounding \<Rightarrow>
      exchange_result_v10 cxx_result"
  \<comment> \<open>C++: \<open>exchangeV10WithoutPriceErrorThresholds\<close>
    (\<open>OfferExchange.cpp\<close>)\<close>
  where
    "exchange_v10_without_price_error_thresholds ledger_version price_n
        price_d max_wheat_send max_wheat_receive max_sheep_send
        max_sheep_receive rounding =
       exchange_v10_without_price_error_thresholds_with_options price_n price_d
         max_wheat_send max_wheat_receive max_sheep_send max_sheep_receive
         rounding (exchange_options_at_version ledger_version)"

definition exchange_v10 ::
    "uint32 \<Rightarrow> int32 \<Rightarrow> int32 \<Rightarrow> int64 \<Rightarrow> int64 \<Rightarrow>
      int64 \<Rightarrow> int64 \<Rightarrow> exchange_rounding \<Rightarrow>
      exchange_result_v10 cxx_result"
  \<comment> \<open>C++: \<open>exchangeV10\<close> (\<open>OfferExchange.cpp\<close>)\<close>
  where
    "exchange_v10 ledger_version price_n price_d max_wheat_send
        max_wheat_receive max_sheep_send max_sheep_receive rounding =
       exchange_v10_with_options price_n price_d max_wheat_send
         max_wheat_receive max_sheep_send max_sheep_receive rounding
         (exchange_options_at_version ledger_version)"

text \<open>
  These two definitions have the argument lists of the C++ functions as
  protocol 29 leaves them: a leading \<open>uint32_t\<close> ledger version, then the price, the four
  caps, and the rounding mode.  Everything below the interface is unchanged,
  so the reduction theorems that follow let every existing option-parametric
  result be specialized to a real protocol.
\<close>

lemma exchange_options_at_version_legacy [simp]:
  "\<not> protocol_version_starts_from ledger_version protocol_version_v29 \<Longrightarrow>
   exchange_options_at_version ledger_version = legacy_exchange_options"
  by (simp add: exchange_options_at_version_def)

lemma exchange_options_at_version_repaired [simp]:
  "protocol_version_starts_from ledger_version protocol_version_v29 \<Longrightarrow>
   exchange_options_at_version ledger_version = repaired_exchange_options"
  by (simp add: exchange_options_at_version_def)

lemma exchange_v10_without_price_error_thresholds_legacy:
  "\<not> protocol_version_starts_from ledger_version protocol_version_v29 \<Longrightarrow>
   exchange_v10_without_price_error_thresholds ledger_version price_n price_d
     max_wheat_send max_wheat_receive max_sheep_send max_sheep_receive
     rounding =
   exchange_v10_without_price_error_thresholds_with_options price_n price_d
     max_wheat_send max_wheat_receive max_sheep_send max_sheep_receive
     rounding legacy_exchange_options"
  by (simp add: exchange_v10_without_price_error_thresholds_def)

lemma exchange_v10_without_price_error_thresholds_repaired:
  "protocol_version_starts_from ledger_version protocol_version_v29 \<Longrightarrow>
   exchange_v10_without_price_error_thresholds ledger_version price_n price_d
     max_wheat_send max_wheat_receive max_sheep_send max_sheep_receive
     rounding =
   exchange_v10_without_price_error_thresholds_with_options price_n price_d
     max_wheat_send max_wheat_receive max_sheep_send max_sheep_receive
     rounding repaired_exchange_options"
  by (simp add: exchange_v10_without_price_error_thresholds_def)

lemma exchange_v10_legacy:
  "\<not> protocol_version_starts_from ledger_version protocol_version_v29 \<Longrightarrow>
   exchange_v10 ledger_version price_n price_d max_wheat_send
     max_wheat_receive max_sheep_send max_sheep_receive rounding =
   exchange_v10_with_options price_n price_d max_wheat_send max_wheat_receive
     max_sheep_send max_sheep_receive rounding legacy_exchange_options"
  by (simp add: exchange_v10_def)

lemma exchange_v10_repaired:
  "protocol_version_starts_from ledger_version protocol_version_v29 \<Longrightarrow>
   exchange_v10 ledger_version price_n price_d max_wheat_send
     max_wheat_receive max_sheep_send max_sheep_receive rounding =
   exchange_v10_with_options price_n price_d max_wheat_send max_wheat_receive
     max_sheep_send max_sheep_receive rounding repaired_exchange_options"
  by (simp add: exchange_v10_def)

text \<open>
  The four lemmas above are the protocol reduction theorems.  Protocol 28 and
  earlier reduce to the legacy kernel and protocol 29 and later to the
  repaired kernel, so protocol-28 preservation is a theorem about the public
  interface rather than an appeal to test evidence.
\<close>

lemma protocol_boundary_is_at_29:
  "exchange_options_at_version 28 = legacy_exchange_options"
  "exchange_options_at_version 29 = repaired_exchange_options"
  \<comment> \<open>The boundary sits exactly between ledger versions 28 and 29.\<close>
  by (simp_all add: exchange_options_at_version_def
      protocol_version_starts_from_def protocol_version_v29_def)

lemma mixed_exchange_options_are_unreachable:
  "exchange_options_at_version ledger_version \<noteq>
     \<lparr>exact_receive_cap = True, symmetric_exact_receive_cap = False\<rparr>"
  "exchange_options_at_version ledger_version \<noteq>
     \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = True\<rparr>"
  \<comment> \<open>No ledger version selects a one-sided repair.\<close>
  text \<open>
    Proof sketch: the mapping returns one of only two records, and neither
    agrees with a mixed one on both fields, so unfolding the definitions and
    splitting on the version test closes both goals.
  \<close>
  by (simp_all add: exchange_options_at_version_def legacy_exchange_options_def
      repaired_exchange_options_def)

text \<open>
  The two single-option configurations remain available to proofs as mutants
  and counterexample witnesses, but no ledger version reaches them.  Any
  claim about protocol behavior must therefore be stated through
  @{const exchange_options_at_version}.
\<close>


subsubsection \<open>Main properties\<close>

text \<open>
  This subsection collects the properties that the rest of the theory
  establishes about the model above.  Each is stated here informally, together
  with the proposition that is actually proved; the proofs follow, one section
  per modeled function.

  \<^bold>\<open>Faithfulness.\<close>  Every modeled C++ function is shown equal, on all bit
  patterns, to a branch-free specification phrased in exact integers.  The
  smallest instance is the offer value:
  @{term [display]
    "calculate_offer_value price_n price_d max_send max_receive =
      (if calculate_offer_value_pre price_n price_d max_send max_receive
       then Cxx_Ok
         (min
           (word_of_int (sint max_send * sint price_n) :: uint128)
           (word_of_int (sint max_receive * sint price_d)))
       else Cxx_Err Cxx_Assertion_Failed)"}
  The analogous statements for @{const big_divide_or_throw},
  @{const big_divide_or_throw128}, @{const check_price_error_bound},
  @{const apply_price_error_thresholds}, and
  @{const exchange_v10_without_price_error_thresholds_with_options} are proved in their own
  sections.

  \<^bold>\<open>Absence of arithmetic failure.\<close>  Under @{const exchange_v10_pre} the whole
  pre-threshold calculation is total: no assertion fails, no 128-bit numerator
  wraps, and no quotient escapes the signed 64-bit range.  What it computes is
  exactly @{const exchange_v10_amounts_int}, evaluated in unbounded integers,
  so the model of @{const exchange_v10_with_options} reduces to
  @{term [display]
    "apply_price_error_thresholds price_n price_d
      (word_of_int
        (fst (exchange_v10_amounts_int price_n price_d max_wheat_send
                max_wheat_receive max_sheep_send max_sheep_receive rounding)))
      (word_of_int
        (snd (exchange_v10_amounts_int price_n price_d max_wheat_send
                max_wheat_receive max_sheep_send max_sheep_receive rounding)))
      (exchange_wheat_value_int price_n price_d max_wheat_send
         max_sheep_receive >
       exchange_sheep_value_int price_n price_d max_sheep_send
         max_wheat_receive)
      rounding"}

  \<^bold>\<open>Result contract.\<close>  Whenever @{const exchange_v10_with_options} succeeds with the
  plain receive cap, both returned amounts are non-negative and respect the
  four caps, and the retained-offer flag is decided by the two offer values:
  @{term [display]
    "exchange_v10_pre price_n price_d max_wheat_send max_wheat_receive
        max_sheep_send max_sheep_receive \<and>
      exchange_v10_with_options price_n price_d max_wheat_send max_wheat_receive
        max_sheep_send max_sheep_receive rounding
        \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr> =
          Cxx_Ok exchange_result \<longrightarrow>
     0 \<le> sint (num_wheat_received exchange_result) \<and>
     sint (num_wheat_received exchange_result) \<le>
       min (sint max_wheat_receive) (sint max_wheat_send) \<and>
     0 \<le> sint (num_sheep_send exchange_result) \<and>
     sint (num_sheep_send exchange_result) \<le>
       min (sint max_sheep_receive) (sint max_sheep_send)"}

  \<^bold>\<open>Contract of a positive trade.\<close>  When the returned amounts are both
  positive, the party whose offer is kept is never disadvantaged, and the
  trade respects the price error bound appropriate to the rounding mode:
  @{term [display]
    "favored_seller_ok price_n price_d
       (num_wheat_received exchange_result)
       (num_sheep_send exchange_result)
       (result_wheat_stays exchange_result) \<and>
     (if rounding = Exchange_Normal
      then price_error_bound_spec price_n price_d
        (num_wheat_received exchange_result)
        (num_sheep_send exchange_result) False
      else price_error_bound_spec price_n price_d
        (num_wheat_received exchange_result)
        (num_sheep_send exchange_result) True)"}
  Outside strict-send mode the two amounts are moreover zero together, so a
  successful call either trades on both sides or trades nothing.


  The properties of this subsection are stated and
  proved for the plain receive cap, matching the protocol versions the C++
  has shipped with; their \<open>exactReceiveCap\<close> counterparts are future work.
\<close>

subsection \<open>Wide multiplication\<close>

text \<open>
  The lemmas below characterize the outcomes of @{const big_multiply} and
  record that its successful result is the exact integer product.
\<close>

lemma big_multiply_nonnegative [simp]:
  assumes "0 \<le> sint a" and "0 \<le> sint b"
  shows "big_multiply a b =
    Cxx_Ok (word_of_int (sint a * sint b))"
  using assms by (simp add: big_multiply_def)

lemma big_multiply_negative_left [simp]:
  assumes "sint a < 0"
  shows "big_multiply a b = Cxx_Err Cxx_Assertion_Failed"
  using assms by (simp add: big_multiply_def)

lemma big_multiply_negative_right [simp]:
  assumes "sint b < 0"
  shows "big_multiply a b = Cxx_Err Cxx_Assertion_Failed"
  using assms by (simp add: big_multiply_def)

lemma nonnegative_int64_product_fits_uint128:
  fixes a b :: int64
  assumes a_nonnegative: "0 \<le> sint a"
      and b_nonnegative: "0 \<le> sint b"
  shows "0 \<le> sint a * sint b"
    and "sint a * sint b < (2 :: int) ^ 128"
proof -
  show "0 \<le> sint a * sint b"
    using a_nonnegative b_nonnegative by simp
  have a_bound: "sint a < (2 :: int) ^ 63"
    using sint_lt [of a] by simp
  have b_bound: "sint b < (2 :: int) ^ 63"
    using sint_lt [of b] by simp
  have "sint a * sint b < (2 :: int) ^ 63 * 2 ^ 63"
    using a_bound b_bound b_nonnegative
    by (intro mult_strict_mono) simp_all
  also have "... < (2 :: int) ^ 128"
    by simp
  finally show "sint a * sint b < (2 :: int) ^ 128" .
qed

lemma big_multiply_uint_value:
  fixes a b :: int64
  assumes "0 \<le> sint a" and "0 \<le> sint b"
  shows "uint (word_of_int (sint a * sint b) :: uint128) =
    sint a * sint b"
proof -
  have bounds: "0 \<le> sint a * sint b"
    "sint a * sint b < (2 :: int) ^ 128"
    using nonnegative_int64_product_fits_uint128 assms by blast+
  have "uint (word_of_int (sint a * sint b) :: uint128) =
      (sint a * sint b) mod (2 :: int) ^ 128"
    by (simp only: uint_word_of_int; simp)
  also have "... = sint a * sint b"
    using bounds by (rule mod_pos_pos_trivial)
  finally show ?thesis .
qed

lemma sint_scast_int32_int64 [simp]:
  "sint (scast x :: int64) = sint (x :: int32)"
  by (rule sint_up_scast) (simp add: is_up)

subsection \<open>Checked division\<close>

text \<open>
  The lemmas below determine, for every bit pattern, which of the three
  outcomes of @{const big_divide_or_throw} and @{const big_divide_or_throw128}
  occurs, and they identify the word returned on success with the exact
  rounded quotient.
\<close>

lemma rounded_quotient_nonnegative:
  assumes numerator_nonnegative: "0 \<le> numerator"
      and divisor_positive: "0 < divisor"
  shows "0 \<le> rounded_quotient numerator divisor rounding"
  text \<open>
    Proof sketch: split on the rounding constructor.  The round-down
    numerator is non-negative directly; the round-up numerator remains
    non-negative because the positive divisor is at least one.  Integer
    division by a positive value preserves non-negativity.
  \<close>
proof (cases rounding)
  case Cxx_Round_Down
  then show ?thesis
    using numerator_nonnegative divisor_positive
    by (simp add: pos_imp_zdiv_nonneg_iff)
next
  case Cxx_Round_Up
  have "0 \<le> numerator + divisor - 1"
    using numerator_nonnegative divisor_positive by linarith
  then show ?thesis
    using Cxx_Round_Up divisor_positive
    by (simp add: pos_imp_zdiv_nonneg_iff)
qed

lemma sint_word_of_int_nonnegative_int64:
  assumes value_nonnegative: "0 \<le> value"
      and value_bounded: "value \<le> int64_max_int"
  shows "sint (word_of_int value :: int64) = value"
  text \<open>
    Proof sketch: the assumptions place the value inside the non-negative
    half of the signed 64-bit range, so signed truncation is the identity.
  \<close>
proof -
  have upper: "value < (2 :: int) ^ 63"
    using value_bounded by simp
  have lower: "- ((2 :: int) ^ 63) \<le> value"
    using value_nonnegative by simp
  show ?thesis
    using lower upper
    unfolding sint_sbintrunc'
    by (simp add: signed_take_bit_int_eq_self)
qed

lemma nonnegative_int64_round_up_numerator_fits_uint128:
  fixes a b c :: int64
  assumes a_nonnegative: "0 \<le> sint a"
      and b_nonnegative: "0 \<le> sint b"
      and c_positive: "0 < sint c"
  shows "sint a * sint b + sint c - 1 < (2 :: int) ^ 128"
  text \<open>
    Proof sketch: each non-negative multiplicand is below two to the
    sixty-third power, so their product is below two to the
    one-hundred-twenty-sixth power.  Adding a signed 64-bit divisor still
    leaves the round-up numerator strictly below the unsigned 128-bit limit.
  \<close>
proof -
  have a_bound: "sint a < (2 :: int) ^ 63"
    using sint_lt [of a] by simp
  have b_bound: "sint b < (2 :: int) ^ 63"
    using sint_lt [of b] by simp
  have c_bound: "sint c < (2 :: int) ^ 63"
    using sint_lt [of c] by simp
  have product_bound:
      "sint a * sint b < (2 :: int) ^ 63 * 2 ^ 63"
    using a_bound b_bound b_nonnegative
    by (intro mult_strict_mono) simp_all
  have "sint a * sint b + sint c - 1 <
      (2 :: int) ^ 126 + 2 ^ 63"
    using product_bound c_bound by simp
  also have "... < (2 :: int) ^ 128"
    by simp
  finally show ?thesis .
qed

lemma uint128_round_up_numerator_fits:
  assumes guard:
    "uint a \<le> (2 :: int) ^ 128 - 1 - (sint b - 1)"
  shows "uint a + sint b - 1 < (2 :: int) ^ 128"
  text \<open>
    Proof sketch: rearranging the explicit C++ guard bounds the incremented
    numerator by the largest unsigned 128-bit integer, hence strictly below
    the modulus.
  \<close>
  using guard by linarith

lemma big_divide_or_throw_success:
  assumes a_nonnegative: "0 \<le> sint a"
      and b_nonnegative: "0 \<le> sint b"
      and c_positive: "0 < sint c"
      and quotient_bounded:
        "rounded_quotient (sint a * sint b) (sint c) rounding
          \<le> int64_max_int"
  shows "big_divide_or_throw a b c rounding =
      Cxx_Ok (word_of_int
        (rounded_quotient (sint a * sint b) (sint c) rounding))"
    and "sint (word_of_int
        (rounded_quotient (sint a * sint b) (sint c) rounding) ::
          int64) =
      rounded_quotient (sint a * sint b) (sint c) rounding"
  text \<open>
    Proof sketch: valid operands make the exact numerator and quotient
    non-negative.  The quotient bound selects the successful branch, and the
    signed-word range lemma shows that the returned bit pattern denotes the
    same mathematical quotient.
  \<close>
proof -
  have product_nonnegative: "0 \<le> sint a * sint b"
    using a_nonnegative b_nonnegative by simp
  have quotient_nonnegative:
      "0 \<le> rounded_quotient (sint a * sint b) (sint c) rounding"
    using rounded_quotient_nonnegative
      [OF product_nonnegative c_positive] .
  show "big_divide_or_throw a b c rounding =
      Cxx_Ok (word_of_int
        (rounded_quotient (sint a * sint b) (sint c) rounding))"
    using a_nonnegative b_nonnegative c_positive quotient_bounded
    by (simp add: big_divide_or_throw_def)
  show "sint (word_of_int
        (rounded_quotient (sint a * sint b) (sint c) rounding) ::
          int64) =
      rounded_quotient (sint a * sint b) (sint c) rounding"
    using sint_word_of_int_nonnegative_int64
      [OF quotient_nonnegative quotient_bounded] .
qed

lemma big_divide_or_throw_assertion_iff:
  "big_divide_or_throw a b c rounding =
      Cxx_Err Cxx_Assertion_Failed
    \<longleftrightarrow> sint a < 0 \<or> sint b < 0 \<or> sint c \<le> 0"
  text \<open>
    Proof sketch: unfold the checked helper.  Only its initial validity test
    constructs an assertion error; later branches construct either overflow
    or a successful word.
  \<close>
  by (auto simp add: big_divide_or_throw_def Let_def split: if_splits)

lemma big_divide_or_throw_overflow_iff:
  assumes "0 \<le> sint a" and "0 \<le> sint b" and "0 < sint c"
  shows "big_divide_or_throw a b c rounding = Cxx_Err Cxx_Overflow
    \<longleftrightarrow> rounded_quotient (sint a * sint b) (sint c) rounding
        > int64_max_int"
  text \<open>
    Proof sketch: under the validity conditions the assertion branch is
    impossible, leaving overflow exactly when the mathematical quotient does
    not fit in a signed 64-bit result.
  \<close>
  using assms
  by (auto simp add: big_divide_or_throw_def Let_def split: if_splits)

theorem big_divide_or_throw_success_iff:
  "big_divide_or_throw a b c rounding = Cxx_Ok result
    \<longleftrightarrow> 0 \<le> sint a \<and> 0 \<le> sint b \<and> 0 < sint c \<and>
      rounded_quotient (sint a * sint b) (sint c) rounding
        \<le> int64_max_int \<and>
      result = word_of_int
        (rounded_quotient (sint a * sint b) (sint c) rounding)"
  text \<open>
    Proof sketch: unfold both checked branches.  Equality with a successful
    result forces valid operands and a bounded quotient; conversely those
    conditions select the successful constructor with the exact word value.
  \<close>
  by (auto simp add: big_divide_or_throw_def Let_def split: if_splits)

lemma big_divide_or_throw128_success:
  assumes divisor_positive: "0 < sint b"
      and no_round_up_overflow:
        "\<not> (rounding = Cxx_Round_Up \<and>
          uint a > (2 :: int) ^ 128 - 1 - (sint b - 1))"
      and quotient_bounded:
        "rounded_quotient (uint a) (sint b) rounding
          \<le> int64_max_int"
  shows "big_divide_or_throw128 a b rounding =
      Cxx_Ok (word_of_int
        (rounded_quotient (uint a) (sint b) rounding))"
    and "sint (word_of_int
        (rounded_quotient (uint a) (sint b) rounding) ::
          int64) =
      rounded_quotient (uint a) (sint b) rounding"
  text \<open>
    Proof sketch: a word has a non-negative unsigned value and the divisor is
    positive, so the exact quotient is non-negative.  The two remaining
    assumptions bypass both overflow checks, and the signed-word range lemma
    identifies the returned word with that quotient.
  \<close>
proof -
  have numerator_nonnegative: "0 \<le> uint a"
    by (rule uint_nonnegative)
  have quotient_nonnegative:
      "0 \<le> rounded_quotient (uint a) (sint b) rounding"
    using rounded_quotient_nonnegative
      [OF numerator_nonnegative divisor_positive] .
  show "big_divide_or_throw128 a b rounding =
      Cxx_Ok (word_of_int
        (rounded_quotient (uint a) (sint b) rounding))"
    using divisor_positive no_round_up_overflow quotient_bounded
    by (simp add: big_divide_or_throw128_def)
  show "sint (word_of_int
        (rounded_quotient (uint a) (sint b) rounding) ::
          int64) =
      rounded_quotient (uint a) (sint b) rounding"
    using sint_word_of_int_nonnegative_int64
      [OF quotient_nonnegative quotient_bounded] .
qed

lemma big_divide_or_throw128_assertion_iff:
  "big_divide_or_throw128 a b rounding =
      Cxx_Err Cxx_Assertion_Failed
    \<longleftrightarrow> sint b \<le> 0"
  text \<open>
    Proof sketch: the divisor check is the only assertion-producing branch;
    the explicit numerator guard and result-range check both report overflow.
  \<close>
  by (auto simp add: big_divide_or_throw128_def Let_def split: if_splits)

lemma big_divide_or_throw128_overflow_iff:
  assumes "0 < sint b"
  shows "big_divide_or_throw128 a b rounding = Cxx_Err Cxx_Overflow
    \<longleftrightarrow>
      (rounding = Cxx_Round_Up \<and>
        uint a > (2 :: int) ^ 128 - 1 - (sint b - 1))
      \<or>
      (\<not> (rounding = Cxx_Round_Up \<and>
          uint a > (2 :: int) ^ 128 - 1 - (sint b - 1)) \<and>
       rounded_quotient (uint a) (sint b) rounding
         > int64_max_int)"
  text \<open>
    Proof sketch: after the positive-divisor check, overflow arises either
    from the explicit round-up increment guard or, when that guard is clear,
    from narrowing a quotient above the signed 64-bit maximum.
  \<close>
  using assms
  by (auto simp add: big_divide_or_throw128_def Let_def split: if_splits)

theorem big_divide_or_throw128_success_iff:
  "big_divide_or_throw128 a b rounding = Cxx_Ok result
    \<longleftrightarrow> 0 < sint b \<and>
      \<not> (rounding = Cxx_Round_Up \<and>
        uint a > (2 :: int) ^ 128 - 1 - (sint b - 1)) \<and>
      rounded_quotient (uint a) (sint b) rounding
        \<le> int64_max_int \<and>
      result = word_of_int
        (rounded_quotient (uint a) (sint b) rounding)"
  text \<open>
    Proof sketch: unfolding the definition shows that success is equivalent
    to passing the divisor assertion, the round-up increment guard, and the
    signed result bound, after which the returned word is fixed uniquely.
  \<close>
  by (auto simp add: big_divide_or_throw128_def Let_def split: if_splits)

subsection \<open>Price error bound\<close>

text \<open>
  The lemmas below show that @{const check_price_error_bound} fails an
  assertion exactly when one of its four numeric arguments is negative, and
  that it otherwise returns the mathematical predicate
  @{const price_error_bound_spec}.
\<close>

lemma sint_price_scale:
  fixes price :: int32
  shows "sint (word_of_int (100 * sint price) :: int64) =
    100 * sint price"
  text \<open>
    Proof sketch: the signed range of a 32-bit word, after multiplication by
    one hundred, is strictly inside the signed 64-bit range.  Consequently
    signed truncation to 64 bits is the identity.
  \<close>
proof -
  have lower32: "-2147483648 \<le> sint price"
    using sint_ge [of price] by simp
  have upper32: "sint price \<le> 2147483647"
    using sint_lt [of price] by simp
  have lower64: "-9223372036854775808 \<le> 100 * sint price"
    using lower32 by linarith
  have upper64: "100 * sint price < 9223372036854775808"
    using upper32 by linarith
  have lower_power: "- ((2 :: int) ^ 63) \<le> 100 * sint price"
    using lower64 by simp
  have upper_power: "100 * sint price < (2 :: int) ^ 63"
    using upper64 by simp
  show ?thesis
    using lower_power upper_power
    unfolding sint_sbintrunc'
    by (simp add: signed_take_bit_int_eq_self)
qed

lemma uint_word_abs_diff:
  fixes a b :: uint128
  shows "uint (if a > b then a - b else b - a) =
    abs (uint a - uint b)"
  text \<open>
    Proof sketch: split on the unsigned ordering of the words.  In each
    branch the larger value is the minuend, so unsigned subtraction does not
    wrap and agrees with the corresponding non-negative integer difference.
  \<close>
proof (cases "a > b")
  case True
  then have "uint b \<le> uint a"
    by (simp add: word_less_def)
  with True show ?thesis
    by (simp add: uint_sub_lem)
next
  case False
  then have "uint a \<le> uint b"
    by (simp add: word_less_def)
  with False show ?thesis
    by (simp add: uint_sub_lem)
qed

lemma nonnegative_price_error_product_fits_uint128:
  fixes price :: int32 and amount :: int64
  assumes price_nonnegative: "0 \<le> sint price"
      and amount_nonnegative: "0 \<le> sint amount"
  shows "0 \<le> 100 * sint price * sint amount"
    and "100 * sint price * sint amount < (2 :: int) ^ 128"
  text \<open>
    Proof sketch: the scaled price is an exact, non-negative signed 64-bit
    value by @{thm [source] sint_price_scale}.  The previously proved bound
    for multiplying two non-negative signed 64-bit words then supplies both
    claims.
  \<close>
proof -
  let ?scaled = "word_of_int (100 * sint price) :: int64"
  have scaled_value: "sint ?scaled = 100 * sint price"
    by (rule sint_price_scale)
  have scaled_nonnegative: "0 \<le> sint ?scaled"
    using price_nonnegative scaled_value by simp
  have bounds:
      "0 \<le> sint ?scaled * sint amount"
      "sint ?scaled * sint amount < (2 :: int) ^ 128"
    using nonnegative_int64_product_fits_uint128
      [OF scaled_nonnegative amount_nonnegative] .
  show "0 \<le> 100 * sint price * sint amount"
    using bounds(1) unfolding scaled_value .
  show "100 * sint price * sint amount < (2 :: int) ^ 128"
    using bounds(2) unfolding scaled_value .
qed

lemma price_error_product_uint_value:
  fixes price :: int32 and amount :: int64
  assumes price_nonnegative: "0 \<le> sint price"
      and amount_nonnegative: "0 \<le> sint amount"
  shows "uint (word_of_int (100 * sint price * sint amount) ::
      uint128) = 100 * sint price * sint amount"
  text \<open>
    Proof sketch: interpret the scaled price as a signed 64-bit word and
    apply the exact unsigned value theorem for @{const big_multiply}; the
    scaling lemma then rewrites the result to mathematical integers.
  \<close>
proof -
  let ?scaled = "word_of_int (100 * sint price) :: int64"
  have scaled_value: "sint ?scaled = 100 * sint price"
    by (rule sint_price_scale)
  have scaled_nonnegative: "0 \<le> sint ?scaled"
    using price_nonnegative scaled_value by simp
  have "uint (word_of_int (sint ?scaled * sint amount) ::
      uint128) = sint ?scaled * sint amount"
    using big_multiply_uint_value
      [OF scaled_nonnegative amount_nonnegative] .
  then show ?thesis
    unfolding scaled_value .
qed

lemma check_price_error_bound_success_words:
  assumes price_n_nonnegative: "0 \<le> sint price_n"
      and price_d_nonnegative: "0 \<le> sint price_d"
      and wheat_nonnegative: "0 \<le> sint wheat_receive"
      and sheep_nonnegative: "0 \<le> sint sheep_send"
  shows "check_price_error_bound price_n price_d wheat_receive sheep_send
      can_favor_wheat =
    Cxx_Ok
      (let lhs = word_of_int
          (100 * sint price_n * sint wheat_receive) :: uint128;
           rhs = word_of_int
          (100 * sint price_d * sint sheep_send) :: uint128;
           cap = word_of_int
          (sint price_n * sint wheat_receive) :: uint128;
           abs_diff = (if lhs > rhs then lhs - rhs else rhs - lhs)
       in (can_favor_wheat \<and> rhs > lhs) \<or> abs_diff \<le> cap)"
  text \<open>
    Proof sketch: non-negativity makes all three calls of
    @{const big_multiply} succeed.  Substitute their exact word results into
    the monadic computation; the early return is equivalent to disjoining
    its condition with the ordinary bound check.
  \<close>
proof -
  let ?err_n = "word_of_int (100 * sint price_n) :: int64"
  let ?err_d = "word_of_int (100 * sint price_d) :: int64"
  let ?lhs =
    "word_of_int
      (100 * sint price_n * sint wheat_receive) :: uint128"
  let ?rhs =
    "word_of_int
      (100 * sint price_d * sint sheep_send) :: uint128"
  let ?cap =
    "word_of_int (sint price_n * sint wheat_receive) :: uint128"
  have err_n_value: "sint ?err_n = 100 * sint price_n"
    by (rule sint_price_scale)
  have err_d_value: "sint ?err_d = 100 * sint price_d"
    by (rule sint_price_scale)
  have lhs_result: "big_multiply ?err_n wheat_receive = Cxx_Ok ?lhs"
    using price_n_nonnegative wheat_nonnegative err_n_value
    by (simp add: big_multiply_def)
  have rhs_result: "big_multiply ?err_d sheep_send = Cxx_Ok ?rhs"
    using price_d_nonnegative sheep_nonnegative err_d_value
    by (simp add: big_multiply_def)
  have cap_nonnegative: "0 \<le> sint (scast price_n :: int64)"
    using price_n_nonnegative by (simp only: sint_scast_int32_int64)
  have cap_result:
      "big_multiply (scast price_n) wheat_receive = Cxx_Ok ?cap"
    using big_multiply_nonnegative
      [OF cap_nonnegative wheat_nonnegative]
    unfolding sint_scast_int32_int64 .
  show ?thesis
    unfolding check_price_error_bound_def
    apply (simp only: lhs_result rhs_result cap_result cxx_bind.simps)
    by auto
qed

theorem check_price_error_bound_integer_characterization:
  assumes price_n_nonnegative: "0 \<le> sint price_n"
      and price_d_nonnegative: "0 \<le> sint price_d"
      and wheat_nonnegative: "0 \<le> sint wheat_receive"
      and sheep_nonnegative: "0 \<le> sint sheep_send"
  shows "check_price_error_bound price_n price_d wheat_receive sheep_send
      can_favor_wheat =
    Cxx_Ok
      (price_error_bound_spec price_n price_d wheat_receive sheep_send
        can_favor_wheat)"
  text \<open>
    Proof sketch: use the word-level success lemma, then replace the unsigned
    values of the two scaled products and the cap by their exact integer
    values.  The unsigned absolute difference is exact because the model
    always subtracts the smaller word from the larger one.
  \<close>
proof -
  let ?lhs =
    "word_of_int
      (100 * sint price_n * sint wheat_receive) :: uint128"
  let ?rhs =
    "word_of_int
      (100 * sint price_d * sint sheep_send) :: uint128"
  let ?cap =
    "word_of_int (sint price_n * sint wheat_receive) :: uint128"
  have lhs_value:
      "uint ?lhs = 100 * sint price_n * sint wheat_receive"
    using price_error_product_uint_value
      [OF price_n_nonnegative wheat_nonnegative] .
  have rhs_value:
      "uint ?rhs = 100 * sint price_d * sint sheep_send"
    using price_error_product_uint_value
      [OF price_d_nonnegative sheep_nonnegative] .
  have cap_nonnegative: "0 \<le> sint (scast price_n :: int64)"
    using price_n_nonnegative by (simp only: sint_scast_int32_int64)
  have cap_value: "uint ?cap = sint price_n * sint wheat_receive"
    using big_multiply_uint_value
      [OF cap_nonnegative wheat_nonnegative]
    unfolding sint_scast_int32_int64 .
  have abs_diff_value:
      "uint (if ?lhs > ?rhs then ?lhs - ?rhs else ?rhs - ?lhs) =
       abs ((100 * sint price_n * sint wheat_receive) -
            (100 * sint price_d * sint sheep_send))"
    using uint_word_abs_diff [where a = ?lhs and b = ?rhs]
    unfolding lhs_value rhs_value .
  have favor_condition:
      "(?rhs > ?lhs) =
       ((100 * sint price_d * sint sheep_send) >
        (100 * sint price_n * sint wheat_receive))"
    by (simp only: word_less_def lhs_value rhs_value)
  have bound_condition:
      "((if ?lhs > ?rhs then ?lhs - ?rhs else ?rhs - ?lhs) \<le> ?cap) =
       (abs ((100 * sint price_n * sint wheat_receive) -
             (100 * sint price_d * sint sheep_send))
        \<le> sint price_n * sint wheat_receive)"
    by (simp only: word_le_def abs_diff_value cap_value)
  show ?thesis
    unfolding price_error_bound_spec_def
    by (simp only: check_price_error_bound_success_words
      [OF price_n_nonnegative price_d_nonnegative
          wheat_nonnegative sheep_nonnegative]
      Let_def favor_condition bound_condition)
qed

theorem check_price_error_bound_negative:
  assumes negative:
    "sint price_n < 0 \<or> sint price_d < 0 \<or>
     sint wheat_receive < 0 \<or> sint sheep_send < 0"
  shows "check_price_error_bound price_n price_d wheat_receive sheep_send
      can_favor_wheat = Cxx_Err Cxx_Assertion_Failed"
  text \<open>
    Proof sketch: exact signed scaling preserves the sign of each price
    component.  Follow the monadic evaluation order: the first negative
    operand encountered by @{const big_multiply} produces the assertion
    error, which the bind propagates unchanged.
  \<close>
proof -
  have err_n_value:
      "sint (word_of_int (100 * sint price_n) :: int64) =
       100 * sint price_n"
    by (rule sint_price_scale)
  have err_d_value:
      "sint (word_of_int (100 * sint price_d) :: int64) =
       100 * sint price_d"
    by (rule sint_price_scale)
  show ?thesis
    unfolding check_price_error_bound_def
    apply (simp only: big_multiply_def err_n_value err_d_value
        sint_scast_int32_int64 cxx_bind.simps)
    using negative
    by auto
qed

theorem check_price_error_bound_characterization:
  "check_price_error_bound price_n price_d wheat_receive sheep_send
      can_favor_wheat =
    (if 0 \<le> sint price_n \<and> 0 \<le> sint price_d \<and>
        0 \<le> sint wheat_receive \<and> 0 \<le> sint sheep_send
     then Cxx_Ok
       (price_error_bound_spec price_n price_d wheat_receive sheep_send
         can_favor_wheat)
     else Cxx_Err Cxx_Assertion_Failed)"
  text \<open>
    Proof sketch: split on the weakest successful-input condition.  The
    non-negative branch is the exact integer characterization; negating that
    conjunction exposes a negative operand, so the assertion theorem applies.
  \<close>
proof (cases "0 \<le> sint price_n \<and> 0 \<le> sint price_d \<and>
    0 \<le> sint wheat_receive \<and> 0 \<le> sint sheep_send")
  case True
  then show ?thesis
    using check_price_error_bound_integer_characterization by simp
next
  case False
  then have "sint price_n < 0 \<or> sint price_d < 0 \<or>
      sint wheat_receive < 0 \<or> sint sheep_send < 0"
    by auto
  then show ?thesis
    using False check_price_error_bound_negative by simp
qed

subsection \<open>Price-error application\<close>

text \<open>
  The lemmas below replace the monadic branch structure of
  @{const apply_price_error_thresholds} by the flat decision tree
  @{const apply_price_error_thresholds_spec}, and derive what a successful
  call guarantees about the record it returns.
\<close>

lemma apply_price_error_thresholds_nonpositive:
  assumes nonpositive:
    "\<not> (0 < sint wheat_receive \<and> 0 < sint sheep_send)"
  shows
    "apply_price_error_thresholds price_n price_d wheat_receive sheep_send
        wheat_stays rounding =
      (if rounding = Exchange_Strict_Send then
         if sheep_send = 0 then Cxx_Err Cxx_Runtime_Error
         else Cxx_Ok
           (make_exchange_result wheat_receive sheep_send wheat_stays)
       else Cxx_Ok (make_exchange_result 0 0 wheat_stays))"
  text \<open>
    Proof sketch: the failed positivity guard selects the final C++ branch;
    simplifying only that guard leaves the strict-send zero test unchanged.
  \<close>
  unfolding apply_price_error_thresholds_def
  by (simp only: if_not_P [OF nonpositive])

lemma apply_price_error_thresholds_negative_price:
  assumes amounts_positive:
      "0 < sint wheat_receive \<and> 0 < sint sheep_send"
    and negative_price: "sint price_n < 0 \<or> sint price_d < 0"
  shows
    "apply_price_error_thresholds price_n price_d wheat_receive sheep_send
        wheat_stays rounding = Cxx_Err Cxx_Assertion_Failed"
  text \<open>
    Proof sketch: positivity reaches both multiplications.  Sign extension
    preserves each price sign, so the first negative price reached by
    @{const big_multiply} produces the modeled assertion and monadic bind
    propagates it.
  \<close>
  unfolding apply_price_error_thresholds_def
  apply (simp only: if_P [OF amounts_positive] big_multiply_def
      sint_scast_int32_int64 cxx_bind.simps)
  using negative_price
  by auto

theorem apply_price_error_thresholds_positive_characterization:
  assumes amounts_positive:
      "0 < sint wheat_receive \<and> 0 < sint sheep_send"
    and price_n_nonnegative: "0 \<le> sint price_n"
    and price_d_nonnegative: "0 \<le> sint price_d"
  shows
    "apply_price_error_thresholds price_n price_d wheat_receive sheep_send
        wheat_stays rounding =
      (let original =
          make_exchange_result wheat_receive sheep_send wheat_stays;
         zero = make_exchange_result 0 0 wheat_stays
       in if \<not> favored_seller_ok price_n price_d wheat_receive sheep_send
            wheat_stays
          then Cxx_Err Cxx_Runtime_Error
          else if rounding = Exchange_Normal then
            Cxx_Ok
              (if price_error_bound_spec price_n price_d wheat_receive
                    sheep_send False
               then original else zero)
          else if price_error_bound_spec price_n price_d wheat_receive
              sheep_send True
          then Cxx_Ok original
          else Cxx_Err Cxx_Runtime_Error)"
  text \<open>
    Proof sketch: the non-negative multiplication contracts replace both
    128-bit words by their exact integer products.  Unsigned word comparisons
    then become the favored-seller inequality, and the already-proved
    price-error contract replaces each checked bound call.
  \<close>
proof -
  let ?wheat_value =
    "word_of_int (sint wheat_receive * sint price_n) :: uint128"
  let ?sheep_value =
    "word_of_int (sint sheep_send * sint price_d) :: uint128"
  have wheat_nonnegative: "0 \<le> sint wheat_receive"
    using amounts_positive by simp
  have sheep_nonnegative: "0 \<le> sint sheep_send"
    using amounts_positive by simp
  have price_n_wide_nonnegative:
      "0 \<le> sint (scast price_n :: int64)"
    using price_n_nonnegative by (simp only: sint_scast_int32_int64)
  have price_d_wide_nonnegative:
      "0 \<le> sint (scast price_d :: int64)"
    using price_d_nonnegative by (simp only: sint_scast_int32_int64)
  have wheat_result:
      "big_multiply wheat_receive (scast price_n) = Cxx_Ok ?wheat_value"
    using big_multiply_nonnegative
      [OF wheat_nonnegative price_n_wide_nonnegative]
    unfolding sint_scast_int32_int64 .
  have sheep_result:
      "big_multiply sheep_send (scast price_d) = Cxx_Ok ?sheep_value"
    using big_multiply_nonnegative
      [OF sheep_nonnegative price_d_wide_nonnegative]
    unfolding sint_scast_int32_int64 .
  have wheat_value:
      "uint ?wheat_value = sint wheat_receive * sint price_n"
    using big_multiply_uint_value
      [OF wheat_nonnegative price_n_wide_nonnegative]
    unfolding sint_scast_int32_int64 .
  have sheep_value:
      "uint ?sheep_value = sint sheep_send * sint price_d"
    using big_multiply_uint_value
      [OF sheep_nonnegative price_d_wide_nonnegative]
    unfolding sint_scast_int32_int64 .
  have sheep_lt_wheat:
      "(?sheep_value < ?wheat_value) =
       (sint sheep_send * sint price_d <
        sint wheat_receive * sint price_n)"
    by (simp only: word_less_def sheep_value wheat_value)
  have wheat_lt_sheep:
      "(?wheat_value < ?sheep_value) =
       (sint wheat_receive * sint price_n <
        sint sheep_send * sint price_d)"
    by (simp only: word_less_def wheat_value sheep_value)
  have invalid_direction:
      "((wheat_stays \<and> ?sheep_value < ?wheat_value) \<or>
        (\<not> wheat_stays \<and> ?sheep_value > ?wheat_value)) =
       (\<not> favored_seller_ok price_n price_d wheat_receive sheep_send
          wheat_stays)"
  proof (cases wheat_stays)
    case True
    have favored:
        "favored_seller_ok price_n price_d wheat_receive sheep_send
          wheat_stays =
         (sint wheat_receive * sint price_n \<le>
          sint sheep_send * sint price_d)"
      using True by (simp only: favored_seller_ok_def Let_def if_True)
    from True sheep_lt_wheat favored show ?thesis by auto
  next
    case False
    have favored:
        "favored_seller_ok price_n price_d wheat_receive sheep_send
          wheat_stays =
         (sint sheep_send * sint price_d \<le>
          sint wheat_receive * sint price_n)"
      using False by (simp only: favored_seller_ok_def Let_def if_False)
    from False wheat_lt_sheep favored show ?thesis by auto
  qed
  have normal_bound:
      "check_price_error_bound price_n price_d wheat_receive sheep_send False =
       Cxx_Ok
         (price_error_bound_spec price_n price_d wheat_receive sheep_send
           False)"
    using check_price_error_bound_integer_characterization
      [OF price_n_nonnegative price_d_nonnegative wheat_nonnegative
          sheep_nonnegative] .
  have path_bound:
      "check_price_error_bound price_n price_d wheat_receive sheep_send True =
       Cxx_Ok
         (price_error_bound_spec price_n price_d wheat_receive sheep_send
           True)"
    using check_price_error_bound_integer_characterization
      [OF price_n_nonnegative price_d_nonnegative wheat_nonnegative
          sheep_nonnegative] .
  show ?thesis
    unfolding apply_price_error_thresholds_def
    apply (simp only: if_P [OF amounts_positive] wheat_result sheep_result
        cxx_bind.simps invalid_direction normal_bound path_bound)
    by (cases rounding) simp_all
qed

theorem apply_price_error_thresholds_characterization:
  "apply_price_error_thresholds price_n price_d wheat_receive sheep_send
      wheat_stays rounding =
    apply_price_error_thresholds_spec price_n price_d wheat_receive sheep_send
      wheat_stays rounding"
  text \<open>
    Proof sketch: partition all bit patterns first by the amount-positivity
    guard and then by price signs.  The preceding three branch theorems cover
    the non-positive, assertion, and fully non-negative cases respectively.
  \<close>
proof (cases "0 < sint wheat_receive \<and> 0 < sint sheep_send")
  case False
  then show ?thesis
    using apply_price_error_thresholds_nonpositive
    by (simp add: apply_price_error_thresholds_spec_def Let_def)
next
  case amounts_positive: True
  show ?thesis
  proof (cases "sint price_n < 0 \<or> sint price_d < 0")
    case True
    then show ?thesis
      using apply_price_error_thresholds_negative_price [OF amounts_positive]
      by (simp add: apply_price_error_thresholds_spec_def Let_def
          amounts_positive)
  next
    case no_negative_price: False
    then have price_n_nonnegative: "0 \<le> sint price_n"
      and price_d_nonnegative: "0 \<le> sint price_d"
      by auto
    show ?thesis
      using apply_price_error_thresholds_positive_characterization
        [OF amounts_positive price_n_nonnegative price_d_nonnegative]
        amounts_positive no_negative_price
      by (simp add: apply_price_error_thresholds_spec_def Let_def)
  qed
qed

theorem apply_price_error_thresholds_preserves_wheat_stays:
  assumes result:
    "apply_price_error_thresholds price_n price_d wheat_receive sheep_send
      wheat_stays rounding = Cxx_Ok exchange_result"
  shows "result_wheat_stays exchange_result = wheat_stays"
  text \<open>
    Proof sketch: rewrite the executable function to its total branch
    characterization.  Every successful constructor in that specification
    uses the input stay flag.
  \<close>
  using result apply_price_error_thresholds_characterization
  by (auto simp add: apply_price_error_thresholds_spec_def
      make_exchange_result_def Let_def
      split: if_splits exchange_rounding.splits)

theorem apply_price_error_thresholds_normal_result:
  assumes result:
    "apply_price_error_thresholds price_n price_d wheat_receive sheep_send
      wheat_stays Exchange_Normal = Cxx_Ok exchange_result"
  shows
    "exchange_result =
       make_exchange_result wheat_receive sheep_send wheat_stays \<or>
     exchange_result = make_exchange_result 0 0 wheat_stays"
  text \<open>
    Proof sketch: after rewriting with the total characterization, all normal
    success branches select either the original record or the explicit
    zero-amount record.
  \<close>
  using result apply_price_error_thresholds_characterization
  by (auto simp add: apply_price_error_thresholds_spec_def Let_def
      split: if_splits)

theorem apply_price_error_thresholds_positive_path_result:
  assumes amounts_positive:
      "0 < sint wheat_receive \<and> 0 < sint sheep_send"
    and path_mode: "rounding \<noteq> Exchange_Normal"
    and result:
      "apply_price_error_thresholds price_n price_d wheat_receive sheep_send
        wheat_stays rounding = Cxx_Ok exchange_result"
  shows
    "exchange_result =
      make_exchange_result wheat_receive sheep_send wheat_stays"
  text \<open>
    Proof sketch: under the positive guard, every non-normal successful branch
    of the total characterization returns the original amount record; all
    alternatives are explicit errors.
  \<close>
  using result apply_price_error_thresholds_characterization amounts_positive
    path_mode
  by (auto simp add: apply_price_error_thresholds_spec_def Let_def
      split: if_splits)

theorem apply_price_error_thresholds_positive_success_favored:
  assumes amounts_positive:
      "0 < sint wheat_receive \<and> 0 < sint sheep_send"
    and result:
      "apply_price_error_thresholds price_n price_d wheat_receive sheep_send
        wheat_stays rounding = Cxx_Ok exchange_result"
  shows
    "favored_seller_ok price_n price_d wheat_receive sheep_send wheat_stays"
  text \<open>
    Proof sketch: a positive call can return successfully only after passing
    the exact favored-seller comparison in the total characterization.
    Negative prices and the opposite direction are error branches.
  \<close>
  using result apply_price_error_thresholds_characterization amounts_positive
  by (auto simp add: apply_price_error_thresholds_spec_def Let_def
      split: if_splits)

theorem apply_price_error_thresholds_positive_trade_bound:
  assumes amounts_positive:
      "0 < sint wheat_receive \<and> 0 < sint sheep_send"
    and result:
      "apply_price_error_thresholds price_n price_d wheat_receive sheep_send
        wheat_stays rounding = Cxx_Ok exchange_result"
    and result_positive:
      "0 < sint (num_wheat_received exchange_result) \<and>
       0 < sint (num_sheep_send exchange_result)"
  shows
    "if rounding = Exchange_Normal
     then price_error_bound_spec price_n price_d wheat_receive sheep_send False
     else price_error_bound_spec price_n price_d wheat_receive sheep_send True"
  text \<open>
    Proof sketch: normal mode may evade its bound only by returning the
    zero-amount record, which the positive-result assumption excludes.
    Non-normal success already requires the one-sided bound.
  \<close>
  using result apply_price_error_thresholds_characterization amounts_positive
    result_positive
  by (auto simp add: apply_price_error_thresholds_spec_def
      make_exchange_result_def Let_def split: if_splits)

subsection \<open>Offer value\<close>

text \<open>
  The lemmas below show that @{const calculate_offer_value} succeeds exactly
  under @{const calculate_offer_value_pre}, and that the unsigned 128-bit word
  it then returns denotes the exact integer
  @{term "min (sint max_send * sint price_n) (sint max_receive * sint price_d)"}.
\<close>

lemma calculate_offer_value_success:
  assumes "calculate_offer_value_pre price_n price_d max_send max_receive"
  shows "calculate_offer_value price_n price_d max_send max_receive =
    Cxx_Ok
      (min
        (word_of_int (sint max_send * sint price_n) :: uint128)
        (word_of_int (sint max_receive * sint price_d) :: uint128))"
  using assms
  by (simp add: calculate_offer_value_pre_def calculate_offer_value_def)

lemma uint_min_word:
  "uint (min a b) = min (uint a) (uint b)"
  for a b :: "'a::len word"
  by (simp add: min_def word_le_def)

theorem calculate_offer_value_integer_characterization:
  assumes pre:
    "calculate_offer_value_pre price_n price_d max_send max_receive"
  obtains v where
    "calculate_offer_value price_n price_d max_send max_receive = Cxx_Ok v"
    and
    "uint v =
      min (sint max_send * sint price_n)
          (sint max_receive * sint price_d)"
proof
  let ?send =
    "word_of_int (sint max_send * sint price_n) :: uint128"
  let ?receive =
    "word_of_int (sint max_receive * sint price_d) :: uint128"
  show "calculate_offer_value price_n price_d max_send max_receive =
      Cxx_Ok (min ?send ?receive)"
    using calculate_offer_value_success [OF pre] .
  from pre have nonnegative:
    "0 \<le> sint max_send" "0 \<le> sint price_n"
    "0 \<le> sint max_receive" "0 \<le> sint price_d"
    by (simp_all add: calculate_offer_value_pre_def)
  have send_value: "uint ?send = sint max_send * sint price_n"
    using big_multiply_uint_value [of max_send "scast price_n"]
      nonnegative by simp
  have receive_value: "uint ?receive = sint max_receive * sint price_d"
    using big_multiply_uint_value [of max_receive "scast price_d"]
      nonnegative by simp
  show "uint (min ?send ?receive) =
      min (sint max_send * sint price_n)
          (sint max_receive * sint price_d)"
    by (simp only: uint_min_word send_value receive_value)
qed

lemma calculate_offer_value_example:
  "calculate_offer_value
      (3 :: int32) (2 :: int32)
      (10 :: int64) (10 :: int64) =
    Cxx_Ok (20 :: uint128)"
  by eval



theorem calculate_offer_value_characterization:
  "calculate_offer_value price_n price_d max_send max_receive =
    (if calculate_offer_value_pre price_n price_d max_send max_receive
     then Cxx_Ok
       (min
         (word_of_int (sint max_send * sint price_n) :: uint128)
         (word_of_int (sint max_receive * sint price_d) :: uint128))
     else Cxx_Err Cxx_Assertion_Failed)"
  text \<open>
    Proof sketch: unfold both multiplications.  The conjunction in
    @{const calculate_offer_value_pre} is exactly the condition under which
    neither sequential @{const big_multiply} call asserts; on that branch both
    exact product words reach the unsigned minimum.
  \<close>
  unfolding calculate_offer_value_def calculate_offer_value_pre_def
    big_multiply_def
  by (auto simp add: sint_scast_int32_int64)

subsection \<open>Exchange before price-error thresholds\<close>

text \<open>
  The lemmas below show that, under @{const exchange_v10_pre}, no assertion,
  overflow, or runtime error can arise in
  @{const exchange_v10_without_price_error_thresholds_with_options}, and that the pair of
  amounts it returns is exactly @{const exchange_v10_amounts_int} evaluated in
  unbounded integer arithmetic.  This is the longest development in the
  theory: each of the five division branches is bounded separately before the
  branches are recombined.
\<close>
lemma exchange_v10_without_as_checked_amounts:
  "exchange_v10_without_price_error_thresholds_with_options price_n price_d
      max_wheat_send max_wheat_receive max_sheep_send max_sheep_receive
      rounding options = do {
    wheat_value \<leftarrow> calculate_offer_value price_n price_d
      max_wheat_send max_sheep_receive;
    sheep_value \<leftarrow> calculate_offer_value price_d price_n
      max_sheep_send max_wheat_receive;
    let wheat_stays = wheat_value > sheep_value;
    amounts \<leftarrow> exchange_v10_amounts price_n price_d wheat_value sheep_value
      max_wheat_send max_wheat_receive max_sheep_send max_sheep_receive
      wheat_stays rounding options;
    check_exchange_v10_result max_wheat_send max_wheat_receive
      max_sheep_send max_sheep_receive wheat_stays amounts
  }"
  text \<open>
    Proof sketch: unfold the top-level model and the factored final checker.
    The tuple projections and two ordered bounds tests are definitionally the
    same as the explicit tail of the executable model.
  \<close>
  unfolding exchange_v10_without_price_error_thresholds_with_options_def
    check_exchange_v10_result_def
  by (simp add: Let_def)

theorem exchange_v10_without_price_error_thresholds_characterization:
  "exchange_v10_without_price_error_thresholds_with_options price_n price_d
      max_wheat_send max_wheat_receive max_sheep_send max_sheep_receive
      rounding options =
    exchange_v10_without_price_error_thresholds_spec price_n price_d
      max_wheat_send max_wheat_receive max_sheep_send max_sheep_receive
      rounding options"
  text \<open>
    Proof sketch: replace both sequential offer-value calls with their total
    characterizations.  A failed precondition produces the first reached
    assertion; otherwise monadic simplification leaves precisely the two exact
    value words, the amount block, and the final checker in the specification.
  \<close>
  unfolding exchange_v10_without_as_checked_amounts
    exchange_v10_without_price_error_thresholds_spec_def
    calculate_offer_value_characterization
  by (auto simp add: cxx_bind.simps Let_def split: if_splits)




lemma int_div_upper_bound:
  fixes numerator divisor bound :: int
  assumes divisor_positive: "0 < divisor"
      and numerator_bound: "numerator \<le> bound * divisor"
  shows "numerator div divisor \<le> bound"
  text \<open>
    Proof sketch: integer division by a positive divisor is monotone in the
    numerator.  Compare with @{term "bound * divisor"} and cancel the exact
    multiple.
  \<close>
proof -
  have "numerator div divisor \<le> (bound * divisor) div divisor"
    using zdiv_mono1 [OF numerator_bound divisor_positive] .
  also have "... = bound"
    using divisor_positive by simp
  finally show ?thesis .
qed

lemma int_ceiling_div_upper_bound:
  fixes numerator divisor bound :: int
  assumes divisor_positive: "0 < divisor"
      and numerator_nonnegative: "0 \<le> numerator"
      and numerator_bound: "numerator \<le> bound * divisor"
  shows "(numerator + divisor - 1) div divisor \<le> bound"
  text \<open>
    Proof sketch: the assumptions force a non-negative bound.  Add
    @{term "divisor - 1"} to the numerator inequality, use division
    monotonicity, and split the exact multiple from the remainder.
  \<close>
proof -
  have bound_nonnegative: "0 \<le> bound"
  proof (rule ccontr)
    assume "\<not> 0 \<le> bound"
    then have bound_negative: "bound < 0" by simp
    have "bound * divisor < 0"
      using bound_negative divisor_positive by (rule mult_neg_pos)
    with numerator_nonnegative numerator_bound show False by linarith
  qed
  have increment_bound:
      "numerator + divisor - 1 \<le> bound * divisor + (divisor - 1)"
    using numerator_bound by simp
  have "(numerator + divisor - 1) div divisor \<le>
      (bound * divisor + (divisor - 1)) div divisor"
    using zdiv_mono1 [OF increment_bound divisor_positive] .
  also have "... = bound + (divisor - 1) div divisor"
    using divisor_positive by (simp only: div_mult_self3)
  also have "... = bound"
    using divisor_positive by simp
  finally show ?thesis .
qed

lemma int_ceiling_div_nonnegative:
  fixes numerator divisor :: int
  assumes "0 \<le> numerator" and "0 < divisor"
  shows "0 \<le> (numerator + divisor - 1) div divisor"
  text \<open>
    Proof sketch: this expression is @{const rounded_quotient} in round-up
    mode, whose non-negativity theorem applies directly.
  \<close>
  using rounded_quotient_nonnegative
    [OF assms, of Cxx_Round_Up]
  by simp

lemma int_div_mult_le:
  fixes numerator divisor :: int
  assumes divisor_positive: "0 < divisor"
  shows "numerator div divisor * divisor \<le> numerator"
  text \<open>
    Proof sketch: decompose the numerator into its quotient multiple and
    remainder.  A positive divisor makes the integer remainder non-negative.
  \<close>
proof -
  have remainder_nonnegative: "0 \<le> numerator mod divisor"
    using divisor_positive by (simp add: pos_mod_sign)
  have "numerator mod divisor + numerator div divisor * divisor = numerator"
    by (rule mod_div_mult_eq)
  with remainder_nonnegative show ?thesis by linarith
qed

lemma sint64_upper_bound:
  "sint (x :: int64) \<le> int64_max_int"
  text \<open>
    Proof sketch: instantiate the generic strict upper bound for signed words
    at width 64 and convert the strict power-of-two bound to the largest
    signed 64-bit integer.
  \<close>
proof -
  have "sint x < (2 :: int) ^ (LENGTH(64) - 1)"
    by (rule sint_lt)
  then show ?thesis by simp
qed

lemma signed_min64_word:
  "signed_min64 a b =
    word_of_int (min (sint a) (sint b))"
  text \<open>
    Proof sketch: split on the signed comparison used by the definition.
    Re-encoding the signed interpretation of either selected word returns the
    original bit pattern.
  \<close>
  unfolding signed_min64_def
  by (auto simp add: min_def)

lemma big_divide_or_throw128_down_bounded:
  assumes divisor_positive: "0 < sint divisor"
      and value_bound: "uint value \<le> bound * sint divisor"
      and bound_bounded: "bound \<le> int64_max_int"
  shows "big_divide_or_throw128 value divisor Cxx_Round_Down =
      Cxx_Ok (word_of_int (uint value div sint divisor))"
    and "sint
      (word_of_int (uint value div sint divisor) :: int64) =
      uint value div sint divisor"
  text \<open>
    Proof sketch: monotonic division turns the supplied product bound into a
    signed-64 quotient bound.  Round-down makes the 128-bit increment guard
    false, so the existing checked-division success theorem yields both the
    exact returned word and its signed interpretation.
  \<close>
proof -
  have quotient_to_bound:
      "uint value div sint divisor \<le> bound"
    by (rule int_div_upper_bound [OF divisor_positive value_bound])
  have quotient_bounded:
      "uint value div sint divisor \<le> int64_max_int"
    using quotient_to_bound bound_bounded by linarith
  have rounded_bounded:
      "rounded_quotient (uint value) (sint divisor) Cxx_Round_Down
        \<le> int64_max_int"
    using quotient_bounded by simp
  have no_guard:
      "\<not> (Cxx_Round_Down = Cxx_Round_Up \<and>
        uint value > (2 :: int) ^ 128 - 1 - (sint divisor - 1))"
    by simp
  from big_divide_or_throw128_success
    [OF divisor_positive no_guard rounded_bounded]
  show "big_divide_or_throw128 value divisor Cxx_Round_Down =
       Cxx_Ok (word_of_int (uint value div sint divisor))"
    by simp
  from big_divide_or_throw128_success
    [OF divisor_positive no_guard rounded_bounded]
  show "sint (word_of_int (uint value div sint divisor) :: int64) =
       uint value div sint divisor"
    by simp
qed

lemma exchange_wheat_value_int_bounds:
  assumes pre: "exchange_v10_pre price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive"
  shows "0 \<le> exchange_wheat_value_int price_n price_d max_wheat_send
      max_sheep_receive"
    and "exchange_wheat_value_int price_n price_d max_wheat_send
        max_sheep_receive \<le> sint max_wheat_send * sint price_n"
    and "exchange_wheat_value_int price_n price_d max_wheat_send
        max_sheep_receive \<le> sint max_sheep_receive * sint price_d"
  text \<open>
    Proof sketch: well-formedness makes both exact products non-negative, and
    their mathematical minimum is non-negative and below each operand.
  \<close>
  using pre
  by (auto simp add: exchange_v10_pre_def exchange_wheat_value_int_def
      min_def)

lemma exchange_sheep_value_int_bounds:
  assumes pre: "exchange_v10_pre price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive"
  shows "0 \<le> exchange_sheep_value_int price_n price_d max_sheep_send
      max_wheat_receive"
    and "exchange_sheep_value_int price_n price_d max_sheep_send
        max_wheat_receive \<le> sint max_sheep_send * sint price_d"
    and "exchange_sheep_value_int price_n price_d max_sheep_send
        max_wheat_receive \<le> sint max_wheat_receive * sint price_n"
  text \<open>
    Proof sketch: this is the symmetric minimum argument for the reversed
    offer value.
  \<close>
  using pre
  by (auto simp add: exchange_v10_pre_def exchange_sheep_value_int_def
      min_def)

lemma exchange_wheat_value_word:
  assumes pre: "exchange_v10_pre price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive"
  defines "value \<equiv>
    min
      (word_of_int (sint max_wheat_send * sint price_n) :: uint128)
      (word_of_int (sint max_sheep_receive * sint price_d))"
  shows "uint value =
    exchange_wheat_value_int price_n price_d max_wheat_send max_sheep_receive"
  text \<open>
    Proof sketch: the established multiplication range theorem identifies each
    128-bit word with its exact non-negative product; unsigned minimum then
    commutes with @{const uint}.
  \<close>
proof -
  from pre have nonnegative:
      "0 \<le> sint max_wheat_send" "0 \<le> sint price_n"
      "0 \<le> sint max_sheep_receive" "0 \<le> sint price_d"
    by (simp_all add: exchange_v10_pre_def)
  have send_value:
      "uint (word_of_int (sint max_wheat_send * sint price_n) ::
        uint128) = sint max_wheat_send * sint price_n"
    using big_multiply_uint_value
      [of max_wheat_send "scast price_n"] nonnegative
    by (simp add: sint_scast_int32_int64)
  have receive_value:
      "uint (word_of_int (sint max_sheep_receive * sint price_d) ::
        uint128) = sint max_sheep_receive * sint price_d"
    using big_multiply_uint_value
      [of max_sheep_receive "scast price_d"] nonnegative
    by (simp add: sint_scast_int32_int64)
  show ?thesis
    unfolding value_def exchange_wheat_value_int_def
    by (simp only: uint_min_word send_value receive_value)
qed

lemma exchange_sheep_value_word:
  assumes pre: "exchange_v10_pre price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive"
  defines "value \<equiv>
    min
      (word_of_int (sint max_sheep_send * sint price_d) :: uint128)
      (word_of_int (sint max_wheat_receive * sint price_n))"
  shows "uint value =
    exchange_sheep_value_int price_n price_d max_sheep_send max_wheat_receive"
  text \<open>
    Proof sketch: apply the same exact-product and unsigned-minimum argument to
    the price and maxima in their reversed order.
  \<close>
proof -
  from pre have nonnegative:
      "0 \<le> sint max_sheep_send" "0 \<le> sint price_d"
      "0 \<le> sint max_wheat_receive" "0 \<le> sint price_n"
    by (simp_all add: exchange_v10_pre_def)
  have send_value:
      "uint (word_of_int (sint max_sheep_send * sint price_d) ::
        uint128) = sint max_sheep_send * sint price_d"
    using big_multiply_uint_value
      [of max_sheep_send "scast price_d"] nonnegative
    by (simp add: sint_scast_int32_int64)
  have receive_value:
      "uint (word_of_int (sint max_wheat_receive * sint price_n) ::
        uint128) = sint max_wheat_receive * sint price_n"
    using big_multiply_uint_value
      [of max_wheat_receive "scast price_n"] nonnegative
    by (simp add: sint_scast_int32_int64)
  show ?thesis
    unfolding value_def exchange_sheep_value_int_def
    by (simp only: uint_min_word send_value receive_value)
qed

lemma exchange_amounts_strict_send_bounds:
  fixes price_n sheep_value wheat_value max_wheat_send max_wheat_receive
    max_sheep_send max_sheep_receive :: int
  assumes price_positive: "0 < price_n"
      and sheep_nonnegative: "0 \<le> sheep_value"
      and sheep_receive_bound:
        "sheep_value \<le> max_wheat_receive * price_n"
      and wheat_stays: "sheep_value < wheat_value"
      and wheat_send_bound: "wheat_value \<le> max_wheat_send * price_n"
      and sheep_send_nonnegative: "0 \<le> max_sheep_send"
      and sheep_receive_nonnegative: "0 \<le> max_sheep_receive"
  shows "0 \<le> sheep_value div price_n"
    and "sheep_value div price_n \<le>
      min max_wheat_receive max_wheat_send"
    and "0 \<le> min max_sheep_send max_sheep_receive"
    and "min max_sheep_send max_sheep_receive \<le>
      min max_sheep_receive max_sheep_send"
  text \<open>
    Proof sketch: floor division preserves non-negativity and each value bound
    yields one wheat maximum.  The strict value ordering supplies the other;
    the sheep output is the signed minimum directly.
  \<close>
proof -
  show "0 \<le> sheep_value div price_n"
    using sheep_nonnegative price_positive
    by (simp add: pos_imp_zdiv_nonneg_iff)
  have send_product_bound:
      "sheep_value \<le> max_wheat_send * price_n"
    using wheat_stays wheat_send_bound by linarith
  have receive:
      "sheep_value div price_n \<le> max_wheat_receive"
    using int_div_upper_bound [OF price_positive sheep_receive_bound] .
  have send: "sheep_value div price_n \<le> max_wheat_send"
    using int_div_upper_bound [OF price_positive send_product_bound] .
  from receive send show "sheep_value div price_n \<le>
      min max_wheat_receive max_wheat_send"
    by simp
  show "0 \<le> min max_sheep_send max_sheep_receive"
    using sheep_send_nonnegative sheep_receive_nonnegative by simp
  show "min max_sheep_send max_sheep_receive \<le>
      min max_sheep_receive max_sheep_send"
    by (simp add: min.commute)
qed

lemma exchange_amounts_wheat_stays_up_bounds:
  fixes price_n price_d sheep_value wheat_value max_wheat_send
    max_wheat_receive max_sheep_send max_sheep_receive wheat_receive
    sheep_send :: int
  assumes price_n_positive: "0 < price_n"
      and price_d_positive: "0 < price_d"
      and sheep_nonnegative: "0 \<le> sheep_value"
      and sheep_wheat_receive_bound:
        "sheep_value \<le> max_wheat_receive * price_n"
      and sheep_sheep_send_bound:
        "sheep_value \<le> max_sheep_send * price_d"
      and wheat_stays: "sheep_value < wheat_value"
      and wheat_wheat_send_bound:
        "wheat_value \<le> max_wheat_send * price_n"
      and wheat_sheep_receive_bound:
        "wheat_value \<le> max_sheep_receive * price_d"
  defines "wheat_receive \<equiv> sheep_value div price_n"
    and "sheep_send \<equiv>
      (wheat_receive * price_n + price_d - 1) div price_d"
  shows "0 \<le> wheat_receive"
    and "wheat_receive \<le> min max_wheat_receive max_wheat_send"
    and "0 \<le> sheep_send"
    and "sheep_send \<le> min max_sheep_receive max_sheep_send"
  text \<open>
    Proof sketch: floor the sheep value to obtain wheat, then bound its product
    by the original value.  The ceiling bound transfers both sheep maxima; the
    strict stay ordering transfers the two opposite-offer maxima.
  \<close>
proof -
  show "0 \<le> wheat_receive"
    unfolding wheat_receive_def
    using sheep_nonnegative price_n_positive
    by (simp add: pos_imp_zdiv_nonneg_iff)
  have sheep_wheat_send_bound:
      "sheep_value \<le> max_wheat_send * price_n"
    using wheat_stays wheat_wheat_send_bound by linarith
  have receive_bound: "wheat_receive \<le> max_wheat_receive"
    unfolding wheat_receive_def
    using int_div_upper_bound
      [OF price_n_positive sheep_wheat_receive_bound] .
  have send_bound: "wheat_receive \<le> max_wheat_send"
    unfolding wheat_receive_def
    using int_div_upper_bound
      [OF price_n_positive sheep_wheat_send_bound] .
  from receive_bound send_bound show
      "wheat_receive \<le> min max_wheat_receive max_wheat_send"
    by simp
  have wheat_product_nonnegative: "0 \<le> wheat_receive * price_n"
    using \<open>0 \<le> wheat_receive\<close> price_n_positive by simp
  have wheat_product_le_sheep:
      "wheat_receive * price_n \<le> sheep_value"
    unfolding wheat_receive_def
    using int_div_mult_le [OF price_n_positive] .
  show "0 \<le> sheep_send"
    unfolding sheep_send_def
    using int_ceiling_div_nonnegative
      [OF wheat_product_nonnegative price_d_positive] .
  have sheep_send_limit: "sheep_send \<le> max_sheep_send"
    unfolding sheep_send_def
    using int_ceiling_div_upper_bound
      [OF price_d_positive wheat_product_nonnegative]
      wheat_product_le_sheep sheep_sheep_send_bound
    by (meson order_trans)
  have wheat_product_receive_bound:
      "wheat_receive * price_n \<le> max_sheep_receive * price_d"
    using wheat_product_le_sheep wheat_stays wheat_sheep_receive_bound
    by linarith
  have sheep_receive_limit: "sheep_send \<le> max_sheep_receive"
    unfolding sheep_send_def
    using int_ceiling_div_upper_bound
      [OF price_d_positive wheat_product_nonnegative
          wheat_product_receive_bound] .
  from sheep_receive_limit sheep_send_limit show
      "sheep_send \<le> min max_sheep_receive max_sheep_send"
    by simp
qed

lemma exchange_amounts_wheat_stays_down_bounds:
  fixes price_n price_d sheep_value wheat_value max_wheat_send
    max_wheat_receive max_sheep_send max_sheep_receive wheat_receive
    sheep_send :: int
  assumes price_n_positive: "0 < price_n"
      and price_d_positive: "0 < price_d"
      and sheep_nonnegative: "0 \<le> sheep_value"
      and sheep_wheat_receive_bound:
        "sheep_value \<le> max_wheat_receive * price_n"
      and sheep_sheep_send_bound:
        "sheep_value \<le> max_sheep_send * price_d"
      and wheat_stays: "sheep_value < wheat_value"
      and wheat_wheat_send_bound:
        "wheat_value \<le> max_wheat_send * price_n"
      and wheat_sheep_receive_bound:
        "wheat_value \<le> max_sheep_receive * price_d"
  defines "sheep_send \<equiv> sheep_value div price_d"
    and "wheat_receive \<equiv> sheep_send * price_d div price_n"
  shows "0 \<le> wheat_receive"
    and "wheat_receive \<le> min max_wheat_receive max_wheat_send"
    and "0 \<le> sheep_send"
    and "sheep_send \<le> min max_sheep_receive max_sheep_send"
  text \<open>
    Proof sketch: this branch floors first in sheep units and then in wheat
    units.  Each quotient product is below its numerator, so the two value
    minima and the strict stay ordering provide all four maxima.
  \<close>
proof -
  show "0 \<le> sheep_send"
    unfolding sheep_send_def
    using sheep_nonnegative price_d_positive
    by (simp add: pos_imp_zdiv_nonneg_iff)
  have sheep_receive_product_bound:
      "sheep_value \<le> max_sheep_receive * price_d"
    using wheat_stays wheat_sheep_receive_bound by linarith
  have receive_bound: "sheep_send \<le> max_sheep_receive"
    unfolding sheep_send_def
    using int_div_upper_bound
      [OF price_d_positive sheep_receive_product_bound] .
  have send_bound: "sheep_send \<le> max_sheep_send"
    unfolding sheep_send_def
    using int_div_upper_bound
      [OF price_d_positive sheep_sheep_send_bound] .
  from receive_bound send_bound show
      "sheep_send \<le> min max_sheep_receive max_sheep_send"
    by simp
  have sheep_product_nonnegative: "0 \<le> sheep_send * price_d"
    using \<open>0 \<le> sheep_send\<close> price_d_positive by simp
  have sheep_product_le_value:
      "sheep_send * price_d \<le> sheep_value"
    unfolding sheep_send_def
    using int_div_mult_le [OF price_d_positive] .
  show "0 \<le> wheat_receive"
    unfolding wheat_receive_def
    using sheep_product_nonnegative price_n_positive
    by (simp add: pos_imp_zdiv_nonneg_iff)
  have wheat_receive_limit: "wheat_receive \<le> max_wheat_receive"
    unfolding wheat_receive_def
    using int_div_upper_bound
      [OF price_n_positive]
      sheep_product_le_value sheep_wheat_receive_bound
    by (meson order_trans)
  have sheep_product_send_bound:
      "sheep_send * price_d \<le> max_wheat_send * price_n"
    using sheep_product_le_value wheat_stays wheat_wheat_send_bound
    by linarith
  have wheat_send_limit: "wheat_receive \<le> max_wheat_send"
    unfolding wheat_receive_def
    using int_div_upper_bound
      [OF price_n_positive sheep_product_send_bound] .
  from wheat_receive_limit wheat_send_limit show
      "wheat_receive \<le> min max_wheat_receive max_wheat_send"
    by simp
qed

lemma exchange_amounts_sheep_stays_wheat_more_bounds:
  fixes price_n price_d wheat_value sheep_value max_wheat_send
    max_wheat_receive max_sheep_send max_sheep_receive wheat_receive
    sheep_send :: int
  assumes price_n_positive: "0 < price_n"
      and price_d_positive: "0 < price_d"
      and wheat_nonnegative: "0 \<le> wheat_value"
      and wheat_wheat_send_bound:
        "wheat_value \<le> max_wheat_send * price_n"
      and wheat_sheep_receive_bound:
        "wheat_value \<le> max_sheep_receive * price_d"
      and sheep_stays: "wheat_value \<le> sheep_value"
      and sheep_wheat_receive_bound:
        "sheep_value \<le> max_wheat_receive * price_n"
      and sheep_sheep_send_bound:
        "sheep_value \<le> max_sheep_send * price_d"
  defines "wheat_receive \<equiv> wheat_value div price_n"
    and "sheep_send \<equiv> wheat_receive * price_n div price_d"
  shows "0 \<le> wheat_receive"
    and "wheat_receive \<le> min max_wheat_receive max_wheat_send"
    and "0 \<le> sheep_send"
    and "sheep_send \<le> min max_sheep_receive max_sheep_send"
  text \<open>
    Proof sketch: floor the smaller wheat value twice.  Its own two product
    bounds and its ordering below the sheep value transfer the four maxima.
  \<close>
proof -
  show "0 \<le> wheat_receive"
    unfolding wheat_receive_def
    using wheat_nonnegative price_n_positive
    by (simp add: pos_imp_zdiv_nonneg_iff)
  have wheat_receive_product_bound:
      "wheat_value \<le> max_wheat_receive * price_n"
    using sheep_stays sheep_wheat_receive_bound by linarith
  have receive_bound: "wheat_receive \<le> max_wheat_receive"
    unfolding wheat_receive_def
    using int_div_upper_bound
      [OF price_n_positive wheat_receive_product_bound] .
  have send_bound: "wheat_receive \<le> max_wheat_send"
    unfolding wheat_receive_def
    using int_div_upper_bound
      [OF price_n_positive wheat_wheat_send_bound] .
  from receive_bound send_bound show
      "wheat_receive \<le> min max_wheat_receive max_wheat_send"
    by simp
  have wheat_product_nonnegative: "0 \<le> wheat_receive * price_n"
    using \<open>0 \<le> wheat_receive\<close> price_n_positive by simp
  have wheat_product_le_value:
      "wheat_receive * price_n \<le> wheat_value"
    unfolding wheat_receive_def
    using int_div_mult_le [OF price_n_positive] .
  show "0 \<le> sheep_send"
    unfolding sheep_send_def
    using wheat_product_nonnegative price_d_positive
    by (simp add: pos_imp_zdiv_nonneg_iff)
  have sheep_receive_limit: "sheep_send \<le> max_sheep_receive"
    unfolding sheep_send_def
    using int_div_upper_bound [OF price_d_positive]
      wheat_product_le_value wheat_sheep_receive_bound
    by (meson order_trans)
  have wheat_product_send_bound:
      "wheat_receive * price_n \<le> max_sheep_send * price_d"
    using wheat_product_le_value sheep_stays sheep_sheep_send_bound
    by linarith
  have sheep_send_limit: "sheep_send \<le> max_sheep_send"
    unfolding sheep_send_def
    using int_div_upper_bound
      [OF price_d_positive wheat_product_send_bound] .
  from sheep_receive_limit sheep_send_limit show
      "sheep_send \<le> min max_sheep_receive max_sheep_send"
    by simp
qed

lemma exchange_amounts_sheep_stays_sheep_more_bounds:
  fixes price_n price_d wheat_value sheep_value max_wheat_send
    max_wheat_receive max_sheep_send max_sheep_receive wheat_receive
    sheep_send :: int
  assumes price_n_positive: "0 < price_n"
      and price_d_positive: "0 < price_d"
      and wheat_nonnegative: "0 \<le> wheat_value"
      and wheat_wheat_send_bound:
        "wheat_value \<le> max_wheat_send * price_n"
      and wheat_sheep_receive_bound:
        "wheat_value \<le> max_sheep_receive * price_d"
      and sheep_stays: "wheat_value \<le> sheep_value"
      and sheep_wheat_receive_bound:
        "sheep_value \<le> max_wheat_receive * price_n"
      and sheep_sheep_send_bound:
        "sheep_value \<le> max_sheep_send * price_d"
  defines "sheep_send \<equiv> wheat_value div price_d"
    and "wheat_receive \<equiv>
      (sheep_send * price_d + price_n - 1) div price_n"
  shows "0 \<le> wheat_receive"
    and "wheat_receive \<le> min max_wheat_receive max_wheat_send"
    and "0 \<le> sheep_send"
    and "sheep_send \<le> min max_sheep_receive max_sheep_send"
  text \<open>
    Proof sketch: floor the smaller wheat value to sheep, then apply the
    ceiling bound to the remaining conversion.  The value ordering supplies
    the maxima originating in the other offer.
  \<close>
proof -
  show "0 \<le> sheep_send"
    unfolding sheep_send_def
    using wheat_nonnegative price_d_positive
    by (simp add: pos_imp_zdiv_nonneg_iff)
  have wheat_sheep_send_bound:
      "wheat_value \<le> max_sheep_send * price_d"
    using sheep_stays sheep_sheep_send_bound by linarith
  have receive_bound: "sheep_send \<le> max_sheep_receive"
    unfolding sheep_send_def
    using int_div_upper_bound
      [OF price_d_positive wheat_sheep_receive_bound] .
  have send_bound: "sheep_send \<le> max_sheep_send"
    unfolding sheep_send_def
    using int_div_upper_bound
      [OF price_d_positive wheat_sheep_send_bound] .
  from receive_bound send_bound show
      "sheep_send \<le> min max_sheep_receive max_sheep_send"
    by simp
  have sheep_product_nonnegative: "0 \<le> sheep_send * price_d"
    using \<open>0 \<le> sheep_send\<close> price_d_positive by simp
  have sheep_product_le_value:
      "sheep_send * price_d \<le> wheat_value"
    unfolding sheep_send_def
    using int_div_mult_le [OF price_d_positive] .
  show "0 \<le> wheat_receive"
    unfolding wheat_receive_def
    using int_ceiling_div_nonnegative
      [OF sheep_product_nonnegative price_n_positive] .
  have wheat_send_limit: "wheat_receive \<le> max_wheat_send"
    unfolding wheat_receive_def
    using int_ceiling_div_upper_bound
      [OF price_n_positive sheep_product_nonnegative]
      sheep_product_le_value wheat_wheat_send_bound
    by (meson order_trans)
  have sheep_product_receive_bound:
      "sheep_send * price_d \<le> max_wheat_receive * price_n"
    using sheep_product_le_value sheep_stays sheep_wheat_receive_bound
    by linarith
  have wheat_receive_limit: "wheat_receive \<le> max_wheat_receive"
    unfolding wheat_receive_def
    using int_ceiling_div_upper_bound
      [OF price_n_positive sheep_product_nonnegative
          sheep_product_receive_bound] .
  from wheat_receive_limit wheat_send_limit show
      "wheat_receive \<le> min max_wheat_receive max_wheat_send"
    by simp
qed

theorem exchange_v10_amounts_int_bounds:
  fixes amounts :: "int \<times> int"
  assumes pre: "exchange_v10_pre price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive"
    and amounts:
      "amounts = exchange_v10_amounts_int price_n price_d max_wheat_send
        max_wheat_receive max_sheep_send max_sheep_receive rounding"
  shows "0 \<le> fst amounts"
    and "fst amounts \<le>
      min (sint max_wheat_receive) (sint max_wheat_send)"
    and "0 \<le> snd amounts"
    and "snd amounts \<le>
      min (sint max_sheep_receive) (sint max_sheep_send)"
  text \<open>
    Proof sketch: split on which exact offer value is smaller, the rounding
    constructor, and the price ordering.  Each of the five C++ calculation
    branches is discharged by its preceding arithmetic-bound lemma.
  \<close>
proof -
  let ?W = "exchange_wheat_value_int price_n price_d max_wheat_send
    max_sheep_receive"
  let ?S = "exchange_sheep_value_int price_n price_d max_sheep_send
    max_wheat_receive"
  from pre have pn: "0 < sint price_n" and pd: "0 < sint price_d"
    and ws: "0 \<le> sint max_wheat_send"
    and wr: "0 \<le> sint max_wheat_receive"
    and ss: "0 \<le> sint max_sheep_send"
    and sr: "0 \<le> sint max_sheep_receive"
    by (simp_all add: exchange_v10_pre_def)
  have W0: "0 \<le> ?W"
    and Wws: "?W \<le> sint max_wheat_send * sint price_n"
    and Wsr: "?W \<le> sint max_sheep_receive * sint price_d"
    using exchange_wheat_value_int_bounds [OF pre] by auto
  have S0: "0 \<le> ?S"
    and Sss: "?S \<le> sint max_sheep_send * sint price_d"
    and Swr: "?S \<le> sint max_wheat_receive * sint price_n"
    using exchange_sheep_value_int_bounds [OF pre] by auto
  have result:
      "0 \<le> fst amounts \<and>
       fst amounts \<le> min (sint max_wheat_receive) (sint max_wheat_send) \<and>
       0 \<le> snd amounts \<and>
       snd amounts \<le> min (sint max_sheep_receive) (sint max_sheep_send)"
  proof (cases "?W > ?S")
    case wheat_stays: True
    show ?thesis
    proof (cases rounding)
      case Exchange_Strict_Send
      note bounds = exchange_amounts_strict_send_bounds
        [OF pn S0 Swr wheat_stays Wws ss sr]
      from bounds amounts wheat_stays Exchange_Strict_Send show ?thesis
        by (simp add: exchange_v10_amounts_int_def Let_def)
    next
      case Exchange_Strict_Receive
      note bounds = exchange_amounts_wheat_stays_up_bounds
        [OF pn pd S0 Swr Sss wheat_stays Wws Wsr]
      from bounds amounts wheat_stays Exchange_Strict_Receive show ?thesis
        by (simp add: exchange_v10_amounts_int_def Let_def)
    next
      case Exchange_Normal
      show ?thesis
      proof (cases "sint price_n > sint price_d")
        case True
        note bounds = exchange_amounts_wheat_stays_up_bounds
          [OF pn pd S0 Swr Sss wheat_stays Wws Wsr]
        from bounds amounts wheat_stays Exchange_Normal True show ?thesis
          by (simp add: exchange_v10_amounts_int_def Let_def)
      next
        case False
        note bounds = exchange_amounts_wheat_stays_down_bounds
          [OF pn pd S0 Swr Sss wheat_stays Wws Wsr]
        from bounds amounts wheat_stays Exchange_Normal False show ?thesis
          by (simp add: exchange_v10_amounts_int_def Let_def)
      qed
    qed
  next
    case sheep_stays: False
    then have WS: "?W \<le> ?S" by simp
    show ?thesis
    proof (cases "sint price_n > sint price_d")
      case True
      note bounds = exchange_amounts_sheep_stays_wheat_more_bounds
        [OF pn pd W0 Wws Wsr WS Swr Sss]
      from bounds amounts sheep_stays True show ?thesis
        by (simp add: exchange_v10_amounts_int_def Let_def)
    next
      case False
      note bounds = exchange_amounts_sheep_stays_sheep_more_bounds
        [OF pn pd W0 Wws Wsr WS Swr Sss]
      from bounds amounts sheep_stays False show ?thesis
        by (simp add: exchange_v10_amounts_int_def Let_def)
    qed
  qed
  from result show "0 \<le> fst amounts" by simp
  from result show "fst amounts \<le>
      min (sint max_wheat_receive) (sint max_wheat_send)" by simp
  from result show "0 \<le> snd amounts" by simp
  from result show "snd amounts \<le>
      min (sint max_sheep_receive) (sint max_sheep_send)" by simp
qed

lemma exchange_v10_amounts_wheat_stays_strict_send:
  assumes pre: "exchange_v10_pre price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive"
    and sheep_value:
      "uint sheep_word =
        exchange_sheep_value_int price_n price_d max_sheep_send
          max_wheat_receive"
  shows "exchange_v10_amounts price_n price_d wheat_word sheep_word
      max_wheat_send max_wheat_receive max_sheep_send max_sheep_receive True
      Exchange_Strict_Send options =
    Cxx_Ok
      (word_of_int
        (exchange_sheep_value_int price_n price_d max_sheep_send
          max_wheat_receive div sint price_n),
       word_of_int
        (min (sint max_sheep_send) (sint max_sheep_receive)))"
  text \<open>
    Proof sketch: the reversed offer value is bounded by
    @{term "sint max_wheat_receive * sint price_n"}, so its round-down division
    fits signed 64 bits.  The second component is exactly the signed minimum.
  \<close>
proof -
  let ?S = "exchange_sheep_value_int price_n price_d max_sheep_send
    max_wheat_receive"
  from pre have pn: "0 < sint price_n"
    by (simp add: exchange_v10_pre_def)
  have pn_wide: "0 < sint (scast price_n :: int64)"
    using pn by (simp add: sint_scast_int32_int64)
  have S_bound: "?S \<le> sint max_wheat_receive * sint price_n"
    using exchange_sheep_value_int_bounds [OF pre] by simp
  have word_bound:
      "uint sheep_word \<le>
        sint max_wheat_receive * sint (scast price_n :: int64)"
    using sheep_value S_bound by (simp add: sint_scast_int32_int64)
  have divide:
      "big_divide_or_throw128 sheep_word (scast price_n)
        Cxx_Round_Down = Cxx_Ok (word_of_int (?S div sint price_n))"
    using big_divide_or_throw128_down_bounded(1)
      [OF pn_wide word_bound sint64_upper_bound] sheep_value
    by (simp add: sint_scast_int32_int64)
  show ?thesis
    unfolding exchange_v10_amounts_def signed_min64_word
    using divide by simp
qed

lemma exchange_v10_amounts_wheat_stays_up:
  assumes pre: "exchange_v10_pre price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive"
    and sheep_value:
      "uint sheep_word =
        exchange_sheep_value_int price_n price_d max_sheep_send
          max_wheat_receive"
    and not_strict_send: "rounding \<noteq> Exchange_Strict_Send"
    and up_branch:
      "sint price_n > sint price_d \<or>
       rounding = Exchange_Strict_Receive"
  shows "exchange_v10_amounts price_n price_d wheat_word sheep_word
      max_wheat_send max_wheat_receive max_sheep_send max_sheep_receive True
      rounding options =
    (let wheat_receive =
        exchange_sheep_value_int price_n price_d max_sheep_send
          max_wheat_receive div sint price_n;
       sheep_send =
        (wheat_receive * sint price_n + sint price_d - 1) div sint price_d
     in Cxx_Ok (word_of_int wheat_receive, word_of_int sheep_send))"
  text \<open>
    Proof sketch: the first round-down quotient is bounded by the wheat-receive
    maximum.  Its product remains below the sheep value, so the round-up
    quotient is bounded by the sheep-send maximum and both checked helpers
    return the exact integer formulas.
  \<close>
proof -
  let ?S = "exchange_sheep_value_int price_n price_d max_sheep_send
    max_wheat_receive"
  let ?WR = "?S div sint price_n"
  let ?SS = "(?WR * sint price_n + sint price_d - 1) div sint price_d"
  from pre have pn: "0 < sint price_n" and pd: "0 < sint price_d"
    by (simp_all add: exchange_v10_pre_def)
  have pn_wide: "0 < sint (scast price_n :: int64)"
    using pn by (simp add: sint_scast_int32_int64)
  have pd_wide: "0 < sint (scast price_d :: int64)"
    using pd by (simp add: sint_scast_int32_int64)
  have S0: "0 \<le> ?S"
    and S_wr: "?S \<le> sint max_wheat_receive * sint price_n"
    and S_ss: "?S \<le> sint max_sheep_send * sint price_d"
    using exchange_sheep_value_int_bounds [OF pre] by auto
  have word_pn_bound:
      "uint sheep_word \<le>
        sint max_wheat_receive * sint (scast price_n :: int64)"
    using sheep_value S_wr by (simp add: sint_scast_int32_int64)
  note first = big_divide_or_throw128_down_bounded
    [OF pn_wide word_pn_bound sint64_upper_bound]
  have first_result:
      "big_divide_or_throw128 sheep_word (scast price_n)
        Cxx_Round_Down = Cxx_Ok (word_of_int ?WR)"
    using first(1) sheep_value by (simp add: sint_scast_int32_int64)
  have first_sint:
      "sint (word_of_int ?WR :: int64) = ?WR"
    using first(2) sheep_value by (simp add: sint_scast_int32_int64)
  have WR0: "0 \<le> ?WR"
    using S0 pn by (simp add: pos_imp_zdiv_nonneg_iff)
  have first_word_nonnegative:
      "0 \<le> sint (word_of_int ?WR :: int64)"
    using first_sint WR0 by simp
  have product0: "0 \<le> ?WR * sint price_n"
    using WR0 pn by simp
  have product_le_S: "?WR * sint price_n \<le> ?S"
    using int_div_mult_le [OF pn] .
  have SS_to_max: "?SS \<le> sint max_sheep_send"
    using int_ceiling_div_upper_bound
      [OF pd product0]
      product_le_S S_ss
    by (meson order_trans)
  have SS_max: "?SS \<le> int64_max_int"
    using SS_to_max sint64_upper_bound [of max_sheep_send] by linarith
  have rounded_bound:
      "rounded_quotient
        (sint (word_of_int ?WR :: int64) *
          sint (scast price_n :: int64))
        (sint (scast price_d :: int64)) Cxx_Round_Up
       \<le> int64_max_int"
    using first_sint SS_max
    by (simp add: sint_scast_int32_int64)
  have second_result:
      "big_divide_or_throw (word_of_int ?WR) (scast price_n)
        (scast price_d) Cxx_Round_Up = Cxx_Ok (word_of_int ?SS)"
    using big_divide_or_throw_success(1)
      [OF first_word_nonnegative less_imp_le [OF pn_wide] pd_wide
          rounded_bound]
      first_sint
    by (simp add: sint_scast_int32_int64)
  show ?thesis
    unfolding exchange_v10_amounts_def
    using not_strict_send up_branch first_result second_result
    by (simp add: Let_def)
qed

lemma exchange_v10_amounts_wheat_stays_down:
  assumes pre: "exchange_v10_pre price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive"
    and sheep_value:
      "uint sheep_word =
        exchange_sheep_value_int price_n price_d max_sheep_send
          max_wheat_receive"
    and not_strict_send: "rounding \<noteq> Exchange_Strict_Send"
    and down_branch:
      "\<not> (sint price_n > sint price_d \<or>
        rounding = Exchange_Strict_Receive)"
    and plain_cap: "\<not> symmetric_exact_receive_cap options"
  shows "exchange_v10_amounts price_n price_d wheat_word sheep_word
      max_wheat_send max_wheat_receive max_sheep_send max_sheep_receive True
      rounding options =
    (let sheep_send =
        exchange_sheep_value_int price_n price_d max_sheep_send
          max_wheat_receive div sint price_d;
       wheat_receive = sheep_send * sint price_d div sint price_n
     in Cxx_Ok (word_of_int wheat_receive, word_of_int sheep_send))"
  text \<open>
    Proof sketch: with the symmetric receive cap disabled the branch divides
    the plain sheep value.  The first floor is bounded by the sheep-send
    maximum.  Its exact product stays below the sheep value, so the second
    floor is bounded by the wheat-receive maximum and both checked divisions
    succeed exactly.
  \<close>
proof -
  let ?S = "exchange_sheep_value_int price_n price_d max_sheep_send
    max_wheat_receive"
  let ?SS = "?S div sint price_d"
  let ?WR = "?SS * sint price_d div sint price_n"
  from pre have pn: "0 < sint price_n" and pd: "0 < sint price_d"
    by (simp_all add: exchange_v10_pre_def)
  have pn_wide: "0 < sint (scast price_n :: int64)"
    using pn by (simp add: sint_scast_int32_int64)
  have pd_wide: "0 < sint (scast price_d :: int64)"
    using pd by (simp add: sint_scast_int32_int64)
  have S0: "0 \<le> ?S"
    and S_ss: "?S \<le> sint max_sheep_send * sint price_d"
    and S_wr: "?S \<le> sint max_wheat_receive * sint price_n"
    using exchange_sheep_value_int_bounds [OF pre] by auto
  have word_pd_bound:
      "uint sheep_word \<le>
        sint max_sheep_send * sint (scast price_d :: int64)"
    using sheep_value S_ss by (simp add: sint_scast_int32_int64)
  note first = big_divide_or_throw128_down_bounded
    [OF pd_wide word_pd_bound sint64_upper_bound]
  have first_result:
      "big_divide_or_throw128 sheep_word (scast price_d)
        Cxx_Round_Down = Cxx_Ok (word_of_int ?SS)"
    using first(1) sheep_value by (simp add: sint_scast_int32_int64)
  have first_sint:
      "sint (word_of_int ?SS :: int64) = ?SS"
    using first(2) sheep_value by (simp add: sint_scast_int32_int64)
  have SS0: "0 \<le> ?SS"
    using S0 pd by (simp add: pos_imp_zdiv_nonneg_iff)
  have first_word_nonnegative:
      "0 \<le> sint (word_of_int ?SS :: int64)"
    using first_sint SS0 by simp
  have product0: "0 \<le> ?SS * sint price_d"
    using SS0 pd by simp
  have product_le_S: "?SS * sint price_d \<le> ?S"
    using int_div_mult_le [OF pd] .
  have WR_to_max: "?WR \<le> sint max_wheat_receive"
    using int_div_upper_bound [OF pn]
      product_le_S S_wr
    by (meson order_trans)
  have WR_max: "?WR \<le> int64_max_int"
    using WR_to_max sint64_upper_bound [of max_wheat_receive] by linarith
  have rounded_bound:
      "rounded_quotient
        (sint (word_of_int ?SS :: int64) *
          sint (scast price_d :: int64))
        (sint (scast price_n :: int64)) Cxx_Round_Down
       \<le> int64_max_int"
    using first_sint WR_max
    by (simp add: sint_scast_int32_int64)
  have second_result:
      "big_divide_or_throw (word_of_int ?SS) (scast price_d)
        (scast price_n) Cxx_Round_Down = Cxx_Ok (word_of_int ?WR)"
    using big_divide_or_throw_success(1)
      [OF first_word_nonnegative less_imp_le [OF pd_wide] pn_wide
          rounded_bound]
      first_sint
    by (simp add: sint_scast_int32_int64)
  show ?thesis
    unfolding exchange_v10_amounts_def
    using not_strict_send down_branch plain_cap first_result second_result
    by (simp add: Let_def)
qed

lemma exchange_v10_amounts_sheep_stays_wheat_more:
  assumes pre: "exchange_v10_pre price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive"
    and wheat_value:
      "uint wheat_word =
        exchange_wheat_value_int price_n price_d max_wheat_send
          max_sheep_receive"
    and wheat_more: "sint price_n > sint price_d"
  shows "exchange_v10_amounts price_n price_d wheat_word sheep_word
      max_wheat_send max_wheat_receive max_sheep_send max_sheep_receive False
      rounding \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr> =
    (let wheat_receive =
        exchange_wheat_value_int price_n price_d max_wheat_send
          max_sheep_receive div sint price_n;
       sheep_send = wheat_receive * sint price_n div sint price_d
     in Cxx_Ok (word_of_int wheat_receive, word_of_int sheep_send))"
  text \<open>
    Proof sketch: divide the wheat value down by the numerator, then divide its
    exact product down by the denominator.  The two defining product bounds of
    the wheat value keep both narrowing operations in signed-64 range.
  \<close>
proof -
  let ?W = "exchange_wheat_value_int price_n price_d max_wheat_send
    max_sheep_receive"
  let ?WR = "?W div sint price_n"
  let ?SS = "?WR * sint price_n div sint price_d"
  from pre have pn: "0 < sint price_n" and pd: "0 < sint price_d"
    by (simp_all add: exchange_v10_pre_def)
  have pn_wide: "0 < sint (scast price_n :: int64)"
    using pn by (simp add: sint_scast_int32_int64)
  have pd_wide: "0 < sint (scast price_d :: int64)"
    using pd by (simp add: sint_scast_int32_int64)
  have W0: "0 \<le> ?W"
    and W_ws: "?W \<le> sint max_wheat_send * sint price_n"
    and W_sr: "?W \<le> sint max_sheep_receive * sint price_d"
    using exchange_wheat_value_int_bounds [OF pre] by auto
  have word_pn_bound:
      "uint wheat_word \<le>
        sint max_wheat_send * sint (scast price_n :: int64)"
    using wheat_value W_ws by (simp add: sint_scast_int32_int64)
  note first = big_divide_or_throw128_down_bounded
    [OF pn_wide word_pn_bound sint64_upper_bound]
  have first_result:
      "big_divide_or_throw128 wheat_word (scast price_n)
        Cxx_Round_Down = Cxx_Ok (word_of_int ?WR)"
    using first(1) wheat_value by (simp add: sint_scast_int32_int64)
  have first_sint:
      "sint (word_of_int ?WR :: int64) = ?WR"
    using first(2) wheat_value by (simp add: sint_scast_int32_int64)
  have WR0: "0 \<le> ?WR"
    using W0 pn by (simp add: pos_imp_zdiv_nonneg_iff)
  have first_word_nonnegative:
      "0 \<le> sint (word_of_int ?WR :: int64)"
    using first_sint WR0 by simp
  have product0: "0 \<le> ?WR * sint price_n"
    using WR0 pn by simp
  have product_le_W: "?WR * sint price_n \<le> ?W"
    using int_div_mult_le [OF pn] .
  have SS_to_max: "?SS \<le> sint max_sheep_receive"
    using int_div_upper_bound [OF pd]
      product_le_W W_sr
    by (meson order_trans)
  have SS_max: "?SS \<le> int64_max_int"
    using SS_to_max sint64_upper_bound [of max_sheep_receive] by linarith
  have rounded_bound:
      "rounded_quotient
        (sint (word_of_int ?WR :: int64) *
          sint (scast price_n :: int64))
        (sint (scast price_d :: int64)) Cxx_Round_Down
       \<le> int64_max_int"
    using first_sint SS_max
    by (simp add: sint_scast_int32_int64)
  have second_result:
      "big_divide_or_throw (word_of_int ?WR) (scast price_n)
        (scast price_d) Cxx_Round_Down = Cxx_Ok (word_of_int ?SS)"
    using big_divide_or_throw_success(1)
      [OF first_word_nonnegative less_imp_le [OF pn_wide] pd_wide
          rounded_bound]
      first_sint
    by (simp add: sint_scast_int32_int64)
  show ?thesis
    unfolding exchange_v10_amounts_def
    using wheat_more first_result second_result
    by (simp add: Let_def)
qed

lemma exchange_v10_amounts_sheep_stays_sheep_more:
  assumes pre: "exchange_v10_pre price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive"
    and wheat_value:
      "uint wheat_word =
        exchange_wheat_value_int price_n price_d max_wheat_send
          max_sheep_receive"
    and sheep_more: "\<not> sint price_n > sint price_d"
  shows "exchange_v10_amounts price_n price_d wheat_word sheep_word
      max_wheat_send max_wheat_receive max_sheep_send max_sheep_receive False
      rounding options =
    (let sheep_send =
        exchange_wheat_value_int price_n price_d max_wheat_send
          max_sheep_receive div sint price_d;
       wheat_receive =
        (sheep_send * sint price_d + sint price_n - 1) div sint price_n
     in Cxx_Ok (word_of_int wheat_receive, word_of_int sheep_send))"
  text \<open>
    Proof sketch: the first floor is bounded by the sheep-receive maximum.
    Its product remains below the wheat value, so the final ceiling is bounded
    by the wheat-send maximum and both checked divisions return exactly.
  \<close>
proof -
  let ?W = "exchange_wheat_value_int price_n price_d max_wheat_send
    max_sheep_receive"
  let ?SS = "?W div sint price_d"
  let ?WR = "(?SS * sint price_d + sint price_n - 1) div sint price_n"
  from pre have pn: "0 < sint price_n" and pd: "0 < sint price_d"
    by (simp_all add: exchange_v10_pre_def)
  have pn_wide: "0 < sint (scast price_n :: int64)"
    using pn by (simp add: sint_scast_int32_int64)
  have pd_wide: "0 < sint (scast price_d :: int64)"
    using pd by (simp add: sint_scast_int32_int64)
  have W0: "0 \<le> ?W"
    and W_ws: "?W \<le> sint max_wheat_send * sint price_n"
    and W_sr: "?W \<le> sint max_sheep_receive * sint price_d"
    using exchange_wheat_value_int_bounds [OF pre] by auto
  have word_pd_bound:
      "uint wheat_word \<le>
        sint max_sheep_receive * sint (scast price_d :: int64)"
    using wheat_value W_sr by (simp add: sint_scast_int32_int64)
  note first = big_divide_or_throw128_down_bounded
    [OF pd_wide word_pd_bound sint64_upper_bound]
  have first_result:
      "big_divide_or_throw128 wheat_word (scast price_d)
        Cxx_Round_Down = Cxx_Ok (word_of_int ?SS)"
    using first(1) wheat_value by (simp add: sint_scast_int32_int64)
  have first_sint:
      "sint (word_of_int ?SS :: int64) = ?SS"
    using first(2) wheat_value by (simp add: sint_scast_int32_int64)
  have SS0: "0 \<le> ?SS"
    using W0 pd by (simp add: pos_imp_zdiv_nonneg_iff)
  have first_word_nonnegative:
      "0 \<le> sint (word_of_int ?SS :: int64)"
    using first_sint SS0 by simp
  have product0: "0 \<le> ?SS * sint price_d"
    using SS0 pd by simp
  have product_le_W: "?SS * sint price_d \<le> ?W"
    using int_div_mult_le [OF pd] .
  have WR_to_max: "?WR \<le> sint max_wheat_send"
    using int_ceiling_div_upper_bound [OF pn product0]
      product_le_W W_ws
    by (meson order_trans)
  have WR_max: "?WR \<le> int64_max_int"
    using WR_to_max sint64_upper_bound [of max_wheat_send] by linarith
  have rounded_bound:
      "rounded_quotient
        (sint (word_of_int ?SS :: int64) *
          sint (scast price_d :: int64))
        (sint (scast price_n :: int64)) Cxx_Round_Up
       \<le> int64_max_int"
    using first_sint WR_max
    by (simp add: sint_scast_int32_int64)
  have second_result:
      "big_divide_or_throw (word_of_int ?SS) (scast price_d)
        (scast price_n) Cxx_Round_Up = Cxx_Ok (word_of_int ?WR)"
    using big_divide_or_throw_success(1)
      [OF first_word_nonnegative less_imp_le [OF pd_wide] pn_wide
          rounded_bound]
      first_sint
    by (simp add: sint_scast_int32_int64)
  show ?thesis
    unfolding exchange_v10_amounts_def
    using sheep_more first_result second_result
    by (simp add: Let_def)
qed

theorem exchange_v10_amounts_integer_characterization:
  fixes rounding :: exchange_rounding
    and wheat_word sheep_word :: uint128
    and amounts :: "int \<times> int"
  assumes pre: "exchange_v10_pre price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive"
  defines "wheat_word \<equiv>
    min
      (word_of_int (sint max_wheat_send * sint price_n) :: uint128)
      (word_of_int (sint max_sheep_receive * sint price_d))"
    and "sheep_word \<equiv>
    min
      (word_of_int (sint max_sheep_send * sint price_d) :: uint128)
      (word_of_int (sint max_wheat_receive * sint price_n))"
    and "amounts \<equiv>
      exchange_v10_amounts_int price_n price_d max_wheat_send
        max_wheat_receive max_sheep_send max_sheep_receive rounding"
  shows "exchange_v10_amounts price_n price_d wheat_word sheep_word
      max_wheat_send max_wheat_receive max_sheep_send max_sheep_receive
      (wheat_word > sheep_word) rounding \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr> =
    Cxx_Ok
      (word_of_int (fst amounts), word_of_int (snd amounts))"
    and "sint (word_of_int (fst amounts) :: int64) = fst amounts"
    and "sint (word_of_int (snd amounts) :: int64) = snd amounts"
  text \<open>
    Proof sketch: identify both 128-bit values with their exact integers, then
    split on the value comparison, rounding mode, and price ordering.  The five
    branch equations above give the exact pair; the global bounds theorem makes
    both re-encoded result words faithful signed-64 values.
  \<close>
proof -
  let ?W = "exchange_wheat_value_int price_n price_d max_wheat_send
    max_sheep_receive"
  let ?S = "exchange_sheep_value_int price_n price_d max_sheep_send
    max_wheat_receive"
  have W_value: "uint wheat_word = ?W"
    using exchange_wheat_value_word [OF pre]
    unfolding wheat_word_def .
  have S_value: "uint sheep_word = ?S"
    using exchange_sheep_value_word [OF pre]
    unfolding sheep_word_def .
  have stays: "(wheat_word > sheep_word) = (?W > ?S)"
    by (simp only: word_less_def W_value S_value)
  have amounts_eq:
      "amounts = exchange_v10_amounts_int price_n price_d max_wheat_send
        max_wheat_receive max_sheep_send max_sheep_receive rounding"
    unfolding amounts_def by simp
  show amount_result:
      "exchange_v10_amounts price_n price_d wheat_word sheep_word
        max_wheat_send max_wheat_receive max_sheep_send max_sheep_receive
        (wheat_word > sheep_word) rounding \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr> =
       Cxx_Ok (word_of_int (fst amounts), word_of_int (snd amounts))"
  proof (cases "?W > ?S")
    case wheat_stays: True
    have word_stays: "wheat_word > sheep_word"
      using stays wheat_stays by simp
    show ?thesis
    proof (cases rounding)
      case Exchange_Strict_Send
      note branch = exchange_v10_amounts_wheat_stays_strict_send
        [OF pre S_value, of wheat_word]
      from branch word_stays amounts_eq wheat_stays Exchange_Strict_Send
      show ?thesis
        by (simp add: exchange_v10_amounts_int_def Let_def)
    next
      case Exchange_Strict_Receive
      note branch = exchange_v10_amounts_wheat_stays_up
        [OF pre S_value, of Exchange_Strict_Receive wheat_word]
      from branch word_stays amounts_eq wheat_stays Exchange_Strict_Receive
      show ?thesis
        by (simp add: exchange_v10_amounts_int_def Let_def)
    next
      case Exchange_Normal
      show ?thesis
      proof (cases "sint price_n > sint price_d")
        case True
        note branch = exchange_v10_amounts_wheat_stays_up
          [OF pre S_value, of Exchange_Normal wheat_word]
        from branch word_stays amounts_eq wheat_stays Exchange_Normal True
        show ?thesis
          by (simp add: exchange_v10_amounts_int_def Let_def)
      next
        case False
        note branch = exchange_v10_amounts_wheat_stays_down
          [OF pre S_value, where rounding = Exchange_Normal
             and wheat_word = wheat_word]
        from branch word_stays amounts_eq wheat_stays Exchange_Normal False
        show ?thesis
          by (simp add: exchange_v10_amounts_int_def Let_def)
      qed
    qed
  next
    case sheep_stays: False
    have word_stays: "\<not> wheat_word > sheep_word"
      using stays sheep_stays by simp
    show ?thesis
    proof (cases "sint price_n > sint price_d")
      case True
      note branch = exchange_v10_amounts_sheep_stays_wheat_more
        [OF pre W_value True, of sheep_word rounding]
      from branch word_stays amounts_eq sheep_stays True show ?thesis
        by (simp add: exchange_v10_amounts_int_def Let_def)
    next
      case False
      note branch = exchange_v10_amounts_sheep_stays_sheep_more
        [OF pre W_value False, of sheep_word rounding]
      from branch word_stays amounts_eq sheep_stays False show ?thesis
        by (simp add: exchange_v10_amounts_int_def Let_def)
    qed
  qed
  have A0: "0 \<le> fst amounts"
    and A_bound:
      "fst amounts \<le> min (sint max_wheat_receive) (sint max_wheat_send)"
    and B0: "0 \<le> snd amounts"
    and B_bound:
      "snd amounts \<le> min (sint max_sheep_receive) (sint max_sheep_send)"
    using exchange_v10_amounts_int_bounds [OF pre amounts_eq] by auto
  have Amax: "fst amounts \<le> int64_max_int"
    using A_bound sint64_upper_bound [of max_wheat_receive] by linarith
  have Bmax: "snd amounts \<le> int64_max_int"
    using B_bound sint64_upper_bound [of max_sheep_receive] by linarith
  show "sint (word_of_int (fst amounts) :: int64) = fst amounts"
    using sint_word_of_int_nonnegative_int64 [OF A0 Amax] .
  show "sint (word_of_int (snd amounts) :: int64) = snd amounts"
    using sint_word_of_int_nonnegative_int64 [OF B0 Bmax] .
qed

theorem exchange_v10_without_price_error_thresholds_integer_characterization:
  fixes rounding :: exchange_rounding and amounts :: "int \<times> int"
  assumes pre: "exchange_v10_pre price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive"
  defines "amounts \<equiv>
    exchange_v10_amounts_int price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive rounding"
  shows "exchange_v10_without_price_error_thresholds_with_options price_n price_d
      max_wheat_send max_wheat_receive max_sheep_send max_sheep_receive
      rounding \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr> =
    Cxx_Ok
      (make_exchange_result
        (word_of_int (fst amounts)) (word_of_int (snd amounts))
        (exchange_wheat_value_int price_n price_d max_wheat_send
           max_sheep_receive >
         exchange_sheep_value_int price_n price_d max_sheep_send
           max_wheat_receive))"
  text \<open>
    Proof sketch: both offer-value calls succeed with their exact 128-bit
    minima under @{const exchange_v10_pre}.  Substitute the exact amount-block
    theorem, then use its signed interpretations and four bounds to prove that
    neither final runtime check is reachable.
  \<close>
proof -
  let ?WW =
    "min
      (word_of_int (sint max_wheat_send * sint price_n) :: uint128)
      (word_of_int (sint max_sheep_receive * sint price_d))"
  let ?SW =
    "min
      (word_of_int (sint max_sheep_send * sint price_d) :: uint128)
      (word_of_int (sint max_wheat_receive * sint price_n))"

  let ?W = "exchange_wheat_value_int price_n price_d max_wheat_send
    max_sheep_receive"
  let ?S = "exchange_sheep_value_int price_n price_d max_sheep_send
    max_wheat_receive"
  have first_pre:
      "calculate_offer_value_pre price_n price_d max_wheat_send
        max_sheep_receive"
    using pre by (simp add: exchange_v10_pre_def
        calculate_offer_value_pre_def)
  have second_pre:
      "calculate_offer_value_pre price_d price_n max_sheep_send
        max_wheat_receive"
    using pre by (simp add: exchange_v10_pre_def
        calculate_offer_value_pre_def)
  have first:
      "calculate_offer_value price_n price_d max_wheat_send
        max_sheep_receive = Cxx_Ok ?WW"
    using calculate_offer_value_success [OF first_pre] .
  have second:
      "calculate_offer_value price_d price_n max_sheep_send
        max_wheat_receive = Cxx_Ok ?SW"
    using calculate_offer_value_success [OF second_pre] .
  have W_value: "uint ?WW = ?W"
    using exchange_wheat_value_word [OF pre] .
  have S_value: "uint ?SW = ?S"
    using exchange_sheep_value_word [OF pre] .
  have stays: "(?WW > ?SW) = (?W > ?S)"
    by (simp only: word_less_def W_value S_value)
  have amounts_eq:
      "amounts = exchange_v10_amounts_int price_n price_d max_wheat_send
        max_wheat_receive max_sheep_send max_sheep_receive rounding"
    unfolding amounts_def by simp
  note amount_result =
    exchange_v10_amounts_integer_characterization [OF pre, of rounding]
  have amount_call:
      "exchange_v10_amounts price_n price_d ?WW ?SW max_wheat_send
        max_wheat_receive max_sheep_send max_sheep_receive (?WW > ?SW)
        rounding \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr> =
       Cxx_Ok (word_of_int (fst amounts), word_of_int (snd amounts))"
    using amount_result(1)
    unfolding amounts_def by simp
  have amount_call_integer:
      "exchange_v10_amounts price_n price_d ?WW ?SW max_wheat_send
        max_wheat_receive max_sheep_send max_sheep_receive (?W > ?S)
        rounding \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr> =
       Cxx_Ok (word_of_int (fst amounts), word_of_int (snd amounts))"
    using amount_call stays by simp
  have A_sint:
      "sint (word_of_int (fst amounts) :: int64) = fst amounts"
    using amount_result(2)
    unfolding amounts_def by simp
  have B_sint:
      "sint (word_of_int (snd amounts) :: int64) = snd amounts"
    using amount_result(3)
    unfolding amounts_def by simp
  have A0: "0 \<le> fst amounts"
    and A_bound:
      "fst amounts \<le> min (sint max_wheat_receive) (sint max_wheat_send)"
    and B0: "0 \<le> snd amounts"
    and B_bound:
      "snd amounts \<le> min (sint max_sheep_receive) (sint max_sheep_send)"
    using exchange_v10_amounts_int_bounds [OF pre amounts_eq] by auto
  show ?thesis
    unfolding exchange_v10_without_as_checked_amounts
    apply (simp only: first second cxx_bind.simps)
    apply (simp only: stays)
    apply (simp only: Let_def amount_call_integer cxx_bind.simps)
    unfolding check_exchange_v10_result_def
    using A_sint B_sint A0 A_bound B0 B_bound
    by (auto simp add: Let_def)
qed

lemma int_ceiling_product_div_eq_zero_iff:
  fixes x multiplier divisor :: int
  assumes x_nonnegative: "0 \<le> x"
      and multiplier_positive: "0 < multiplier"
      and divisor_positive: "0 < divisor"
  shows "((x * multiplier + divisor - 1) div divisor = 0) =
    (x = 0)"
  text \<open>
    Proof sketch: the zero input simplifies directly.  A positive integer
    input times a positive multiplier is at least one, so the augmented
    numerator is at least the divisor and monotonic division makes the
    quotient positive.
  \<close>
proof (cases "x = 0")
  case True
  with divisor_positive show ?thesis by simp
next
  case False
  with x_nonnegative have x_positive: "0 < x" by linarith
  have product_positive: "0 < x * multiplier"
    using x_positive multiplier_positive by simp
  have divisor_bound:
      "divisor \<le> x * multiplier + divisor - 1"
    using product_positive by linarith
  have quotient_positive:
      "0 < (x * multiplier + divisor - 1) div divisor"
  proof -
    have "divisor div divisor \<le>
        (x * multiplier + divisor - 1) div divisor"
      using zdiv_mono1 [OF divisor_bound divisor_positive] .
    with divisor_positive show ?thesis by simp
  qed
  with False show ?thesis by simp
qed

lemma int_floor_product_div_eq_zero_iff:
  fixes x multiplier divisor :: int
  assumes x_nonnegative: "0 \<le> x"
      and multiplier_at_least_divisor: "divisor \<le> multiplier"
      and divisor_positive: "0 < divisor"
  shows "(x * multiplier div divisor = 0) = (x = 0)"
  text \<open>
    Proof sketch: a positive integer input is at least one.  Multiplying it by
    a non-negative multiplier no smaller than the divisor makes the numerator
    at least the divisor, hence the floor quotient is positive.
  \<close>
proof (cases "x = 0")
  case True
  then show ?thesis by simp
next
  case False
  with x_nonnegative have one_le_x: "1 \<le> x" by linarith
  have multiplier_nonnegative: "0 \<le> multiplier"
    using multiplier_at_least_divisor divisor_positive by linarith
  have multiplier_le_product: "multiplier \<le> x * multiplier"
    using mult_left_mono [OF one_le_x multiplier_nonnegative]
    by (simp add: mult.commute)
  have divisor_le_product: "divisor \<le> x * multiplier"
    using multiplier_at_least_divisor multiplier_le_product by linarith
  have "divisor div divisor \<le> x * multiplier div divisor"
    using zdiv_mono1 [OF divisor_le_product divisor_positive] .
  with divisor_positive False show ?thesis by simp
qed

theorem exchange_v10_amounts_zero_iff:
  assumes pre: "exchange_v10_pre price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive"
    and not_strict_send: "rounding \<noteq> Exchange_Strict_Send"
  shows "(fst (exchange_v10_amounts_int price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive rounding) = 0) =
    (snd (exchange_v10_amounts_int price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive rounding) = 0)"
  text \<open>
    Proof sketch: split along the executable branch tree.  Every normal or
    strict-receive branch relates the two amounts by either a positive ceiling
    conversion or a floor conversion whose multiplier is at least its divisor;
    the two preceding zero lemmas apply.
  \<close>
proof -
  let ?W = "exchange_wheat_value_int price_n price_d max_wheat_send
    max_sheep_receive"
  let ?S = "exchange_sheep_value_int price_n price_d max_sheep_send
    max_wheat_receive"
  from pre have pn: "0 < sint price_n" and pd: "0 < sint price_d"
    by (simp_all add: exchange_v10_pre_def)
  have W0: "0 \<le> ?W"
    using exchange_wheat_value_int_bounds [OF pre] by simp
  have S0: "0 \<le> ?S"
    using exchange_sheep_value_int_bounds [OF pre] by simp
  show ?thesis
  proof (cases "?W > ?S")
    case wheat_stays: True
    show ?thesis
    proof (cases rounding)
      case Exchange_Strict_Send
      with not_strict_send show ?thesis by simp
    next
      case Exchange_Strict_Receive
      have first_nonnegative: "0 \<le> ?S div sint price_n"
        using S0 pn by (simp add: pos_imp_zdiv_nonneg_iff)
      note zero = int_ceiling_product_div_eq_zero_iff
        [OF first_nonnegative pn pd]
      from zero wheat_stays Exchange_Strict_Receive show ?thesis
        by (simp add: exchange_v10_amounts_int_def Let_def)
    next
      case Exchange_Normal
      show ?thesis
      proof (cases "sint price_n > sint price_d")
        case True
        have first_nonnegative: "0 \<le> ?S div sint price_n"
          using S0 pn by (simp add: pos_imp_zdiv_nonneg_iff)
        note zero = int_ceiling_product_div_eq_zero_iff
          [OF first_nonnegative pn pd]
        from zero wheat_stays Exchange_Normal True show ?thesis
          by (simp add: exchange_v10_amounts_int_def Let_def)
      next
        case False
        then have price_order: "sint price_n \<le> sint price_d" by simp
        have first_nonnegative: "0 \<le> ?S div sint price_d"
          using S0 pd by (simp add: pos_imp_zdiv_nonneg_iff)
        note zero = int_floor_product_div_eq_zero_iff
          [OF first_nonnegative price_order pn]
        from zero wheat_stays Exchange_Normal False show ?thesis
          by (simp add: exchange_v10_amounts_int_def Let_def)
      qed
    qed
  next
    case sheep_stays: False
    show ?thesis
    proof (cases "sint price_n > sint price_d")
      case True
      then have price_order: "sint price_d \<le> sint price_n" by simp
      have first_nonnegative: "0 \<le> ?W div sint price_n"
        using W0 pn by (simp add: pos_imp_zdiv_nonneg_iff)
      note zero = int_floor_product_div_eq_zero_iff
        [OF first_nonnegative price_order pd]
      from zero sheep_stays True show ?thesis
        by (simp add: exchange_v10_amounts_int_def Let_def)
    next
      case False
      have first_nonnegative: "0 \<le> ?W div sint price_d"
        using W0 pd by (simp add: pos_imp_zdiv_nonneg_iff)
      note zero = int_ceiling_product_div_eq_zero_iff
        [OF first_nonnegative pd pn]
      from zero sheep_stays False show ?thesis
        by (simp add: exchange_v10_amounts_int_def Let_def)
    qed
  qed
qed

theorem exchange_v10_without_price_error_thresholds_zero_iff:
  assumes pre: "exchange_v10_pre price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive"
    and not_strict_send: "rounding \<noteq> Exchange_Strict_Send"
    and result:
      "exchange_v10_without_price_error_thresholds_with_options price_n price_d
        max_wheat_send max_wheat_receive max_sheep_send max_sheep_receive
        rounding \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr> = Cxx_Ok exchange_result"
  shows "(num_wheat_received exchange_result = 0) =
    (num_sheep_send exchange_result = 0)"
  text \<open>
    Proof sketch: the exact top-level characterization fixes the returned
    record to the integer amount pair.  Its signed-word equalities convert
    word zero to integer zero, where @{thm exchange_v10_amounts_zero_iff}
    applies.
  \<close>
proof -
  let ?A = "exchange_v10_amounts_int price_n price_d max_wheat_send
    max_wheat_receive max_sheep_send max_sheep_receive rounding"
  note exact =
    exchange_v10_without_price_error_thresholds_integer_characterization
      [OF pre, of rounding]
  have result_record:
      "exchange_result =
       make_exchange_result (word_of_int (fst ?A)) (word_of_int (snd ?A))
         (exchange_wheat_value_int price_n price_d max_wheat_send
            max_sheep_receive >
          exchange_sheep_value_int price_n price_d max_sheep_send
            max_wheat_receive)"
    using result exact by simp
  note amount_words =
    exchange_v10_amounts_integer_characterization [OF pre, of rounding]
  have A_sint:
      "sint (word_of_int (fst ?A) :: int64) = fst ?A"
    using amount_words(2) .
  have B_sint:
      "sint (word_of_int (snd ?A) :: int64) = snd ?A"
    using amount_words(3) .
  have integer_zero: "(fst ?A = 0) = (snd ?A = 0)"
    using exchange_v10_amounts_zero_iff [OF pre not_strict_send] .
  show ?thesis
    unfolding result_record make_exchange_result_def
    using A_sint B_sint integer_zero
    by auto
qed

lemma int_nested_floor_product_positive_iff:
  fixes x multiplier divisor :: int
  assumes x_nonnegative: "0 \<le> x"
      and multiplier_greater: "divisor < multiplier"
      and divisor_positive: "0 < divisor"
  shows "(0 < (x div multiplier) * multiplier div divisor) =
    (multiplier \<le> x)"
  text \<open>
    Proof sketch: if the first quotient is positive, it is at least one and its
    product is above the smaller divisor.  Conversely the first quotient is
    zero exactly when the value lies below the positive multiplier.
  \<close>
proof -
  have multiplier_positive: "0 < multiplier"
    using multiplier_greater divisor_positive by linarith
  show ?thesis
  proof (cases "multiplier \<le> x")
    case True
    then have quotient_positive: "0 < x div multiplier"
      using multiplier_positive
      by (simp add: pos_imp_zdiv_pos_iff)
    then have one_le_quotient: "1 \<le> x div multiplier" by linarith
    have multiplier_nonnegative: "0 \<le> multiplier"
      using multiplier_positive by linarith
    have multiplier_le_product:
        "multiplier \<le> (x div multiplier) * multiplier"
      using mult_left_mono [OF one_le_quotient multiplier_nonnegative]
      by (simp add: mult.commute)
    then have divisor_le_product:
        "divisor \<le> (x div multiplier) * multiplier"
      using multiplier_greater by linarith
    then show ?thesis
      using True divisor_positive
      by (simp add: pos_imp_zdiv_pos_iff)
  next
    case False
    then have "x div multiplier = 0"
      using x_nonnegative multiplier_positive
      by (simp add: pos_imp_zdiv_pos_iff pos_imp_zdiv_nonneg_iff)
    with False show ?thesis by simp
  qed
qed

theorem exchange_v10_strict_send_sheep_positive_iff:
  assumes pre: "exchange_v10_pre price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive"
  shows "(0 < snd
      (exchange_v10_amounts_int price_n price_d max_wheat_send
        max_wheat_receive max_sheep_send max_sheep_receive
        Exchange_Strict_Send)) =
    (let wheat_value =
        exchange_wheat_value_int price_n price_d max_wheat_send
          max_sheep_receive;
       sheep_value =
        exchange_sheep_value_int price_n price_d max_sheep_send
          max_wheat_receive
     in if wheat_value > sheep_value
        then 0 < sint max_sheep_send \<and> 0 < sint max_sheep_receive
        else if sint price_n > sint price_d
        then sint price_n \<le> wheat_value
        else sint price_d \<le> wheat_value)"
  text \<open>
    Proof sketch: in the wheat-stays branch, sheep is the minimum of the two
    sheep maxima.  Otherwise simplify the selected floor formula: when wheat
    is more valuable the nested quotient is positive exactly at one numerator
    unit, and in the other price order ordinary positive division has the same
    threshold.
  \<close>
proof -
  let ?W = "exchange_wheat_value_int price_n price_d max_wheat_send
    max_sheep_receive"
  let ?S = "exchange_sheep_value_int price_n price_d max_sheep_send
    max_wheat_receive"
  from pre have pn: "0 < sint price_n" and pd: "0 < sint price_d"
    and ss: "0 \<le> sint max_sheep_send"
    and sr: "0 \<le> sint max_sheep_receive"
    by (simp_all add: exchange_v10_pre_def)
  have W0: "0 \<le> ?W"
    using exchange_wheat_value_int_bounds [OF pre] by simp
  show ?thesis
  proof (cases "?W > ?S")
    case True
    with ss sr show ?thesis
      by (simp add: exchange_v10_amounts_int_def Let_def)
  next
    case False
    show ?thesis
    proof (cases "sint price_n > sint price_d")
      case True
      note positive = int_nested_floor_product_positive_iff
        [OF W0 True pd]
      from positive False True show ?thesis
        by (simp add: exchange_v10_amounts_int_def Let_def)
    next
      case False
      with pd show ?thesis
        by (simp add: exchange_v10_amounts_int_def Let_def
            pos_imp_zdiv_pos_iff)
    qed
  qed
qed

theorem exchange_v10_without_strict_send_sheep_positive_iff:
  assumes pre: "exchange_v10_pre price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive"
    and result:
      "exchange_v10_without_price_error_thresholds_with_options price_n price_d
        max_wheat_send max_wheat_receive max_sheep_send max_sheep_receive
        Exchange_Strict_Send \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr> = Cxx_Ok exchange_result"
  shows "(0 < sint (num_sheep_send exchange_result)) =
    (let wheat_value =
        exchange_wheat_value_int price_n price_d max_wheat_send
          max_sheep_receive;
       sheep_value =
        exchange_sheep_value_int price_n price_d max_sheep_send
          max_wheat_receive
     in if wheat_value > sheep_value
        then 0 < sint max_sheep_send \<and> 0 < sint max_sheep_receive
        else if sint price_n > sint price_d
        then sint price_n \<le> wheat_value
        else sint price_d \<le> wheat_value)"
  text \<open>
    Proof sketch: rewrite the successful result to the exact integer amount
    record and use the signed interpretation of its sheep word.  The preceding
    integer equivalence is then exactly the desired minimal input condition.
  \<close>
proof -
  let ?A = "exchange_v10_amounts_int price_n price_d max_wheat_send
    max_wheat_receive max_sheep_send max_sheep_receive
    Exchange_Strict_Send"
  note exact =
    exchange_v10_without_price_error_thresholds_integer_characterization
      [OF pre, of Exchange_Strict_Send]
  have result_record:
      "exchange_result =
       make_exchange_result (word_of_int (fst ?A)) (word_of_int (snd ?A))
         (exchange_wheat_value_int price_n price_d max_wheat_send
            max_sheep_receive >
          exchange_sheep_value_int price_n price_d max_sheep_send
            max_wheat_receive)"
    using result exact by simp
  note amount_words =
    exchange_v10_amounts_integer_characterization
      [OF pre, of Exchange_Strict_Send]
  have B_sint:
      "sint (word_of_int (snd ?A) :: int64) = snd ?A"
    using amount_words(3) .
  show ?thesis
    unfolding result_record make_exchange_result_def
    using B_sint exchange_v10_strict_send_sheep_positive_iff [OF pre]
    by simp
qed

theorem exchange_v10_without_price_error_thresholds_result_contract:
  assumes pre: "exchange_v10_pre price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive"
    and result:
      "exchange_v10_without_price_error_thresholds_with_options price_n price_d
        max_wheat_send max_wheat_receive max_sheep_send max_sheep_receive
        rounding \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr> = Cxx_Ok exchange_result"
  shows "0 \<le> sint (num_wheat_received exchange_result)"
    and "sint (num_wheat_received exchange_result) \<le>
      min (sint max_wheat_receive) (sint max_wheat_send)"
    and "0 \<le> sint (num_sheep_send exchange_result)"
    and "sint (num_sheep_send exchange_result) \<le>
      min (sint max_sheep_receive) (sint max_sheep_send)"
    and "result_wheat_stays exchange_result =
      (exchange_wheat_value_int price_n price_d max_wheat_send
         max_sheep_receive >
       exchange_sheep_value_int price_n price_d max_sheep_send
         max_wheat_receive)"
  text \<open>
    Proof sketch: uniqueness of the successful constructor identifies the
    returned record with the exact integer characterization.  Its signed-word
    equalities and the four amount bounds yield the range clauses, while the
    record constructor exposes the exact offer-value comparison.
  \<close>
proof -
  let ?A = "exchange_v10_amounts_int price_n price_d max_wheat_send
    max_wheat_receive max_sheep_send max_sheep_receive rounding"
  note exact =
    exchange_v10_without_price_error_thresholds_integer_characterization
      [OF pre, of rounding]
  have result_record:
      "exchange_result =
       make_exchange_result (word_of_int (fst ?A)) (word_of_int (snd ?A))
         (exchange_wheat_value_int price_n price_d max_wheat_send
            max_sheep_receive >
          exchange_sheep_value_int price_n price_d max_sheep_send
            max_wheat_receive)"
    using result exact by simp
  note amount_words =
    exchange_v10_amounts_integer_characterization [OF pre, of rounding]
  have A_sint:
      "sint (word_of_int (fst ?A) :: int64) = fst ?A"
    using amount_words(2) .
  have B_sint:
      "sint (word_of_int (snd ?A) :: int64) = snd ?A"
    using amount_words(3) .
  note bounds = exchange_v10_amounts_int_bounds [OF pre refl]
  show "0 \<le> sint (num_wheat_received exchange_result)"
    unfolding result_record make_exchange_result_def
    using A_sint bounds(1) by simp
  show "sint (num_wheat_received exchange_result) \<le>
      min (sint max_wheat_receive) (sint max_wheat_send)"
    unfolding result_record make_exchange_result_def
    using A_sint bounds(2) by simp
  show "0 \<le> sint (num_sheep_send exchange_result)"
    unfolding result_record make_exchange_result_def
    using B_sint bounds(3) by simp
  show "sint (num_sheep_send exchange_result) \<le>
      min (sint max_sheep_receive) (sint max_sheep_send)"
    unfolding result_record make_exchange_result_def
    using B_sint bounds(4) by simp
  show "result_wheat_stays exchange_result =
      (exchange_wheat_value_int price_n price_d max_wheat_send
         max_sheep_receive >
       exchange_sheep_value_int price_n price_d max_sheep_send
         max_wheat_receive)"
    unfolding result_record make_exchange_result_def by simp
qed

subsection \<open>Full exchange\<close>

text \<open>
  This last section composes the results above into the contract of
  @{const exchange_v10_with_options} and then establishes the crossing property announced
  at the end of the model.
\<close>

theorem exchange_v10_characterization:
  "exchange_v10_with_options price_n price_d max_wheat_send max_wheat_receive
      max_sheep_send max_sheep_receive rounding options =
    (case exchange_v10_without_price_error_thresholds_with_options price_n price_d
        max_wheat_send max_wheat_receive max_sheep_send max_sheep_receive
        rounding options of
      Cxx_Err error \<Rightarrow> Cxx_Err error
    | Cxx_Ok before_thresholds \<Rightarrow>
        apply_price_error_thresholds price_n price_d
          (num_wheat_received before_thresholds)
          (num_sheep_send before_thresholds)
          (result_wheat_stays before_thresholds) rounding)"
  text \<open>
    Proof sketch: unfold the single monadic bind.  Its two constructor cases
    are exactly propagation of the first error or the second C++ call with the
    successful record fields.
  \<close>
  by (simp add: exchange_v10_with_options_def split: cxx_result.splits)

theorem exchange_v10_integer_characterization:
  fixes rounding :: exchange_rounding and amounts :: "int \<times> int"
  assumes pre: "exchange_v10_pre price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive"
  defines "amounts \<equiv>
    exchange_v10_amounts_int price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive rounding"
  shows "exchange_v10_with_options price_n price_d max_wheat_send max_wheat_receive
      max_sheep_send max_sheep_receive rounding \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr> =
    apply_price_error_thresholds price_n price_d
      (word_of_int (fst amounts)) (word_of_int (snd amounts))
      (exchange_wheat_value_int price_n price_d max_wheat_send
         max_sheep_receive >
       exchange_sheep_value_int price_n price_d max_sheep_send
         max_wheat_receive)
      rounding"
  text \<open>
    Proof sketch: @{thm [source]
    exchange_v10_without_price_error_thresholds_integer_characterization}
    replaces the first call by its exact amount record under
    @{const exchange_v10_pre}.  Simplifying the record selectors leaves the
    threshold call shown here.
  \<close>
  using exchange_v10_without_price_error_thresholds_integer_characterization
    [OF pre, of rounding]
  unfolding exchange_v10_with_options_def amounts_def make_exchange_result_def
  by simp

theorem apply_price_error_thresholds_result_choices:
  assumes result:
    "apply_price_error_thresholds price_n price_d wheat_receive sheep_send
      wheat_stays rounding = Cxx_Ok exchange_result"
  shows "exchange_result =
      make_exchange_result wheat_receive sheep_send wheat_stays \<or>
    exchange_result = make_exchange_result 0 0 wheat_stays"
  text \<open>
    Proof sketch: every successful branch of the total threshold
    characterization returns either the unchanged record or its explicit
    zero-amount counterpart.  All remaining branches are errors.
  \<close>
  using result apply_price_error_thresholds_characterization
  by (auto simp add: apply_price_error_thresholds_spec_def Let_def
      split: if_splits exchange_rounding.splits)

theorem exchange_v10_result_contract:
  assumes pre: "exchange_v10_pre price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive"
    and result: "exchange_v10_with_options price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive rounding \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr> =
      Cxx_Ok exchange_result"
  shows "0 \<le> sint (num_wheat_received exchange_result)"
    and "sint (num_wheat_received exchange_result) \<le>
      min (sint max_wheat_receive) (sint max_wheat_send)"
    and "0 \<le> sint (num_sheep_send exchange_result)"
    and "sint (num_sheep_send exchange_result) \<le>
      min (sint max_sheep_receive) (sint max_sheep_send)"
    and "result_wheat_stays exchange_result =
      (exchange_wheat_value_int price_n price_d max_wheat_send
         max_sheep_receive >
       exchange_sheep_value_int price_n price_d max_sheep_send
         max_wheat_receive)"
  text \<open>
    Proof sketch: the integer characterization fixes the input to the threshold
    caller.  A successful threshold call returns either those bounded
    pre-threshold amounts or two zeros and always preserves the stay flag.
    The previously proved signed interpretations and four bounds therefore
    establish every clause.
  \<close>
proof -
  let ?A = "exchange_v10_amounts_int price_n price_d max_wheat_send
    max_wheat_receive max_sheep_send max_sheep_receive rounding"
  let ?stays = "exchange_wheat_value_int price_n price_d max_wheat_send
    max_sheep_receive >
    exchange_sheep_value_int price_n price_d max_sheep_send
      max_wheat_receive"
  have exact:
      "exchange_v10_with_options price_n price_d max_wheat_send max_wheat_receive
        max_sheep_send max_sheep_receive rounding \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr> =
       apply_price_error_thresholds price_n price_d
         (word_of_int (fst ?A)) (word_of_int (snd ?A)) ?stays rounding"
    using exchange_v10_integer_characterization [OF pre, of rounding] by simp
  have applied:
      "apply_price_error_thresholds price_n price_d
        (word_of_int (fst ?A)) (word_of_int (snd ?A)) ?stays rounding =
       Cxx_Ok exchange_result"

    using result exact by simp
  note choices = apply_price_error_thresholds_result_choices [OF applied]
  note amount_words =
    exchange_v10_amounts_integer_characterization [OF pre, of rounding]
  have A_sint:
      "sint (word_of_int (fst ?A) :: int64) = fst ?A"
    using amount_words(2) .
  have B_sint:
      "sint (word_of_int (snd ?A) :: int64) = snd ?A"
    using amount_words(3) .
  note bounds = exchange_v10_amounts_int_bounds [OF pre refl]
  show "0 \<le> sint (num_wheat_received exchange_result)"
    using choices A_sint bounds(1)
    by (auto simp add: make_exchange_result_def)
  show "sint (num_wheat_received exchange_result) \<le>
      min (sint max_wheat_receive) (sint max_wheat_send)"
    using choices A_sint bounds(2) pre
    by (auto simp add: make_exchange_result_def exchange_v10_pre_def)
  show "0 \<le> sint (num_sheep_send exchange_result)"
    using choices B_sint bounds(3)
    by (auto simp add: make_exchange_result_def)
  show "sint (num_sheep_send exchange_result) \<le>
      min (sint max_sheep_receive) (sint max_sheep_send)"
    using choices B_sint bounds(4) pre
    by (auto simp add: make_exchange_result_def exchange_v10_pre_def)
  show "result_wheat_stays exchange_result = ?stays"
    using choices by (auto simp add: make_exchange_result_def)
qed

lemma int_le_ceiling_div_mult:
  fixes numerator divisor :: int
  assumes divisor_positive: "0 < divisor"
  shows "numerator \<le>
    ((numerator + divisor - 1) div divisor) * divisor"
  text \<open>
    Proof sketch: decompose the adjusted numerator into its quotient multiple
    and remainder.  The remainder is strictly below the positive divisor, so
    cancellation of the common divisor increment gives the ceiling inequality.
  \<close>
proof -
  have remainder_less:
      "(numerator + divisor - 1) mod divisor < divisor"
    using divisor_positive by simp
  have decomposition:
      "(numerator + divisor - 1) mod divisor +
       (numerator + divisor - 1) div divisor * divisor =
       numerator + divisor - 1"
    by (rule mod_div_mult_eq)
  from remainder_less decomposition show ?thesis by linarith
qed

lemma exchange_strict_send_favored_int:
  fixes wheat_value sheep_value price_n price_d max_sheep_send
    max_sheep_receive :: int
  assumes pn: "0 < price_n" and pd: "0 < price_d"
    and stays: "sheep_value < wheat_value"
    and wheat_receive_bound:
      "wheat_value \<le> max_sheep_receive * price_d"
    and sheep_send_bound:
      "sheep_value \<le> max_sheep_send * price_d"
  shows "(sheep_value div price_n) * price_n \<le>
    min max_sheep_send max_sheep_receive * price_d"
  text \<open>
    Proof sketch: the rounded-down received amount has value at most the sheep
    offer value.  That value is bounded by the send maximum directly and,
    because wheat stays, strictly by the receive maximum; split which maximum
    is the minimum.
  \<close>
proof -
  have floor_bound:
      "sheep_value div price_n * price_n \<le> sheep_value"
    using int_div_mult_le [OF pn] .
  show ?thesis
  proof (cases "max_sheep_send \<le> max_sheep_receive")
    case True
    then show ?thesis
      using floor_bound sheep_send_bound by simp
  next
    case False
    then show ?thesis
      using floor_bound stays wheat_receive_bound by simp
  qed
qed

lemma exchange_v10_amounts_int_favored:
  fixes rounding :: exchange_rounding and amounts :: "int \<times> int"
  assumes pre: "exchange_v10_pre price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive"
  defines "amounts \<equiv>
    exchange_v10_amounts_int price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive rounding"
  shows "if exchange_wheat_value_int price_n price_d max_wheat_send
          max_sheep_receive >
        exchange_sheep_value_int price_n price_d max_sheep_send
          max_wheat_receive
    then fst amounts * sint price_n \<le> snd amounts * sint price_d
    else snd amounts * sint price_d \<le> fst amounts * sint price_n"
  text \<open>
    Proof sketch: follow the five amount branches.  Every floor conversion
    favors the output side by @{thm int_div_mult_le}, every ceiling conversion
    favors it by @{thm int_le_ceiling_div_mult}, and the special strict-send
    branch is @{thm exchange_strict_send_favored_int}.
  \<close>
proof -
  let ?W = "exchange_wheat_value_int price_n price_d max_wheat_send
    max_sheep_receive"
  let ?S = "exchange_sheep_value_int price_n price_d max_sheep_send
    max_wheat_receive"
  have pn: "0 < sint price_n" and pd: "0 < sint price_d"
    using pre by (simp_all add: exchange_v10_pre_def)
  have W_receive: "?W \<le> sint max_sheep_receive * sint price_d"
    by (simp add: exchange_wheat_value_int_def)
  have S_send: "?S \<le> sint max_sheep_send * sint price_d"
    by (simp add: exchange_sheep_value_int_def)
  show ?thesis
  proof (cases "?W > ?S")
    case stays: True
    show ?thesis
    proof (cases "rounding = Exchange_Strict_Send")
      case strict: True
      have favored:
          "(?S div sint price_n) * sint price_n \<le>
           min (sint max_sheep_send) (sint max_sheep_receive) *
             sint price_d"
        using exchange_strict_send_favored_int
          [OF pn pd stays W_receive S_send] .
      from stays strict favored show ?thesis
        by (simp add: amounts_def exchange_v10_amounts_int_def Let_def)
    next
      case not_strict: False
      show ?thesis
      proof (cases "sint price_n > sint price_d \<or>
          rounding = Exchange_Strict_Receive")
        case up: True
        have ceiling:
            "(?S div sint price_n) * sint price_n \<le>
             (((?S div sint price_n) * sint price_n + sint price_d - 1)
                div sint price_d) * sint price_d"
          by (rule int_le_ceiling_div_mult [OF pd])
        from stays not_strict up ceiling show ?thesis
          by (simp add: amounts_def exchange_v10_amounts_int_def Let_def)
      next
        case down: False
        have floor:
            "((?S div sint price_d) * sint price_d) div sint price_n *
               sint price_n \<le>
             (?S div sint price_d) * sint price_d"
          by (rule int_div_mult_le [OF pn])
        from stays not_strict down floor show ?thesis
          by (simp add: amounts_def exchange_v10_amounts_int_def Let_def)
      qed
    qed
  next
    case stays: False
    show ?thesis
    proof (cases "sint price_n > sint price_d")
      case wheat_more: True
      have floor:
          "((?W div sint price_n) * sint price_n) div sint price_d *
             sint price_d \<le>
           (?W div sint price_n) * sint price_n"
        by (rule int_div_mult_le [OF pd])
      from stays wheat_more floor show ?thesis
        by (simp add: amounts_def exchange_v10_amounts_int_def Let_def)
    next
      case sheep_more: False
      have ceiling:
          "(?W div sint price_d) * sint price_d \<le>
           (((?W div sint price_d) * sint price_d + sint price_n - 1)
              div sint price_n) * sint price_n"
        by (rule int_le_ceiling_div_mult [OF pn])
      from stays sheep_more ceiling show ?thesis
        by (simp add: amounts_def exchange_v10_amounts_int_def Let_def)
    qed
  qed
qed

lemma exchange_v10_before_favored:
  fixes rounding :: exchange_rounding
  assumes pre: "exchange_v10_pre price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive"
  defines "amounts \<equiv>
    exchange_v10_amounts_int price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive rounding"
  defines "wheat_stays \<equiv>
    exchange_wheat_value_int price_n price_d max_wheat_send
      max_sheep_receive >
    exchange_sheep_value_int price_n price_d max_sheep_send
      max_wheat_receive"
  shows "favored_seller_ok price_n price_d
    (word_of_int (fst amounts)) (word_of_int (snd amounts)) wheat_stays"
  text \<open>
    Proof sketch: the amount words denote the exact mathematical amounts under
    @{const exchange_v10_pre}.  Substitute those signed interpretations into
    @{const favored_seller_ok} and apply the preceding branch theorem.
  \<close>
proof -
  note words =
    exchange_v10_amounts_integer_characterization [OF pre, of rounding]
  note favored =
    exchange_v10_amounts_int_favored [OF pre, of rounding]
  show ?thesis
    using words(2,3) favored
    by (simp add: amounts_def wheat_stays_def favored_seller_ok_def Let_def)
qed


theorem exchange_v10_wellformed_characterization:
  fixes rounding :: exchange_rounding and amounts :: "int \<times> int"
  assumes pre: "exchange_v10_pre price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive"
  defines "amounts \<equiv>
    exchange_v10_amounts_int price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive rounding"
  defines "wheat_stays \<equiv>
    exchange_wheat_value_int price_n price_d max_wheat_send
      max_sheep_receive >
    exchange_sheep_value_int price_n price_d max_sheep_send
      max_wheat_receive"
  shows "exchange_v10_with_options price_n price_d max_wheat_send max_wheat_receive
      max_sheep_send max_sheep_receive rounding \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr> =
    (let wheat_receive = (word_of_int (fst amounts) :: int64) in
     let sheep_send = (word_of_int (snd amounts) :: int64) in
     let original =
       make_exchange_result wheat_receive sheep_send wheat_stays in
     let zero = make_exchange_result 0 0 wheat_stays in
     if \<not> (0 < fst amounts \<and> 0 < snd amounts) then
       if rounding = Exchange_Strict_Send then
         if sheep_send = 0 then Cxx_Err Cxx_Runtime_Error
         else Cxx_Ok original
       else Cxx_Ok zero
     else if rounding = Exchange_Normal then
       Cxx_Ok
         (if price_error_bound_spec price_n price_d wheat_receive
               sheep_send False
          then original else zero)
     else if price_error_bound_spec price_n price_d wheat_receive
         sheep_send True
     then Cxx_Ok original
     else Cxx_Err Cxx_Runtime_Error)"
  text \<open>
    Proof sketch: substitute the exact pre-threshold amount record.  Its signed
    interpretations replace the positivity guard, positive prices eliminate
    assertion outcomes, and @{thm exchange_v10_before_favored} eliminates both
    favored-seller runtime failures.  The remaining branches are exactly the
    normal and path price-bound behavior plus the strict-send zero test.
  \<close>
proof -
  let ?WR = "word_of_int (fst amounts) :: int64"
  let ?SS = "word_of_int (snd amounts) :: int64"
  have exact:
      "exchange_v10_with_options price_n price_d max_wheat_send max_wheat_receive
        max_sheep_send max_sheep_receive rounding \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr> =
       apply_price_error_thresholds price_n price_d ?WR ?SS wheat_stays
         rounding"
    using exchange_v10_integer_characterization [OF pre, of rounding]
    by (simp add: amounts_def wheat_stays_def)
  note words =
    exchange_v10_amounts_integer_characterization [OF pre, of rounding]
  have A_sint: "sint ?WR = fst amounts"
    using words(2) by (simp add: amounts_def)
  have B_sint: "sint ?SS = snd amounts"
    using words(3) by (simp add: amounts_def)
  have favored:
      "favored_seller_ok price_n price_d ?WR ?SS wheat_stays"
    using exchange_v10_before_favored [OF pre, of rounding]
    by (simp add: amounts_def wheat_stays_def)
  have prices: "0 \<le> sint price_n" "0 \<le> sint price_d"
    using pre by (simp_all add: exchange_v10_pre_def)
  show ?thesis
    unfolding exact apply_price_error_thresholds_characterization
      apply_price_error_thresholds_spec_def Let_def
    using A_sint B_sint favored prices
    by simp
qed

corollary exchange_v10_normal_characterization:
  fixes amounts :: "int \<times> int"
  assumes pre: "exchange_v10_pre price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive"
  defines "amounts \<equiv>
    exchange_v10_amounts_int price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive Exchange_Normal"
  shows "exchange_v10_with_options price_n price_d max_wheat_send max_wheat_receive
      max_sheep_send max_sheep_receive Exchange_Normal
      \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr> =
    (let wheat_stays =
       exchange_wheat_value_int price_n price_d max_wheat_send
         max_sheep_receive >
       exchange_sheep_value_int price_n price_d max_sheep_send
         max_wheat_receive in
     let wheat_receive = (word_of_int (fst amounts) :: int64) in
     let sheep_send = (word_of_int (snd amounts) :: int64) in
     Cxx_Ok
       (if 0 < fst amounts \<and> 0 < snd amounts \<and>
           price_error_bound_spec price_n price_d wheat_receive
             sheep_send False
        then make_exchange_result wheat_receive sheep_send wheat_stays
        else make_exchange_result 0 0 wheat_stays))"
  text \<open>
    Proof sketch: specialize the well-formed characterization to normal mode.
    Every non-positive trade becomes the zero record; a positive trade retains
    its amounts exactly when the symmetric price-error predicate succeeds.
  \<close>
  using exchange_v10_wellformed_characterization
    [OF pre, of Exchange_Normal]
  by (auto simp add: amounts_def Let_def split: if_splits)

corollary exchange_v10_path_characterization:
  fixes rounding :: exchange_rounding and amounts :: "int \<times> int"
  assumes pre: "exchange_v10_pre price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive"
    and path_mode: "rounding \<noteq> Exchange_Normal"
  defines "amounts \<equiv>
    exchange_v10_amounts_int price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive rounding"
  shows "exchange_v10_with_options price_n price_d max_wheat_send max_wheat_receive
      max_sheep_send max_sheep_receive rounding \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr> =
    (let wheat_stays =
       exchange_wheat_value_int price_n price_d max_wheat_send
         max_sheep_receive >
       exchange_sheep_value_int price_n price_d max_sheep_send
         max_wheat_receive in
     let wheat_receive = (word_of_int (fst amounts) :: int64) in
     let sheep_send = (word_of_int (snd amounts) :: int64) in
     let original =
       make_exchange_result wheat_receive sheep_send wheat_stays in
     if \<not> (0 < fst amounts \<and> 0 < snd amounts) then
       if rounding = Exchange_Strict_Send then
         if sheep_send = 0 then Cxx_Err Cxx_Runtime_Error
         else Cxx_Ok original
       else Cxx_Ok (make_exchange_result 0 0 wheat_stays)
     else if price_error_bound_spec price_n price_d wheat_receive
         sheep_send True
     then Cxx_Ok original
     else Cxx_Err Cxx_Runtime_Error)"
  text \<open>
    Proof sketch: specialize the well-formed characterization to a non-normal
    constructor.  Positive trades are preserved exactly when the one-sided
    price bound holds; the remaining non-positive branch distinguishes the raw
    strict-send sheep-zero check from strict-receive zeroing.
  \<close>
  using exchange_v10_wellformed_characterization
    [OF pre, of rounding]
  by (auto simp add: amounts_def path_mode Let_def split: if_splits)


lemma word_zero_iff_sint_zero:
  "((word :: int64) = 0) = (sint word = 0)"
  text \<open>
    Proof sketch: the forward direction is immediate.  In the reverse
    direction @{thm Word.uint_sint} turns signed zero into unsigned zero, which
    uniquely identifies the zero word by @{thm Word.uint_0_iff}.
  \<close>
proof
  assume "word = 0"
  then show "sint word = 0" by simp
next
  assume zero: "sint word = 0"
  have "uint word = 0"
    using zero by (simp add: Word.uint_sint)
  then show "word = 0"
    by (simp only: Word.uint_0_iff)
qed

theorem exchange_v10_zero_iff:
  assumes pre: "exchange_v10_pre price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive"
    and not_strict_send: "rounding \<noteq> Exchange_Strict_Send"
    and result: "exchange_v10_with_options price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive rounding \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr> =
      Cxx_Ok exchange_result"
  shows "(num_wheat_received exchange_result = 0) =
    (num_sheep_send exchange_result = 0)"
  text \<open>
    Proof sketch: a successful threshold call returns either the exact
    pre-threshold record or two zeros.  For the first choice, signed-word
    faithfulness and @{thm exchange_v10_amounts_zero_iff} establish simultaneous
    zero outside strict-send mode; the second choice is immediate.
  \<close>
proof -
  let ?A = "exchange_v10_amounts_int price_n price_d max_wheat_send
    max_wheat_receive max_sheep_send max_sheep_receive rounding"
  let ?WR = "word_of_int (fst ?A) :: int64"
  let ?SS = "word_of_int (snd ?A) :: int64"
  let ?stays = "exchange_wheat_value_int price_n price_d max_wheat_send
    max_sheep_receive >
    exchange_sheep_value_int price_n price_d max_sheep_send
      max_wheat_receive"
  have exact:
      "exchange_v10_with_options price_n price_d max_wheat_send max_wheat_receive
        max_sheep_send max_sheep_receive rounding \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr> =
       apply_price_error_thresholds price_n price_d ?WR ?SS ?stays rounding"
    using exchange_v10_integer_characterization [OF pre, of rounding] by simp
  have applied:
      "apply_price_error_thresholds price_n price_d ?WR ?SS ?stays rounding =
       Cxx_Ok exchange_result"
    using result exact by simp
  note choices = apply_price_error_thresholds_result_choices [OF applied]
  note words =
    exchange_v10_amounts_integer_characterization [OF pre, of rounding]
  have A_sint: "sint ?WR = fst ?A"
    using words(2) .
  have B_sint: "sint ?SS = snd ?A"
    using words(3) .
  have amount_zero: "(fst ?A = 0) = (snd ?A = 0)"
    using exchange_v10_amounts_zero_iff [OF pre not_strict_send] .
  have word_zero: "(?WR = 0) = (?SS = 0)"
    using word_zero_iff_sint_zero [of ?WR]
      word_zero_iff_sint_zero [of ?SS] A_sint B_sint amount_zero
    by auto
  from choices word_zero show ?thesis
    by (auto simp add: make_exchange_result_def)
qed

theorem apply_price_error_thresholds_strict_send_success:
  assumes result:
    "apply_price_error_thresholds price_n price_d wheat_receive sheep_send
      wheat_stays Exchange_Strict_Send = Cxx_Ok exchange_result"
  shows "exchange_result =
      make_exchange_result wheat_receive sheep_send wheat_stays"
    and "sheep_send \<noteq> 0"
  text \<open>
    Proof sketch: a positive strict-send trade can only return the unchanged
    record, and positivity makes the sheep word nonzero.  The non-positive
    strict-send branch also returns that record exactly when its explicit raw
    sheep-zero check is false.
  \<close>
  using result apply_price_error_thresholds_characterization
  by (auto simp add: apply_price_error_thresholds_spec_def Let_def
      split: if_splits)

theorem exchange_v10_strict_send_sheep_positive:
  assumes pre: "exchange_v10_pre price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive"
    and result: "exchange_v10_with_options price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive
      Exchange_Strict_Send \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr> = Cxx_Ok exchange_result"
  shows "0 < sint (num_sheep_send exchange_result)"
  text \<open>
    Proof sketch: strict-send success preserves the pre-threshold record and
    proves its sheep word nonzero.  That word denotes a non-negative exact
    integer amount, so nonzero strengthens to strictly positive.
  \<close>
proof -
  let ?A = "exchange_v10_amounts_int price_n price_d max_wheat_send
    max_wheat_receive max_sheep_send max_sheep_receive
      Exchange_Strict_Send"
  let ?WR = "word_of_int (fst ?A) :: int64"
  let ?SS = "word_of_int (snd ?A) :: int64"
  let ?stays = "exchange_wheat_value_int price_n price_d max_wheat_send
    max_sheep_receive >
    exchange_sheep_value_int price_n price_d max_sheep_send
      max_wheat_receive"
  have exact:
      "exchange_v10_with_options price_n price_d max_wheat_send max_wheat_receive
        max_sheep_send max_sheep_receive Exchange_Strict_Send \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr> =
       apply_price_error_thresholds price_n price_d ?WR ?SS ?stays
         Exchange_Strict_Send"
    using exchange_v10_integer_characterization
      [OF pre, of Exchange_Strict_Send] by simp
  have applied:
      "apply_price_error_thresholds price_n price_d ?WR ?SS ?stays
        Exchange_Strict_Send = Cxx_Ok exchange_result"
    using result exact by simp
  note strict =
    apply_price_error_thresholds_strict_send_success [OF applied]
  note words =
    exchange_v10_amounts_integer_characterization
      [OF pre, of Exchange_Strict_Send]
  have B_sint: "sint ?SS = snd ?A"
    using words(3) .
  have B_nonnegative: "0 \<le> snd ?A"
    using exchange_v10_amounts_int_bounds [OF pre refl] by simp
  have "sint ?SS \<noteq> 0"
    using strict(2) word_zero_iff_sint_zero [of ?SS] by auto
  then have "0 < sint ?SS"
    using B_sint B_nonnegative by linarith
  with strict(1) show ?thesis
    by (simp add: make_exchange_result_def)
qed

theorem exchange_v10_positive_trade_contract:
  assumes pre: "exchange_v10_pre price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive"
    and result: "exchange_v10_with_options price_n price_d max_wheat_send
      max_wheat_receive max_sheep_send max_sheep_receive rounding \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr> =
      Cxx_Ok exchange_result"
    and positive:
      "0 < sint (num_wheat_received exchange_result) \<and>
       0 < sint (num_sheep_send exchange_result)"
  shows "favored_seller_ok price_n price_d
      (num_wheat_received exchange_result)
      (num_sheep_send exchange_result)
      (result_wheat_stays exchange_result)"
    and "if rounding = Exchange_Normal
      then price_error_bound_spec price_n price_d
        (num_wheat_received exchange_result)
        (num_sheep_send exchange_result) False
      else price_error_bound_spec price_n price_d
        (num_wheat_received exchange_result)
        (num_sheep_send exchange_result) True"
  text \<open>
    Proof sketch: a positive returned trade cannot be the explicit zero record,
    so the threshold choice theorem identifies it with the exact pre-threshold
    record.  Apply the threshold caller's favored-seller and price-bound
    contracts and substitute those unchanged fields.
  \<close>
proof -
  let ?A = "exchange_v10_amounts_int price_n price_d max_wheat_send
    max_wheat_receive max_sheep_send max_sheep_receive rounding"
  let ?WR = "word_of_int (fst ?A) :: int64"
  let ?SS = "word_of_int (snd ?A) :: int64"
  let ?stays = "exchange_wheat_value_int price_n price_d max_wheat_send
    max_sheep_receive >
    exchange_sheep_value_int price_n price_d max_sheep_send
      max_wheat_receive"
  have exact:
      "exchange_v10_with_options price_n price_d max_wheat_send max_wheat_receive
        max_sheep_send max_sheep_receive rounding \<lparr>exact_receive_cap = False, symmetric_exact_receive_cap = False\<rparr> =
       apply_price_error_thresholds price_n price_d ?WR ?SS ?stays rounding"
    using exchange_v10_integer_characterization [OF pre, of rounding] by simp
  have applied:
      "apply_price_error_thresholds price_n price_d ?WR ?SS ?stays rounding =
       Cxx_Ok exchange_result"
    using result exact by simp
  note choices = apply_price_error_thresholds_result_choices [OF applied]
  have result_record:
      "exchange_result = make_exchange_result ?WR ?SS ?stays"
    using choices positive
    by (auto simp add: make_exchange_result_def)
  have input_positive: "0 < sint ?WR \<and> 0 < sint ?SS"
    using positive result_record
    by (simp add: make_exchange_result_def)
  note favored =
    apply_price_error_thresholds_positive_success_favored
      [OF input_positive applied]
  show "favored_seller_ok price_n price_d
      (num_wheat_received exchange_result)
      (num_sheep_send exchange_result)
      (result_wheat_stays exchange_result)"
    using favored unfolding result_record make_exchange_result_def by simp
  note bound =
    apply_price_error_thresholds_positive_trade_bound
      [OF input_positive applied positive]
  show "if rounding = Exchange_Normal
      then price_error_bound_spec price_n price_d
        (num_wheat_received exchange_result)
        (num_sheep_send exchange_result) False
      else price_error_bound_spec price_n price_d
        (num_wheat_received exchange_result)
        (num_sheep_send exchange_result) True"
    using bound result_record
    by (cases rounding) (simp_all add: make_exchange_result_def)
qed


export_code big_multiply big_divide_or_throw big_divide_or_throw128
  check_price_error_bound calculate_offer_value
  calculate_offer_value_with_exact_receive_cap apply_price_error_thresholds
  exchange_v10_without_price_error_thresholds_with_options exchange_v10_with_options
  Cxx_Round_Down Cxx_Round_Up checking SML

end
