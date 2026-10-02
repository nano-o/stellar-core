theory Offer_Exchange_Divide_Layered
  imports Offer_Exchange_Arithmetic
begin

section \<open>Layered model of the wide arithmetic helpers\<close>

text \<open>
  This theory models the wide arithmetic helpers of \<open>util/numeric.cpp\<close> with
  one definition per C++ function, computing on 128-bit words exactly as the
  C++ does: \<open>bigDivideUnsigned\<close>, \<open>bigDivide\<close>, and \<open>bigDivideOrThrow\<close>; their
  128-bit counterparts \<open>bigDivideUnsigned128\<close>, \<open>bigDivide128\<close>, and
  \<open>bigDivideOrThrow128\<close>; and \<open>bigMultiplyUnsigned\<close> and \<open>bigMultiply\<close>.  Each
  layer is characterized over exact integers, and each top-level wrapper is
  proved equal to the collapsed constant of the same name in
  @{theory OfferExchange.Offer_Exchange_Arithmetic}, so the integer
  characterizations already proved there transfer unchanged.  The
  differential harness exercises every layer separately through the transport
  definitions in \<open>Offer_Exchange_Test_Interface\<close>.
\<close>

subsection \<open>Definitions\<close>

type_synonym uint64 = "64 word"

definition uint64_max128 :: uint128
  \<comment> \<open>C++: \<open>UINT64_MAX\<close> after conversion to \<open>uint128_t\<close>\<close>
  where "uint64_max128 = 2 ^ 64 - 1"

text \<open>
  The definition \<open>big_divide_unsigned\<close> below models \<open>bigDivideUnsigned\<close>.  The C++ function
  asserts that the divisor is non-zero, widens the three unsigned 64-bit
  operands to 128 bits, forms the rounded quotient in 128-bit arithmetic,
  stores its low 64 bits through the out-parameter, and returns whether the
  quotient fitted in 64 bits.  The out-parameter and the Boolean return are
  modelled together as a pair.
\<close>

definition big_divide_unsigned ::
    "uint64 \<Rightarrow> uint64 \<Rightarrow> uint64 \<Rightarrow> cxx_rounding \<Rightarrow>
      (bool \<times> uint64) cxx_result"
  \<comment> \<open>C++: \<open>bigDivideUnsigned\<close> (\<open>util/numeric.cpp\<close>)\<close>
  where
    "big_divide_unsigned A B C rounding =
      (if \<not> (0 < uint C) then Cxx_Err Cxx_Assertion_Failed
       else
         let a = (ucast A :: uint128); b = (ucast B :: uint128);
             c = (ucast C :: uint128);
             x = (if rounding = Cxx_Round_Down then (a * b) div c
                  else (a * b + c - 1) div c)
         in Cxx_Ok (x \<le> uint64_max128, ucast x))"

text \<open>
  The definition \<open>big_divide_layered\<close> below models \<open>bigDivide\<close>.  The C++ function asserts
  that the two multiplicands are non-negative and the divisor positive, casts
  all three to \<open>uint64_t\<close>, calls the unsigned helper, and on success
  additionally checks the result against \<open>INT64_MAX\<close>.  Casting a signed
  64-bit word to an unsigned one is the identity on bit patterns, so the
  arguments are passed through unchanged; only their interpretation switches
  from @{const sint} to @{const uint}.  The comparison with \<open>INT64_MAX\<close> is
  unsigned in C++ because the constant is promoted, hence @{const uint}.  On
  the failure path the C++ leaves the out-parameter unassigned; the model
  returns zero there, and its only caller never reads that value.
\<close>

definition big_divide_layered ::
    "int64 \<Rightarrow> int64 \<Rightarrow> int64 \<Rightarrow> cxx_rounding \<Rightarrow>
      (bool \<times> int64) cxx_result"
  \<comment> \<open>C++: \<open>bigDivide\<close> (\<open>util/numeric.cpp\<close>)\<close>
  where
    "big_divide_layered A B C rounding =
      (if \<not> (0 \<le> sint A \<and> 0 \<le> sint B \<and> 0 < sint C)
       then Cxx_Err Cxx_Assertion_Failed
       else do {
         (res, r2) \<leftarrow> big_divide_unsigned A B C rounding;
         if res then Cxx_Ok (uint r2 \<le> int64_max_int, r2)
         else Cxx_Ok (False, 0)
       })"

text \<open>
  The definition \<open>big_divide_or_throw_layered\<close> below models
  \<open>bigDivideOrThrow\<close>, which
  turns a false return from \<open>bigDivide\<close> into an overflow exception.
\<close>

definition big_divide_or_throw_layered ::
    "int64 \<Rightarrow> int64 \<Rightarrow> int64 \<Rightarrow> cxx_rounding \<Rightarrow>
      int64 cxx_result"
  \<comment> \<open>C++: \<open>bigDivideOrThrow\<close> (\<open>util/numeric.cpp\<close>)\<close>
  where
    "big_divide_or_throw_layered A B C rounding = do {
       (ok, res) \<leftarrow> big_divide_layered A B C rounding;
       if ok then Cxx_Ok res else Cxx_Err Cxx_Overflow
     }"

subsubsection \<open>Examples\<close>

lemma "big_divide_unsigned 10 1 3 Cxx_Round_Down = Cxx_Ok (True, 3)"
  by eval

lemma "big_divide_unsigned 10 1 3 Cxx_Round_Up = Cxx_Ok (True, 4)"
  by eval

lemma "big_divide_or_throw_layered 10 1 3 Cxx_Round_Up = Cxx_Ok 4"
  by eval

lemma "big_divide_or_throw_layered (-1) 1 3 Cxx_Round_Up =
    Cxx_Err Cxx_Assertion_Failed"
  by eval

lemma "big_divide_or_throw_layered int64_max int64_max 1 Cxx_Round_Down =
    Cxx_Err Cxx_Overflow"
  by eval

subsection \<open>The 128-bit family\<close>

definition uint128_max :: uint128
  \<comment> \<open>C++: \<open>uint128_max()\<close>\<close>
  where "uint128_max = word_of_int (2 ^ 128 - 1)"

text \<open>
  The definition \<open>big_divide_unsigned128\<close> below models
  \<open>bigDivideUnsigned128\<close>.  The C++ function asserts that the divisor is
  non-zero, widens it to 128 bits, and, when rounding up, returns false
  early if the incremented numerator would wrap.  Otherwise it forms the
  rounded quotient, stores its low 64 bits through the out-parameter, and
  returns whether the quotient fitted in 64 bits.  On the early exit the
  out-parameter is left unassigned; the model returns zero there.
\<close>

definition big_divide_unsigned128 ::
    "uint128 \<Rightarrow> uint64 \<Rightarrow> cxx_rounding \<Rightarrow> (bool \<times> uint64) cxx_result"
  \<comment> \<open>C++: \<open>bigDivideUnsigned128\<close> (\<open>util/numeric.cpp\<close>)\<close>
  where
    "big_divide_unsigned128 a B rounding =
      (if B = 0 then Cxx_Err Cxx_Assertion_Failed
       else
         let b = (ucast B :: uint128)
         in if rounding = Cxx_Round_Up \<and> a > uint128_max - (b - 1)
            then Cxx_Ok (False, 0)
            else
              let x = (if rounding = Cxx_Round_Down then a div b
                       else (a + b - 1) div b)
              in Cxx_Ok (x \<le> uint64_max128, ucast x))"

text \<open>
  The definitions \<open>big_divide128_layered\<close> and
  \<open>big_divide_or_throw128_layered\<close> below model \<open>bigDivide128\<close> and
  \<open>bigDivideOrThrow128\<close>.  They mirror the signed wrapper and the throwing
  wrapper of the 64-bit family exactly.
\<close>

definition big_divide128_layered ::
    "uint128 \<Rightarrow> int64 \<Rightarrow> cxx_rounding \<Rightarrow> (bool \<times> int64) cxx_result"
  \<comment> \<open>C++: \<open>bigDivide128\<close> (\<open>util/numeric.cpp\<close>)\<close>
  where
    "big_divide128_layered a B rounding =
      (if \<not> 0 < sint B then Cxx_Err Cxx_Assertion_Failed
       else do {
         (res, r2) \<leftarrow> big_divide_unsigned128 a B rounding;
         if res then Cxx_Ok (uint r2 \<le> int64_max_int, r2)
         else Cxx_Ok (False, 0)
       })"

definition big_divide_or_throw128_layered ::
    "uint128 \<Rightarrow> int64 \<Rightarrow> cxx_rounding \<Rightarrow> int64 cxx_result"
  \<comment> \<open>C++: \<open>bigDivideOrThrow128\<close> (\<open>util/numeric.cpp\<close>)\<close>
  where
    "big_divide_or_throw128_layered a B rounding = do {
       (ok, res) \<leftarrow> big_divide128_layered a B rounding;
       if ok then Cxx_Ok res else Cxx_Err Cxx_Overflow
     }"

subsubsection \<open>Examples\<close>

lemma "big_divide_unsigned128 10 3 Cxx_Round_Up = Cxx_Ok (True, 4)"
  by eval

lemma "big_divide_unsigned128 uint128_max 2 Cxx_Round_Up = Cxx_Ok (False, 0)"
  by eval

text \<open>
  With divisor one the guard cannot fire, exactly as the C++ comment argues:
  the incremented numerator wraps to the same value it started from, and the
  overflow is caught by the 64-bit range check instead.
\<close>

lemma "big_divide_unsigned128 uint128_max 1 Cxx_Round_Up =
    Cxx_Ok (False, ucast uint128_max)"
  by eval

lemma "big_divide_unsigned128 uint128_max 1 Cxx_Round_Down =
    Cxx_Ok (False, ucast uint128_max)"
  by eval

lemma "big_divide_or_throw128_layered 10 3 Cxx_Round_Down = Cxx_Ok 3"
  by eval

lemma "big_divide_or_throw128_layered 10 0 Cxx_Round_Down =
    Cxx_Err Cxx_Assertion_Failed"
  by eval

lemma "big_divide_or_throw128_layered uint128_max 1 Cxx_Round_Up =
    Cxx_Err Cxx_Overflow"
  by eval

subsection \<open>Wide multiplication\<close>

text \<open>
  The definitions \<open>big_multiply_unsigned\<close> and \<open>big_multiply_layered\<close> below
  model \<open>bigMultiplyUnsigned\<close> and \<open>bigMultiply\<close>.  The unsigned helper
  zero-extends both operands to 128 bits and multiplies; the signed wrapper
  asserts that both operands are non-negative and passes them through, the
  cast to \<open>uint64_t\<close> being the identity on bit patterns.
\<close>

definition big_multiply_unsigned :: "uint64 \<Rightarrow> uint64 \<Rightarrow> uint128"
  \<comment> \<open>C++: \<open>bigMultiplyUnsigned\<close> (\<open>util/numeric.cpp\<close>)\<close>
  where "big_multiply_unsigned a b = (ucast a :: uint128) * ucast b"

definition big_multiply_layered :: "int64 \<Rightarrow> int64 \<Rightarrow> uint128 cxx_result"
  \<comment> \<open>C++: \<open>bigMultiply\<close> (\<open>util/numeric.cpp\<close>)\<close>
  where
    "big_multiply_layered a b =
      (if \<not> (0 \<le> sint a \<and> 0 \<le> sint b) then Cxx_Err Cxx_Assertion_Failed
       else Cxx_Ok (big_multiply_unsigned a b))"

subsubsection \<open>Examples\<close>

lemma "big_multiply_unsigned (- 1) (- 1) = (2 ^ 64 - 1) * (2 ^ 64 - 1)"
  by eval

lemma "big_multiply_layered 6 7 = Cxx_Ok 42"
  by eval

lemma "big_multiply_layered (- 1) 7 = Cxx_Err Cxx_Assertion_Failed"
  by eval

subsection \<open>Reading the word arithmetic as integer arithmetic\<close>

text \<open>
  The lemmas below let the 128-bit word operations of
  @{const big_divide_unsigned} be read as operations on unbounded integers.
  Zero extension preserves the unsigned value, the product of two unsigned
  64-bit values fits in 128 bits, and so does the round-up numerator.
\<close>

lemma uint_ucast_uint64_uint128 [simp]:
  "uint (ucast (w :: uint64) :: uint128) = uint w"
  text \<open>Proof sketch: zero extension from 64 to 128 bits is an up-cast.\<close>
  by (simp add: uint_up_ucast is_up)

lemma uint_uint64_max128 [simp]:
  "uint uint64_max128 = 2 ^ 64 - 1"
  text \<open>Proof sketch: the constant is a numeral below the 128-bit modulus.\<close>
  unfolding uint64_max128_def by simp

lemma uint64_product_fits_uint128:
  fixes A B :: uint64
  shows "uint A * uint B < (2 :: int) ^ 128"
  text \<open>
    Proof sketch: both factors are non-negative and below two to the
    sixty-fourth power, so their product is below two to the
    one-hundred-twenty-eighth power.
  \<close>
proof -
  have "uint A < (2 :: int) ^ 64" and "uint B < (2 :: int) ^ 64"
    using uint_bounded [of A] uint_bounded [of B] by simp_all
  then have "uint A * uint B < (2 :: int) ^ 64 * 2 ^ 64"
    by (intro mult_strict_mono) simp_all
  then show ?thesis by simp
qed

lemma uint64_round_up_numerator_fits_uint128:
  fixes A B C :: uint64
  shows "uint A * uint B + uint C < (2 :: int) ^ 128"
  text \<open>
    Proof sketch: each unsigned 64-bit value is at most two to the
    sixty-fourth power minus one.  The product of two such bounds plus a
    third bound is two to the one-hundred-twenty-eighth power minus two to
    the sixty-fourth power, which is below the modulus.
  \<close>
proof -
  have bounds: "uint A \<le> (2 :: int) ^ 64 - 1" "uint B \<le> (2 :: int) ^ 64 - 1"
      "uint C \<le> (2 :: int) ^ 64 - 1"
    using uint_bounded [of A] uint_bounded [of B] uint_bounded [of C]
    by simp_all
  have product: "uint A * uint B \<le> ((2 :: int) ^ 64 - 1) * (2 ^ 64 - 1)"
    using bounds by (intro mult_mono) simp_all
  have "uint A * uint B + uint C \<le>
      ((2 :: int) ^ 64 - 1) * (2 ^ 64 - 1) + (2 ^ 64 - 1)"
    using product bounds(3) by linarith
  also have "... < (2 :: int) ^ 128" by simp
  finally show ?thesis .
qed

lemma uint_product_uint64_uint128:
  fixes A B :: uint64
  shows "uint ((ucast A :: uint128) * ucast B) = uint A * uint B"
  text \<open>Proof sketch: the product fits, so 128-bit multiplication is exact.\<close>
  using uint_mult_lem [of "ucast A :: uint128" "ucast B"]
    uint64_product_fits_uint128 [of A B]
  by simp

lemma uint_round_up_numerator_uint64_uint128:
  fixes A B C :: uint64
  assumes divisor_positive: "0 < uint C"
  shows "uint ((ucast A :: uint128) * ucast B + ucast C - 1) =
    uint A * uint B + uint C - 1"
  text \<open>
    Proof sketch: the sum fits, so the 128-bit addition is exact, and it is
    at least one because the divisor is, so subtracting one is exact too.
  \<close>
proof -
  have sum: "uint ((ucast A :: uint128) * ucast B + ucast C) =
      uint A * uint B + uint C"
    using uint_add_lem [of "(ucast A :: uint128) * ucast B" "ucast C"]
      uint64_round_up_numerator_fits_uint128 [of A B C]
    by (simp add: uint_product_uint64_uint128)
  have "0 \<le> uint A * uint B" by simp
  then have "1 \<le> uint A * uint B + uint C"
    using divisor_positive by linarith
  then have "uint (1 :: uint128) \<le>
      uint ((ucast A :: uint128) * ucast B + ucast C)"
    using sum by simp
  then show ?thesis
    using uint_sub_lem
      [of "1 :: uint128" "(ucast A :: uint128) * ucast B + ucast C"] sum
    by simp
qed

lemma ucast_uint128_uint64:
  "(ucast (x :: uint128) :: uint64) = word_of_int (uint x)"
  text \<open>Proof sketch: this is the general cast law at one type instance.\<close>
  by (rule ucast_eq)

lemma sint_nonnegative_eq_uint:
  fixes w :: int64
  assumes "0 \<le> sint w"
  shows "sint w = uint w"
  text \<open>
    Proof sketch: a non-negative signed value lies below two to the
    sixty-third power, so taking its low 64 bits is the identity, and the
    unsigned value is exactly those low 64 bits.
  \<close>
  using assms sint_lt [of w] by (simp add: uint_sint take_bit_int_eq_self)

subsection \<open>Characterizations\<close>

text \<open>
  Each layer is now characterized over exact integers.  The unsigned helper
  is characterized for all inputs, not only for the non-negative signed ones
  its caller supplies.
\<close>

theorem big_divide_unsigned_characterization:
  "big_divide_unsigned A B C rounding =
    (if C = 0 then Cxx_Err Cxx_Assertion_Failed
     else Cxx_Ok
       (rounded_quotient (uint A * uint B) (uint C) rounding \<le> 2 ^ 64 - 1,
        word_of_int (rounded_quotient (uint A * uint B) (uint C) rounding)))"
  text \<open>
    Proof sketch: a zero divisor fails the assertion.  Otherwise split on the
    rounding mode; in each case the 128-bit numerator is exact by the fitting
    lemmas, word division is exact, the comparison against the 64-bit maximum
    is the unsigned comparison of exact values, and the final narrowing cast
    is @{const word_of_int} of the exact quotient.
  \<close>
proof (cases "C = 0")
  case True
  then show ?thesis by (simp add: big_divide_unsigned_def)
next
  case False
  then have "uint C \<noteq> 0" by (simp add: uint_0_iff)
  then have pos: "0 < uint C"
    using uint_nonnegative [of C] by (auto simp add: order_less_le)
  show ?thesis
  proof (cases rounding)
    case Cxx_Round_Down
    with pos False show ?thesis
      by (simp only: big_divide_unsigned_def Let_def,
          simp add: word_le_def uint_div uint_product_uint64_uint128
            ucast_uint128_uint64)
  next
    case Cxx_Round_Up
    with pos False show ?thesis
      by (simp only: big_divide_unsigned_def Let_def,
          simp add: word_le_def uint_div uint_round_up_numerator_uint64_uint128
            ucast_uint128_uint64)
  qed
qed

lemma uint_word_of_int_uint64:
  assumes "0 \<le> q" and "q \<le> (2 :: int) ^ 64 - 1"
  shows "uint (word_of_int q :: uint64) = q"
  text \<open>Proof sketch: the value is inside the unsigned 64-bit range.\<close>
  using assms by (simp add: uint_word_of_int take_bit_int_eq_self)

theorem big_divide_layered_characterization:
  "big_divide_layered A B C rounding =
    (if \<not> (0 \<le> sint A \<and> 0 \<le> sint B \<and> 0 < sint C)
     then Cxx_Err Cxx_Assertion_Failed
     else Cxx_Ok
       (rounded_quotient (sint A * sint B) (sint C) rounding \<le> int64_max_int,
        if rounded_quotient (sint A * sint B) (sint C) rounding \<le> 2 ^ 64 - 1
        then word_of_int (rounded_quotient (sint A * sint B) (sint C) rounding)
        else 0))"
  text \<open>
    Proof sketch: under the assertion the three signed values equal their
    unsigned readings, so the unsigned characterization applies with the
    same exact quotient.  If that quotient fits in 64 bits the wrapper reads
    it back exactly and compares it against the signed maximum; otherwise
    the unsigned flag is already false and so is the signed comparison.
  \<close>
proof (cases "0 \<le> sint A \<and> 0 \<le> sint B \<and> 0 < sint C")
  case False
  then show ?thesis by (simp add: big_divide_layered_def)
next
  case True
  then have signed: "sint A = uint A" "sint B = uint B" "sint C = uint C"
    by (simp_all add: sint_nonnegative_eq_uint)
  have nonzero: "C \<noteq> 0" using True by auto
  let ?q = "rounded_quotient (uint A * uint B) (uint C) rounding"
  have q_nonnegative: "0 \<le> ?q"
    using True signed by (simp add: rounded_quotient_nonnegative)
  show ?thesis
  proof (cases "?q \<le> 2 ^ 64 - 1")
    case True
    then have "uint (word_of_int ?q :: uint64) = ?q"
      using q_nonnegative uint_word_of_int_uint64 by blast
    with \<open>0 \<le> sint A \<and> 0 \<le> sint B \<and> 0 < sint C\<close> True nonzero show ?thesis
      by (simp add: big_divide_layered_def big_divide_unsigned_characterization
          signed)
  next
    case False
    then have "\<not> ?q \<le> int64_max_int" by simp
    with \<open>0 \<le> sint A \<and> 0 \<le> sint B \<and> 0 < sint C\<close> False nonzero show ?thesis
      by (simp add: big_divide_layered_def big_divide_unsigned_characterization
          signed)
  qed
qed

subsection \<open>Agreement with the collapsed model\<close>

theorem big_divide_or_throw_layered_eq [export_audit]:
  "big_divide_or_throw_layered A B C rounding =
    big_divide_or_throw A B C rounding"
  text \<open>
    Proof sketch: rewrite the layered wrapper with the characterization of
    its inner layer.  The assertion conditions coincide, and a quotient
    passes the signed range check exactly when the collapsed model does not
    report overflow, in which case both return the same word.
  \<close>
  by (auto simp add: big_divide_or_throw_layered_def
      big_divide_layered_characterization big_divide_or_throw_def Let_def)

corollary big_divide_or_throw_layered_success_iff:
  "big_divide_or_throw_layered A B C rounding = Cxx_Ok result
    \<longleftrightarrow> 0 \<le> sint A \<and> 0 \<le> sint B \<and> 0 < sint C \<and>
      rounded_quotient (sint A * sint B) (sint C) rounding
        \<le> int64_max_int \<and>
      result = word_of_int
        (rounded_quotient (sint A * sint B) (sint C) rounding)"
  text \<open>Proof sketch: transfer the existing theorem along the equality.\<close>
  unfolding big_divide_or_throw_layered_eq
  by (rule big_divide_or_throw_success_iff)

subsection \<open>Wide multiplication agrees with the collapsed model\<close>

lemma uint_big_multiply_unsigned:
  "uint (big_multiply_unsigned a b) = uint a * uint b"
  text \<open>Proof sketch: the product of two 64-bit values fits in 128 bits.\<close>
  by (simp add: big_multiply_unsigned_def uint_product_uint64_uint128)

lemma big_multiply_unsigned_word:
  fixes a b :: int64
  assumes "0 \<le> sint a" and "0 \<le> sint b"
  shows "big_multiply_unsigned a b = word_of_int (sint a * sint b)"
  text \<open>
    Proof sketch: both words have the unsigned value @{term "sint a * sint b"},
    the left one by the exact product lemma and the reading of non-negative
    signed values as unsigned ones, so they are the same word.
  \<close>
  by (metis assms(1,2) sint_nonnegative_eq_uint uint_big_multiply_unsigned
      word_of_int_uint)

theorem big_multiply_layered_eq [export_audit]:
  "big_multiply_layered a b = big_multiply a b"
  text \<open>
    Proof sketch: the assertions coincide, and on the success path both sides
    return the word with unsigned value @{term "sint a * sint b"}.
  \<close>
proof (cases "0 \<le> sint a \<and> 0 \<le> sint b")
  case False
  then show ?thesis
    by (auto simp add: big_multiply_layered_def big_multiply_def)
next
  case True
  then show ?thesis
    by (simp add: big_multiply_layered_def big_multiply_def
        big_multiply_unsigned_word)
qed

subsection \<open>The 128-bit family: word arithmetic as integer arithmetic\<close>

lemma uint_uint128_max [simp]:
  "uint uint128_max = 2 ^ 128 - 1"
  text \<open>Proof sketch: the constant is the largest 128-bit numeral.\<close>
  by (simp add: uint128_max_def uint_word_of_int)

lemma uint128_guard_value:
  fixes B :: uint64
  assumes "B \<noteq> 0"
  shows "uint (uint128_max - ((ucast B :: uint128) - 1)) =
    2 ^ 128 - 1 - (uint B - 1)"
  text \<open>
    Proof sketch: the divisor is at least one, so subtracting one from its
    zero extension is exact, and subtracting that from the all-ones word is
    exact as well because it is at most the all-ones value.
  \<close>
proof -
  have B_pos: "0 < uint B"
    using assms uint_nonnegative [of B]
    by (auto simp add: uint_0_iff order_less_le)
  have inner: "uint ((ucast B :: uint128) - 1) = uint B - 1"
    using B_pos uint_sub_lem [of "1 :: uint128" "ucast B :: uint128"] by simp
  have outer: "uint (uint128_max - ((ucast B :: uint128) - 1)) =
      uint uint128_max - uint ((ucast B :: uint128) - 1)"
    using inner uint_bounded [of B]
      uint_sub_lem [of "(ucast B :: uint128) - 1" uint128_max] by simp
  show ?thesis using inner outer by simp
qed

lemma uint128_guard_word_iff:
  fixes a :: uint128 and B :: uint64
  assumes "B \<noteq> 0"
  shows "(a > uint128_max - ((ucast B :: uint128) - 1)) =
    (uint a > 2 ^ 128 - 1 - (uint B - 1))"
  text \<open>Proof sketch: unsigned word comparison compares the exact values.\<close>
  by (simp only: word_less_def uint128_guard_value [OF assms])

lemma uint128_round_up_numerator:
  fixes a :: uint128 and B :: uint64
  assumes "B \<noteq> 0" and "uint a \<le> 2 ^ 128 - 1 - (uint B - 1)"
  shows "uint (a + ucast B - 1) = uint a + uint B - 1"
  text \<open>
    Proof sketch: the two word operations compute the exact result modulo
    the 128-bit modulus, whatever the intermediate sum does.  The guard says
    the exact result is at most the largest 128-bit value, and it is
    non-negative because the divisor is at least one, so the reduction is
    the identity.  This is precisely the argument in the C++ comment.
  \<close>
proof -
  have B_pos: "0 < uint B"
    using assms(1) uint_nonnegative [of B]
    by (auto simp add: uint_0_iff order_less_le)
  have "uint (a + ucast B - 1) = (uint a + uint B - 1) mod 2 ^ 128"
    by (simp add: uint_word_ariths mod_diff_left_eq)
  also have "... = uint a + uint B - 1"
    using assms(2) B_pos uint_nonnegative [of a]
    by (intro mod_pos_pos_trivial) linarith+
  finally show ?thesis .
qed

subsection \<open>The 128-bit family: characterizations\<close>

theorem big_divide_unsigned128_characterization:
  "big_divide_unsigned128 a B rounding =
    (if B = 0 then Cxx_Err Cxx_Assertion_Failed
     else if rounding = Cxx_Round_Up \<and> uint a > 2 ^ 128 - 1 - (uint B - 1)
     then Cxx_Ok (False, 0)
     else Cxx_Ok (rounded_quotient (uint a) (uint B) rounding \<le> 2 ^ 64 - 1,
                  word_of_int (rounded_quotient (uint a) (uint B) rounding)))"
  text \<open>
    Proof sketch: a zero divisor fails the assertion.  Otherwise the word
    guard is the exact integer guard.  When it fires the function returns
    false without touching the out-parameter.  When it does not, split on the
    rounding mode: word division is exact, the round-up numerator is exact
    by the previous lemma, the 64-bit comparison compares exact values, and
    the narrowing cast is @{const word_of_int} of the exact quotient.
  \<close>
proof (cases "B = 0")
  case True
  then show ?thesis by (simp add: big_divide_unsigned128_def)
next
  case False
  note guard = uint128_guard_word_iff [OF False]
  show ?thesis
  proof (cases "rounding = Cxx_Round_Up \<and> uint a > 2 ^ 128 - 1 - (uint B - 1)")
    case True
    with False show ?thesis
      by (simp add: big_divide_unsigned128_def Let_def guard)
  next
    case guard_false: False
    show ?thesis
    proof (cases rounding)
      case Cxx_Round_Down
      with \<open>B \<noteq> 0\<close> guard_false show ?thesis
        by (simp only: big_divide_unsigned128_def Let_def,
            simp add: guard word_le_def uint_div ucast_uint128_uint64)
    next
      case Cxx_Round_Up
      then have "uint a \<le> 2 ^ 128 - 1 - (uint B - 1)"
        using guard_false by simp
      then have numerator: "uint (a + ucast B - 1) = uint a + uint B - 1"
        by (rule uint128_round_up_numerator [OF \<open>B \<noteq> 0\<close>])
      with \<open>B \<noteq> 0\<close> guard_false Cxx_Round_Up show ?thesis
        by (simp only: big_divide_unsigned128_def Let_def,
            simp add: guard word_le_def uint_div ucast_uint128_uint64)
    qed
  qed
qed

theorem big_divide128_layered_characterization:
  "big_divide128_layered a B rounding =
    (if \<not> 0 < sint B then Cxx_Err Cxx_Assertion_Failed
     else if rounding = Cxx_Round_Up \<and> uint a > 2 ^ 128 - 1 - (sint B - 1)
     then Cxx_Ok (False, 0)
     else Cxx_Ok
       (rounded_quotient (uint a) (sint B) rounding \<le> int64_max_int,
        if rounded_quotient (uint a) (sint B) rounding \<le> 2 ^ 64 - 1
        then word_of_int (rounded_quotient (uint a) (sint B) rounding)
        else 0))"
  text \<open>
    Proof sketch: under the assertion the signed divisor equals its unsigned
    reading, so the unsigned characterization applies.  If the guard fires,
    the false flag is passed through.  Otherwise, if the quotient fits in
    64 bits the wrapper reads it back exactly and compares it against the
    signed maximum, and if it does not, both flags are false.
  \<close>
proof (cases "0 < sint B")
  case False
  then show ?thesis by (simp add: big_divide128_layered_def)
next
  case True
  then have signed: "sint B = uint B" by (simp add: sint_nonnegative_eq_uint)
  have nonzero: "B \<noteq> 0" using True by auto
  let ?q = "rounded_quotient (uint a) (uint B) rounding"
  have q_nonnegative: "0 \<le> ?q"
    using True signed by (simp add: rounded_quotient_nonnegative)
  show ?thesis
  proof (cases "rounding = Cxx_Round_Up \<and> uint a > 2 ^ 128 - 1 - (uint B - 1)")
    case True
    with \<open>0 < sint B\<close> nonzero show ?thesis
      by (simp add: big_divide128_layered_def
          big_divide_unsigned128_characterization signed)
  next
    case guard_false: False
    show ?thesis
    proof (cases "?q \<le> 2 ^ 64 - 1")
      case True
      then have "uint (word_of_int ?q :: uint64) = ?q"
        using q_nonnegative uint_word_of_int_uint64 by blast
      with \<open>0 < sint B\<close> nonzero guard_false True show ?thesis
        by (auto simp add: big_divide128_layered_def
            big_divide_unsigned128_characterization signed)
    next
      case False
      then have "\<not> ?q \<le> int64_max_int" by simp
      with \<open>0 < sint B\<close> nonzero guard_false False show ?thesis
        by (auto simp add: big_divide128_layered_def
            big_divide_unsigned128_characterization signed)
    qed
  qed
qed

subsection \<open>The 128-bit family agrees with the collapsed model\<close>

theorem big_divide_or_throw128_layered_eq [export_audit]:
  "big_divide_or_throw128_layered a B rounding =
    big_divide_or_throw128 a B rounding"
  text \<open>
    Proof sketch: rewrite the layered wrapper with the characterization of
    its inner layer.  The assertion and the guard coincide with the collapsed
    model's first two branches, and a quotient passes the signed range check
    exactly when the collapsed model does not report overflow.
  \<close>
  by (auto simp add: big_divide_or_throw128_layered_def
      big_divide128_layered_characterization big_divide_or_throw128_def
      Let_def)

corollary big_divide_or_throw128_layered_success_iff:
  "big_divide_or_throw128_layered a B rounding = Cxx_Ok result
    \<longleftrightarrow> 0 < sint B \<and>
      \<not> (rounding = Cxx_Round_Up \<and>
        uint a > (2 :: int) ^ 128 - 1 - (sint B - 1)) \<and>
      rounded_quotient (uint a) (sint B) rounding
        \<le> int64_max_int \<and>
      result = word_of_int
        (rounded_quotient (uint a) (sint B) rounding)"
  text \<open>Proof sketch: transfer the existing theorem along the equality.\<close>
  unfolding big_divide_or_throw128_layered_eq
  by (rule big_divide_or_throw128_success_iff)

end
