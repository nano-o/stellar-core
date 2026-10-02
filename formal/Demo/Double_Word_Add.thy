theory Double_Word_Add
  imports "HOL-Library.Word" Pretty_Numerals
begin

section \<open>Adding double-length words: a proof worked by hand\<close>

text \<open>
  A 128-bit unsigned integer can be represented as two 64-bit words, a high
  half and a low half.  Addition adds the low halves, detects whether that
  addition wrapped around, and propagates the carry into the high half:

  \<^verbatim>\<open>
    struct u128 { uint64_t hi; uint64_t lo; };

    u128 add(u128 a, u128 b) {
      uint64_t lo = a.lo + b.lo;        // wraps modulo 2^64
      uint64_t carry = lo < a.lo;       // wrapped iff the sum got smaller
      return { a.hi + b.hi + carry, lo };
    }
  \<close>

  We model this function, then prove that it is commutative.  The statement
  looks trivial, but the code is not symmetric: the carry compares the sum
  with @{text "a.lo"}, never with @{text "b.lo"}.
\<close>

type_synonym uint64 = "64 word"

text \<open>A double word is the pair of its high and low halves, in that order.\<close>

type_synonym dword = "uint64 \<times> uint64"

subsection \<open>The model\<close>

text \<open>
  The model follows the C++ line by line.  Word addition in Isabelle wraps
  modulo @{term "(2::int) ^ 64"}, exactly like @{text "uint64_t"} addition.
  The conversion of the Boolean comparison to @{text "uint64_t"} is written
  out as an @{text "if"}.
\<close>

fun add_dword :: "dword \<Rightarrow> dword \<Rightarrow> dword"
  \<comment> \<open>C++: \<open>add\<close> above\<close>
  where
    "add_dword (a_hi, a_lo) (b_hi, b_lo) =
      (let lo = a_lo + b_lo;
           carry = (if lo < a_lo then 1 else 0 :: uint64)
       in (a_hi + b_hi + carry, lo))"

subsection \<open>Step 1: run it\<close>

text \<open>Before proving anything, evaluate a few cases, including a carry:\<close>

value "add_dword (0, 2) (0, 3)"
value "add_dword (0, 2 ^ 64 - 1) (0, 1)"
value "add_dword (5, 2 ^ 64 - 1) (7, 2 ^ 64 - 1)"

subsection \<open>Step 2: state the property and look for counterexamples\<close>

text \<open>
  Swapping the arguments should not change the result.  Before spending
  effort on a proof, ask @{text quickcheck} to search for a counterexample.
\<close>

lemma "add_dword a b = add_dword b a"
  quickcheck
  oops

subsection \<open>Step 3: a naive attempt, and the goal it leaves\<close>

text \<open>
  Write both arguments as their halves, unfold the definition, and let the
  simplifier use commutativity of word addition.  The additions are handled,
  but the proof gets stuck: place the cursor on the @{text apply} line to
  see the remaining goal.  It says that the two carry tests agree: the sum
  is below @{text a_lo} exactly when it is below @{text b_lo}.  That is
  true, but the simplifier does not know why.
\<close>

lemma "add_dword (a_hi, a_lo) (b_hi, b_lo) = add_dword (b_hi, b_lo) (a_hi, a_lo)"
  apply (simp add: Let_def add.commute)
  oops

subsection \<open>Step 4: the missing fact about the carry\<close>

text \<open>
  The key observation: the comparison detects exactly the overflow of the
  mathematical sum.  We prove it by moving from words to their integer
  values with @{term uint}.
\<close>

lemma carry_iff_overflow:
  fixes x y :: uint64
  shows "x + y < x \<longleftrightarrow> 2 ^ 64 \<le> uint x + uint y"
  text \<open>
    Proof sketch: split on whether the integer sum fits in 64 bits.  If it
    fits, the word sum is the integer sum, which is at least
    @{term "uint x"}.  If it does not fit, the word sum is the integer sum
    minus @{term "(2::int) ^ 64"}, which is less than @{term "uint x"}
    because @{term "uint y < 2 ^ 64"}.
  \<close>
proof (cases "uint x + uint y < 2 ^ 64")
  case True
  then have "uint (x + y) = uint x + uint y"
    by (simp add: uint_plus_if')
  then show ?thesis
    using True by (simp add: word_less_def)
next
  case False
  then have "uint (x + y) = uint x + uint y - 2 ^ 64"
    by (simp add: uint_plus_if')
  moreover have "uint y < 2 ^ 64"
    using uint_bounded [of y] by simp
  ultimately show ?thesis
    using False by (simp add: word_less_def)
qed

text \<open>
  Overflow of the integer sum is symmetric in @{term x} and @{term y}, so the
  two carry tests agree.
\<close>

lemma carry_symmetric:
  fixes x y :: uint64
  shows "x + y < x \<longleftrightarrow> x + y < y"
  text \<open>
    Proof sketch: rewrite both sides with @{thm [source] carry_iff_overflow};
    integer addition is commutative.
  \<close>
  using carry_iff_overflow [of x y] carry_iff_overflow [of y x]
  by (simp add: add.commute)

subsection \<open>Step 5: the proof\<close>

text \<open>
  With the carry fact available, the proof goes through as in Step 3: each
  of the three components of the result is commutative.
\<close>

theorem add_dword_commute:
  "add_dword a b = add_dword b a"
  text \<open>
    Proof sketch: split both arguments into halves.  The low halves commute
    by commutativity of word addition, the carries agree by
    @{thm [source] carry_symmetric}, and the high halves commute by
    commutativity again.
  \<close>
proof -
  obtain a_hi a_lo where a: "a = (a_hi, a_lo)" by (cases a)
  obtain b_hi b_lo where b: "b = (b_hi, b_lo)" by (cases b)
  have lo: "a_lo + b_lo = b_lo + a_lo"
    by (rule add.commute)
  have carry: "a_lo + b_lo < a_lo \<longleftrightarrow> b_lo + a_lo < b_lo"
    using carry_symmetric [of a_lo b_lo] by (simp add: add.commute)
  have hi: "a_hi + b_hi = b_hi + a_hi"
    by (rule add.commute)
  show ?thesis
    unfolding a b add_dword.simps Let_def
    using lo carry hi by simp
qed

end
