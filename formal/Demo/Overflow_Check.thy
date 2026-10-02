theory Overflow_Check
  imports "HOL-Library.Word" Pretty_Numerals
begin

section \<open>Is the overflow check right?\<close>

text \<open>
  This idiom appears in countless code bases:

  \<^verbatim>\<open>
    bool add_overflows(uint64_t a, uint64_t b) {
      return a + b < a;   // the sum wrapped around iff it got smaller
    }
  \<close>

  It is one line, but is it right for all @{text "2^128"} pairs of inputs?
  We model it, run it, test it, and prove it.
\<close>

subsection \<open>Step 1: the model\<close>

type_synonym uint64 = "64 word"

text \<open>
  Isabelle's type @{typ "64 word"} behaves like @{text uint64_t}: its
  arithmetic wraps around modulo @{term "(2::int) ^ 64"}.  So
  @{text "2 ^ 64"} is zero, @{text "2 ^ 64 - 1"} is the largest value
  (@{text UINT64_MAX}), and adding one to it wraps around to zero:
\<close>

value "2 ^ 64 :: uint64"
value "(2 ^ 64 - 1) + 1 :: uint64"

text \<open>The model is the C++ line, transcribed:\<close>

definition add_overflows :: "uint64 \<Rightarrow> uint64 \<Rightarrow> bool"
  \<comment> \<open>C++: \<open>add_overflows\<close> above\<close>
  where "add_overflows a b = (a + b < a)"

subsection \<open>Step 2: run it\<close>

value "add_overflows 2 3"
value "add_overflows (2 ^ 64 - 1) 1"
value "add_overflows (2 ^ 64 - 1) (2 ^ 64 - 1)"

subsection \<open>Step 3: say what ``right'' means, and test it\<close>

text \<open>
  The check should return true exactly when the mathematical sum does not
  fit in 64 bits.  The function @{term uint} gives the value of a word as an
  unbounded integer, so the mathematical sum is @{term "uint a + uint b"},
  and the property is:
  @{text "add_overflows a b \<longleftrightarrow> 2 ^ 64 \<le> uint a + uint b"}.

  Before trying to prove anything, test.  Suppose the check had been
  written with @{text "<="} instead of @{text "<"}:
\<close>

definition add_overflows_buggy :: "uint64 \<Rightarrow> uint64 \<Rightarrow> bool"
  where "add_overflows_buggy a b = (a + b \<le> a)"

lemma "add_overflows_buggy a b \<longleftrightarrow> 2 ^ 64 \<le> uint a + uint b"
  quickcheck
  oops

text \<open>
  Quickcheck finds a counterexample at once: @{text "a = 0"} and
  @{text "b = 0"}, where the buggy check reports an overflow for
  @{text "0 + 0"}.  The real check survives:
\<close>

lemma "add_overflows a b \<longleftrightarrow> 2 ^ 64 \<le> uint a + uint b"
  quickcheck
  oops

text \<open>
  Quickcheck only tries small inputs, though, and small inputs never
  overflow.  This is evidence, not proof; the last section shows a bug that
  testing misses.
\<close>

subsection \<open>Step 4: a first proof attempt\<close>

text \<open>
  Unfold the definition, turn the word comparison into a comparison of
  integer values (@{thm [source] word_less_def}), and call the simplifier.
  Place the cursor on the @{text apply} line to see where it gets stuck:
  @{text "uint (a + b) < uint a \<longleftrightarrow> 2 ^ 64 \<le> uint a + uint b"}
  (Isabelle prints @{text "\<longleftrightarrow>"} between Booleans as @{text "="}).
  It does not know the integer value of a sum that may have wrapped around.
\<close>

lemma "add_overflows a b \<longleftrightarrow> 2 ^ 64 \<le> uint a + uint b"
  apply (unfold add_overflows_def word_less_def)
  oops

subsection \<open>Step 5: search the library\<close>

text \<open>Ask Isabelle which theorems talk about the value of a word sum:\<close>

find_theorems "uint (_ + _)"

text \<open>
  One of the results, @{thm [source] uint_plus_if'}, says what an engineer
  would say: if the integer sum fits in 64 bits, it is the value of the
  word sum; otherwise the value is the integer sum minus
  @{term "(2::int) ^ 64"}.

  @{thm [display] uint_plus_if'}
\<close>

subsection \<open>Step 6: the proof\<close>

text \<open>
  Proof sketch: split on whether the integer sum fits in 64 bits.  If it
  fits, the word sum is the integer sum, which is at least
  @{term "uint a"}, so the check is false.  If it does not fit, the word
  sum is the integer sum minus @{term "(2::int) ^ 64"}, which is less
  than @{term "uint a"} because @{term "uint b < 2 ^ 64"}, so the check
  is true.
\<close>

lemma add_overflows_correct:
  "add_overflows a b \<longleftrightarrow> 2 ^ 64 \<le> uint a + uint b"
  \<comment> \<open>The check reports an overflow exactly when the true sum needs more
      than 64 bits.\<close>
proof (cases "uint a + uint b < 2 ^ 64")
  case True
  \<comment> \<open>No wraparound: the word sum is the integer sum.\<close>
  then have "uint (a + b) = uint a + uint b"
    by (simp add: uint_plus_if')
  then show ?thesis
    using True by (simp add: add_overflows_def word_less_def)
next
  case False
  \<comment> \<open>Wraparound: the word sum is the integer sum minus \<open>2 ^ 64\<close>.\<close>
  have "add_overflows a b = True"
  proof -
    from False have "uint (a + b) = uint a + uint b - 2 ^ 64"
      by (simp add: uint_plus_if')
    moreover have "uint b < 2 ^ 64"
      using uint_bounded [of b] by simp
    ultimately show "add_overflows a b = True"
      by (simp add: add_overflows_def word_less_def) 
  qed
  moreover have "2 ^ 64 \<le> uint a + uint b"
    using False by linarith
  ultimately show ?thesis by simp
qed

subsection \<open>Coda: why not just test?\<close>

text \<open>
  Another common form of the check tests before adding, so that the
  addition never wraps.  Suppose it is written with @{text ">="} where
  @{text ">"} is needed:

  \<^verbatim>\<open>
    bool add_would_overflow(uint64_t a, uint64_t b) {
      return a >= UINT64_MAX - b;   // should be >
    }
  \<close>
\<close>

definition add_would_overflow :: "uint64 \<Rightarrow> uint64 \<Rightarrow> bool"
  \<comment> \<open>C++: \<open>add_would_overflow\<close> above, off by one; \<open>UINT64_MAX\<close> is \<open>2 ^ 64 - 1\<close>\<close>
  where "add_would_overflow a b = (a \<ge> (2 ^ 64 - 1) - b)"

text \<open>Quickcheck finds nothing wrong:\<close>

lemma "add_would_overflow a b \<longleftrightarrow> 2 ^ 64 \<le> uint a + uint b"
  quickcheck
  oops

text \<open>
  Yet the check is wrong at the boundary: @{text "(2 ^ 64 - 1) + 0"} does not
  overflow, but the check says it does, while the original check gets it
  right:
\<close>

value "(add_would_overflow (2 ^ 64 - 1) 0, add_overflows (2 ^ 64 - 1) 0)"

text \<open>
  Overflow bugs live near @{text "2^64"}, where small-input testing never
  looks.  The proof of @{thm [source] add_overflows_correct} covers all
  @{text "2^128"} input pairs; no proof of the corresponding statement for
  @{const add_would_overflow} can exist.
\<close>

end
