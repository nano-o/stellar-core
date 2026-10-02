theory Pretty_Numerals
  imports Main
begin

section \<open>Printing numerals near powers of two\<close>

text \<open>
  Word arithmetic produces numerals such as @{text 18446744073709551615},
  which are hard to read.  This theory changes how such numerals are
  printed, in goals, @{command value} results and counterexamples alike: a
  numeral within 1000 of @{text "2^64"} or @{text "2^128"} is printed as
  that power plus or minus the difference, for example as
  @{text "2 ^ 64 - 1"}.

  Only the printing changes.  The printed term denotes the same value as
  the numeral in every type, including word types, where both sides are
  reduced modulo the word size.  The rewriting runs in the uncheck phase,
  which transforms terms just before they are printed.
\<close>

ML \<open>
structure Pretty_Numerals =
struct

(*powers of two, by exponent, near which numerals are rewritten*)
val exponents = [64, 128];
val max_distance = 1000;

fun near_power n =
  get_first (fn e =>
    let val d = n - Integer.pow e 2
    in if abs d <= max_distance then SOME (e, d) else NONE end) exponents;

fun power_form T (e, d) =
  let
    val pow =
      Const (\<^const_name>\<open>power\<close>, T --> HOLogic.natT --> T) $
        HOLogic.mk_number T 2 $ HOLogic.mk_number HOLogic.natT e;
    fun binop c = Const (c, T --> T --> T);
  in
    if d = 0 then pow
    else if d < 0 then binop \<^const_name>\<open>minus\<close> $ pow $ HOLogic.mk_number T (~ d)
    else binop \<^const_name>\<open>plus\<close> $ pow $ HOLogic.mk_number T d
  end;

fun rewrite (t as Const (\<^const_name>\<open>numeral\<close>, Type ("fun", [_, T])) $ bits) =
      (case try HOLogic.dest_numeral bits of
        SOME n => (case near_power n of SOME ed => power_form T ed | NONE => t)
      | NONE => t)
  | rewrite (t $ u) = rewrite t $ rewrite u
  | rewrite (Abs (x, T, t)) = Abs (x, T, rewrite t)
  | rewrite t = t;

end;
\<close>

setup \<open>
  Context.theory_map
    (Syntax_Phases.term_uncheck 100 "pretty_numerals" (K (map Pretty_Numerals.rewrite)))
\<close>

text \<open>
  Examples.  The last numeral is 1616 below @{text "2^64"}, too far away to
  be rewritten.
\<close>

value "18446744073709551615 :: int"
value "18446744073709551616 :: int"
value "(2 :: int) ^ 128 + 5"
value "18446744073709550000 :: int"

end
