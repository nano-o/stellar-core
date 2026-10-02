theory Timed_Methods
  imports Main
begin

text \<open>
  We make common methods time out quickly in order for LLMs to get quick
  feedback.  The limit is a local configuration so established heavy proofs
  can raise it without weakening the default for new work.
\<close>

ML \<open>
structure Timed_Method =
struct
  val timeout =
    Attrib.setup_config_real \<^binding>\<open>timed_methods_timeout\<close> (K 2.0)

  fun get_timeout ctxt = Time.fromReal (Config.get ctxt timeout)

  fun mk_warn name =
    let
      val warned = Unsynchronized.ref false
    in
      fn () =>
        if !warned then ()
        else (warned := true; warning (name ^ ": timeout"))
    end

  fun timeout_seq timeout warn seq =
    if Timeout.ignored timeout then seq
    else
      let
        val deadline = Time.now () + timeout
        fun pull seq =
          let
            val remaining = deadline - Time.now ()
          in
            if remaining <= Time.zeroTime then (warn (); NONE)
            else (Timeout.apply remaining Seq.pull seq
                  handle Timeout.TIMEOUT _ => (warn (); NONE))
          end
        fun make seq =
          Seq.make (fn () =>
            (case pull seq of
              NONE => NONE
            | SOME (x, seq') => SOME (x, make seq')))
      in
        make seq
      end

  fun wrap_tac ctxt warn tac st =
    let val timeout = get_timeout ctxt
    in
      if Timeout.ignored timeout then tac st
      else
        (Timeout.apply timeout (fn () => timeout_seq timeout warn (tac st)) ()
          handle Timeout.TIMEOUT _ => (warn (); Seq.empty))
    end
  fun wrap_tac' ctxt warn tac = fn i => wrap_tac ctxt warn (tac i)
end
\<close>

text \<open>
  The @{attribute timed_methods_timeout} configuration defaults to two seconds
  and is read when each wrapped method is invoked.
\<close>

method_setup auto = \<open>
  Scan.lift (Scan.option (Parse.nat -- Parse.nat)) --|
    Method.sections Clasimp.clasimp_modifiers >>
  (fn NONE => (fn ctxt =>
      let
        val warn = Timed_Method.mk_warn "auto"
      in
        SIMPLE_METHOD (CHANGED_PROP (Timed_Method.wrap_tac ctxt warn (Clasimp.auto_tac ctxt)))
      end)
    | SOME (m, n) => (fn ctxt =>
      let
        val warn = Timed_Method.mk_warn "auto"
      in
        SIMPLE_METHOD (CHANGED_PROP (Timed_Method.wrap_tac ctxt warn (Clasimp.mk_auto_tac ctxt m n)))
      end))
\<close>


method_setup intro = \<open>
  Attrib.thms >> (fn ths => fn ctxt =>
    let
      val warn = Timed_Method.mk_warn "intro"
      val tac = CHANGED_PROP o REPEAT_ALL_NEW (match_tac ctxt ths)
    in
      SIMPLE_METHOD' (Timed_Method.wrap_tac' ctxt warn tac)
    end)
\<close>
method_setup simp = \<open>
  let
    val no_asmN = "no_asm"
    val no_asm_useN = "no_asm_use"
    val no_asm_simpN = "no_asm_simp"
    val asm_lrN = "asm_lr"

    val simp_options =
      (Args.parens (Args.$$$ no_asmN) >> K Simplifier.simp_tac ||
       Args.parens (Args.$$$ no_asm_simpN) >> K Simplifier.asm_simp_tac ||
       Args.parens (Args.$$$ no_asm_useN) >> K Simplifier.full_simp_tac ||
       Args.parens (Args.$$$ asm_lrN) >> K Simplifier.asm_lr_simp_tac ||
       Scan.succeed Simplifier.asm_full_simp_tac)

    fun simp_method more_mods meth =
      Scan.lift simp_options --|
        Method.sections (more_mods @ Simplifier.simp_modifiers') >>
        (fn tac => fn ctxt => METHOD (fn facts => meth ctxt tac facts))
  in
    simp_method Splitter.split_modifiers (fn ctxt => fn tac => fn facts =>
      let
        val warn = Timed_Method.mk_warn "simp"
        val base_tac =
          HEADGOAL (Method.insert_tac ctxt facts THEN' (CHANGED_PROP oo tac) ctxt)
      in
        Timed_Method.wrap_tac ctxt warn base_tac
      end)
  end
\<close>

method_setup simp_all = \<open>
  let
    val no_asmN = "no_asm"
    val no_asm_useN = "no_asm_use"
    val no_asm_simpN = "no_asm_simp"
    val asm_lrN = "asm_lr"

    val simp_options =
      (Args.parens (Args.$$$ no_asmN) >> K Simplifier.simp_tac ||
       Args.parens (Args.$$$ no_asm_simpN) >> K Simplifier.asm_simp_tac ||
       Args.parens (Args.$$$ no_asm_useN) >> K Simplifier.full_simp_tac ||
       Args.parens (Args.$$$ asm_lrN) >> K Simplifier.asm_lr_simp_tac ||
       Scan.succeed Simplifier.asm_full_simp_tac)

    fun simp_method more_mods meth =
      Scan.lift simp_options --|
        Method.sections (more_mods @ Simplifier.simp_modifiers') >>
        (fn tac => fn ctxt => METHOD (fn facts => meth ctxt tac facts))
  in
    simp_method Splitter.split_modifiers (fn ctxt => fn tac => fn facts =>
      let
        val warn = Timed_Method.mk_warn "simp_all"
        val base_tac =
          ALLGOALS (Method.insert_tac ctxt facts) THEN
            (CHANGED_PROP o PARALLEL_ALLGOALS o tac) ctxt
      in
        Timed_Method.wrap_tac ctxt warn base_tac
      end)
  end
\<close>

method_setup blast = \<open>
  Scan.lift (Scan.option Parse.nat) --|
    Method.sections Classical.cla_modifiers >>
  (fn NONE => (fn ctxt =>
      let
        val warn = Timed_Method.mk_warn "blast"
      in
        SIMPLE_METHOD' (Timed_Method.wrap_tac' ctxt warn (Blast.blast_tac ctxt))
      end)
    | SOME lim => (fn ctxt =>
      let
        val warn = Timed_Method.mk_warn "blast"
      in
        SIMPLE_METHOD' (Timed_Method.wrap_tac' ctxt warn (Blast.depth_tac ctxt lim))
      end))
\<close>

method_setup force = \<open>
  Method.sections Clasimp.clasimp_modifiers >> K (fn ctxt =>
    let
      val warn = Timed_Method.mk_warn "force"
    in
      SIMPLE_METHOD' (Timed_Method.wrap_tac' ctxt warn (Clasimp.force_tac ctxt))
    end)
\<close>

method_setup fastforce = \<open>
  Method.sections Clasimp.clasimp_modifiers >> K (fn ctxt =>
    let
      val warn = Timed_Method.mk_warn "fastforce"
    in
      SIMPLE_METHOD' (Timed_Method.wrap_tac' ctxt warn (Clasimp.fast_force_tac ctxt))
    end)
\<close>

method_setup metis = \<open>
  let
    val strip_spaces =
      ATP_Util.strip_spaces false (not o member (op =) (String.explode "[]():,"))
    val parse_multi_thm =
      ATP_Util.scan_and_trace_multi_thm
        >> apsnd (map Token.unparse #> implode_space #> strip_spaces)
  in
    Scan.lift Metis_Tactic.parse_metis_options -- Scan.repeat parse_multi_thm >>
      (fn (opts, multi_ths) => fn ctxt =>
        let
          val warn = Timed_Method.mk_warn "metis"
          val ths = maps fst multi_ths
        in
          METHOD (fn facts =>
            Timed_Method.wrap_tac ctxt warn (Metis_Tactic.metis_method (opts, ths) ctxt facts))
        end)
  end
\<close>


end
