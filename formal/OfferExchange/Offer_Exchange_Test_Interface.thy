theory Offer_Exchange_Test_Interface
  imports Offer_Exchange_Lifecycle Offer_Exchange_Divide_Layered
begin

section \<open>Differential-test transport interface\<close>

definition big_multiply_test ::
    "integer \<Rightarrow> integer \<Rightarrow> integer cxx_result"
  where
    "big_multiply_test a b =
      (case big_multiply_layered
          (word_of_int (int_of_integer a) :: int64)
          (word_of_int (int_of_integer b) :: int64)
       of Cxx_Ok value \<Rightarrow> Cxx_Ok (integer_of_int (uint value))
        | Cxx_Err error \<Rightarrow> Cxx_Err error)"

definition big_divide_or_throw_test ::
    "integer \<Rightarrow> integer \<Rightarrow> integer \<Rightarrow> cxx_rounding \<Rightarrow> integer cxx_result"
  where
    "big_divide_or_throw_test a b c rounding =
      (case big_divide_or_throw_layered
          (word_of_int (int_of_integer a) :: int64)
          (word_of_int (int_of_integer b) :: int64)
          (word_of_int (int_of_integer c) :: int64)
          rounding
       of Cxx_Ok value \<Rightarrow> Cxx_Ok (integer_of_int (sint value))
        | Cxx_Err error \<Rightarrow> Cxx_Err error)"

definition big_divide_or_throw128_test ::
    "integer \<Rightarrow> integer \<Rightarrow> cxx_rounding \<Rightarrow> integer cxx_result"
  where
    "big_divide_or_throw128_test a b rounding =
      (case big_divide_or_throw128_layered
          (word_of_int (int_of_integer a) :: uint128)
          (word_of_int (int_of_integer b) :: int64)
          rounding
       of Cxx_Ok value \<Rightarrow> Cxx_Ok (integer_of_int (sint value))
        | Cxx_Err error \<Rightarrow> Cxx_Err error)"

definition big_multiply_unsigned_test :: "integer \<Rightarrow> integer \<Rightarrow> integer"
  where
    "big_multiply_unsigned_test a b =
      integer_of_int (uint (big_multiply_unsigned
        (word_of_int (int_of_integer a) :: uint64)
        (word_of_int (int_of_integer b) :: uint64)))"

text \<open>
  The no-throw division helpers return a flag and write an out-parameter.
  The transport carries the flag and then the value.  For the wrappers that
  leave the out-parameter unassigned on failure, the value is replaced by
  zero when the flag is false, and the C++ side of the harness does the same.
  \<open>bigDivideUnsigned\<close> assigns its out-parameter on every path past the
  assertion, so its value is transported unmasked.
\<close>

definition big_divide_unsigned_test ::
    "integer \<Rightarrow> integer \<Rightarrow> integer \<Rightarrow> cxx_rounding \<Rightarrow>
      (bool \<times> integer) cxx_result"
  where
    "big_divide_unsigned_test a b c rounding =
      (case big_divide_unsigned
          (word_of_int (int_of_integer a) :: uint64)
          (word_of_int (int_of_integer b) :: uint64)
          (word_of_int (int_of_integer c) :: uint64)
          rounding
       of Cxx_Ok (flag, value) \<Rightarrow> Cxx_Ok (flag, integer_of_int (uint value))
        | Cxx_Err error \<Rightarrow> Cxx_Err error)"

definition big_divide_nothrow_test ::
    "integer \<Rightarrow> integer \<Rightarrow> integer \<Rightarrow> cxx_rounding \<Rightarrow>
      (bool \<times> integer) cxx_result"
  where
    "big_divide_nothrow_test a b c rounding =
      (case big_divide_layered
          (word_of_int (int_of_integer a) :: int64)
          (word_of_int (int_of_integer b) :: int64)
          (word_of_int (int_of_integer c) :: int64)
          rounding
       of Cxx_Ok (flag, value) \<Rightarrow>
            Cxx_Ok (flag, if flag then integer_of_int (sint value) else 0)
        | Cxx_Err error \<Rightarrow> Cxx_Err error)"

definition big_divide_unsigned128_test ::
    "integer \<Rightarrow> integer \<Rightarrow> cxx_rounding \<Rightarrow> (bool \<times> integer) cxx_result"
  where
    "big_divide_unsigned128_test a b rounding =
      (case big_divide_unsigned128
          (word_of_int (int_of_integer a) :: uint128)
          (word_of_int (int_of_integer b) :: uint64)
          rounding
       of Cxx_Ok (flag, value) \<Rightarrow>
            Cxx_Ok (flag, if flag then integer_of_int (uint value) else 0)
        | Cxx_Err error \<Rightarrow> Cxx_Err error)"

definition big_divide128_nothrow_test ::
    "integer \<Rightarrow> integer \<Rightarrow> cxx_rounding \<Rightarrow> (bool \<times> integer) cxx_result"
  where
    "big_divide128_nothrow_test a b rounding =
      (case big_divide128_layered
          (word_of_int (int_of_integer a) :: uint128)
          (word_of_int (int_of_integer b) :: int64)
          rounding
       of Cxx_Ok (flag, value) \<Rightarrow>
            Cxx_Ok (flag, if flag then integer_of_int (sint value) else 0)
        | Cxx_Err error \<Rightarrow> Cxx_Err error)"

definition check_price_error_bound_test ::
    "integer \<Rightarrow> integer \<Rightarrow> integer \<Rightarrow> integer \<Rightarrow> bool \<Rightarrow> bool cxx_result"
  where
    "check_price_error_bound_test price_n price_d wheat_receive sheep_send
        can_favor_wheat =
      check_price_error_bound
        (word_of_int (int_of_integer price_n) :: int32)
        (word_of_int (int_of_integer price_d) :: int32)
        (word_of_int (int_of_integer wheat_receive) :: int64)
        (word_of_int (int_of_integer sheep_send) :: int64)
        can_favor_wheat"

definition calculate_offer_value_test ::
    "integer \<Rightarrow> integer \<Rightarrow> integer \<Rightarrow> integer \<Rightarrow> integer cxx_result"
  where
    "calculate_offer_value_test price_n price_d max_send max_receive =
      (case calculate_offer_value
          (word_of_int (int_of_integer price_n) :: int32)
          (word_of_int (int_of_integer price_d) :: int32)
          (word_of_int (int_of_integer max_send) :: int64)
          (word_of_int (int_of_integer max_receive) :: int64)
       of Cxx_Ok value \<Rightarrow> Cxx_Ok (integer_of_int (uint value))
        | Cxx_Err error \<Rightarrow> Cxx_Err error)"

definition calculate_offer_amount_from_value_test ::
    "integer \<Rightarrow> integer \<Rightarrow> integer \<Rightarrow> integer \<Rightarrow> integer cxx_result"
  where
    "calculate_offer_amount_from_value_test price_n price_d
        max_send max_receive =
      (case calculate_offer_amount_from_value
          (word_of_int (int_of_integer price_n) :: int32)
          (word_of_int (int_of_integer price_d) :: int32)
          (word_of_int (int_of_integer max_send) :: int64)
          (word_of_int (int_of_integer max_receive) :: int64)
       of Cxx_Ok amount \<Rightarrow> Cxx_Ok (integer_of_int (sint amount))
        | Cxx_Err error \<Rightarrow> Cxx_Err error)"


datatype exchange_result_transport =
  Exchange_Result_Transport integer integer bool

definition apply_price_error_thresholds_test ::
    "integer \<Rightarrow> integer \<Rightarrow> integer \<Rightarrow> integer \<Rightarrow> bool \<Rightarrow> exchange_rounding \<Rightarrow>
      exchange_result_transport cxx_result"
  where
    "apply_price_error_thresholds_test price_n price_d wheat_receive sheep_send
        wheat_stays rounding =
      (case apply_price_error_thresholds
          (word_of_int (int_of_integer price_n) :: int32)
          (word_of_int (int_of_integer price_d) :: int32)
          (word_of_int (int_of_integer wheat_receive) :: int64)
          (word_of_int (int_of_integer sheep_send) :: int64)
          wheat_stays rounding
       of Cxx_Ok result \<Rightarrow> Cxx_Ok
            (Exchange_Result_Transport
              (integer_of_int (sint (num_wheat_received result)))
              (integer_of_int (sint (num_sheep_send result)))
              (result_wheat_stays result))
        | Cxx_Err error \<Rightarrow> Cxx_Err error)"
definition exchange_v10_without_price_error_thresholds_test ::
    "integer \<Rightarrow> integer \<Rightarrow> integer \<Rightarrow> integer \<Rightarrow> integer \<Rightarrow> integer \<Rightarrow>
      exchange_rounding \<Rightarrow> integer \<Rightarrow>
      exchange_result_transport cxx_result"
  where
    "exchange_v10_without_price_error_thresholds_test price_n price_d
        max_wheat_send max_wheat_receive max_sheep_send max_sheep_receive
        rounding ledger_version =
      (case exchange_v10_without_price_error_thresholds
          (word_of_int (int_of_integer ledger_version) :: uint32)
          (word_of_int (int_of_integer price_n) :: int32)
          (word_of_int (int_of_integer price_d) :: int32)
          (word_of_int (int_of_integer max_wheat_send) :: int64)
          (word_of_int (int_of_integer max_wheat_receive) :: int64)
          (word_of_int (int_of_integer max_sheep_send) :: int64)
          (word_of_int (int_of_integer max_sheep_receive) :: int64)
          rounding
       of Cxx_Ok result \<Rightarrow> Cxx_Ok
            (Exchange_Result_Transport
              (integer_of_int (sint (num_wheat_received result)))
              (integer_of_int (sint (num_sheep_send result)))
              (result_wheat_stays result))
        | Cxx_Err error \<Rightarrow> Cxx_Err error)"


definition exchange_v10_test ::
    "integer \<Rightarrow> integer \<Rightarrow> integer \<Rightarrow> integer \<Rightarrow> integer \<Rightarrow> integer \<Rightarrow>
      exchange_rounding \<Rightarrow> integer \<Rightarrow>
      exchange_result_transport cxx_result"
  where
    "exchange_v10_test price_n price_d
        max_wheat_send max_wheat_receive max_sheep_send max_sheep_receive
        rounding ledger_version =
      (case exchange_v10
          (word_of_int (int_of_integer ledger_version) :: uint32)
          (word_of_int (int_of_integer price_n) :: int32)
          (word_of_int (int_of_integer price_d) :: int32)
          (word_of_int (int_of_integer max_wheat_send) :: int64)
          (word_of_int (int_of_integer max_wheat_receive) :: int64)
          (word_of_int (int_of_integer max_sheep_send) :: int64)
          (word_of_int (int_of_integer max_sheep_receive) :: int64)
          rounding
       of Cxx_Ok result \<Rightarrow> Cxx_Ok
            (Exchange_Result_Transport
              (integer_of_int (sint (num_wheat_received result)))
              (integer_of_int (sint (num_sheep_send result)))
              (result_wheat_stays result))
        | Cxx_Err error \<Rightarrow> Cxx_Err error)"

definition adjust_offer_test ::
    "integer \<Rightarrow> integer \<Rightarrow> integer \<Rightarrow> integer \<Rightarrow> integer \<Rightarrow>
      integer cxx_result"
  where
    "adjust_offer_test price_n price_d max_wheat_send max_sheep_receive
        ledger_version =
      (case adjust_offer
          (word_of_int (int_of_integer ledger_version) :: uint32)
          (word_of_int (int_of_integer price_n) :: int32)
          (word_of_int (int_of_integer price_d) :: int32)
          (word_of_int (int_of_integer max_wheat_send) :: int64)
          (word_of_int (int_of_integer max_sheep_receive) :: int64)
       of Cxx_Ok value \<Rightarrow> Cxx_Ok (integer_of_int (sint value))
        | Cxx_Err error \<Rightarrow> Cxx_Err error)"

text \<open>
  These adapters expose the remaining maker-independent Adjustment definitions
  over transport-level integers.  The liability adapters preserve modeled C++
  errors and signed results; the three filters return their Boolean decisions
  directly.
\<close>

definition offer_selling_liabilities_test ::
    "integer \<Rightarrow> integer \<Rightarrow> integer \<Rightarrow> integer \<Rightarrow>
      integer cxx_result"
  where
    "offer_selling_liabilities_test price_n price_d ledger_version amount =
      (case offer_selling_liabilities_at_version
          (word_of_int (int_of_integer ledger_version) :: uint32)
          (word_of_int (int_of_integer price_n) :: int32)
          (word_of_int (int_of_integer price_d) :: int32)
          (word_of_int (int_of_integer amount) :: int64)
       of Cxx_Ok value \<Rightarrow> Cxx_Ok (integer_of_int (sint value))
        | Cxx_Err error \<Rightarrow> Cxx_Err error)"

definition offer_buying_liabilities_test ::
    "integer \<Rightarrow> integer \<Rightarrow> integer \<Rightarrow> integer \<Rightarrow>
      integer cxx_result"
  where
    "offer_buying_liabilities_test price_n price_d ledger_version amount =
      (case offer_buying_liabilities_at_version
          (word_of_int (int_of_integer ledger_version) :: uint32)
          (word_of_int (int_of_integer price_n) :: int32)
          (word_of_int (int_of_integer price_d) :: int32)
          (word_of_int (int_of_integer amount) :: int64)
       of Cxx_Ok value \<Rightarrow> Cxx_Ok (integer_of_int (sint value))
        | Cxx_Err error \<Rightarrow> Cxx_Err error)"

subsection \<open>Offer-lifecycle transport\<close>

text \<open>
  Lifecycle outputs have one fixed physical order.  After the runner's
  transport status field, the 27 fields are: stage, post created, canonical
  price numerator, canonical price denominator, posted amount, maker after
  posting (five fields), limit change accepted, resulting buy limit, resulting
  buying capacity, cross succeeded, wheat received, sheep sent, remaining
  offer, final maker (five fields), and final taker (five fields).  Every
  party-state group is ordered
  @{text \<open>sell_balance, sell_liabilities, buy_limit, buy_balance,
    buy_liabilities\<close>}.

  The stable stage enum is: 1 malformed post; 2 line full; 3 underfunded;
  4 no offer; 5 invalid limit change; 6--8 posting assertion, overflow, and
  runtime error; 9--11 crossing assertion, overflow, and runtime error; and
  12 successful crossing.  Thus operation rejection is never conflated with a
  modeled C++ failure.  Fields unavailable at a stage have the canonical value
  zero or False.

  Stage 0 is retired.  It meant overlay rejection, which this model no longer
  performs: the protocol-29 overlay-admission filter is out of scope, and the
  earlier prototype filter this model carried is not the one stellar-core
  ships.
\<close>

datatype lifecycle_transport =
  Lifecycle_Transport
    integer bool
    integer integer integer
    integer integer integer integer integer
    bool integer integer
    bool integer integer integer
    integer integer integer integer integer
    integer integer integer integer integer

fun post_failure_stage :: "post_outcome \<Rightarrow> integer"
  where
    "post_failure_stage Post_Malformed = 1"
  | "post_failure_stage Post_Line_Full = 2"
  | "post_failure_stage Post_Underfunded = 3"
  | "post_failure_stage Post_No_Offer = 4"
  | "post_failure_stage (Post_Created amount maker) = 1"

fun post_cxx_error_stage :: "cxx_error \<Rightarrow> integer"
  where
    "post_cxx_error_stage Cxx_Assertion_Failed = 6"
  | "post_cxx_error_stage Cxx_Overflow = 7"
  | "post_cxx_error_stage Cxx_Runtime_Error = 8"

fun cross_cxx_error_stage :: "cxx_error \<Rightarrow> integer"
  where
    "cross_cxx_error_stage Cxx_Assertion_Failed = 9"
  | "cross_cxx_error_stage Cxx_Overflow = 10"
  | "cross_cxx_error_stage Cxx_Runtime_Error = 11"

definition empty_lifecycle_transport ::
    "integer \<Rightarrow> lifecycle_transport"
  where
    "empty_lifecycle_transport stage =
      Lifecycle_Transport stage False
        0 0 0  0 0 0 0 0  False 0 0  False 0 0 0
        0 0 0 0 0  0 0 0 0 0"

fun lifecycle_outcome_transport ::
    "lifecycle_outcome \<Rightarrow> lifecycle_transport"
  where
    "lifecycle_outcome_transport (Post_Failed failed) =
       empty_lifecycle_transport (post_failure_stage failed)"
  | "lifecycle_outcome_transport (Post_Cxx_Error error) =
       empty_lifecycle_transport (post_cxx_error_stage error)"
  | "lifecycle_outcome_transport (Limit_Change_Invalid prefix) =
       Lifecycle_Transport 5 True
         (integer_of_int (sint (lifecycle_prefix_price_n prefix)))
         (integer_of_int (sint (lifecycle_prefix_price_d prefix)))
         (integer_of_int (sint (lifecycle_prefix_posted_amount prefix)))
         (integer_of_int
           (sint (sell_balance (lifecycle_prefix_maker_after_post prefix))))
         (integer_of_int
           (sint (sell_liabilities (lifecycle_prefix_maker_after_post prefix))))
         (integer_of_int
           (sint (buy_limit (lifecycle_prefix_maker_after_post prefix))))
         (integer_of_int
           (sint (buy_balance (lifecycle_prefix_maker_after_post prefix))))
         (integer_of_int
           (sint (buy_liabilities (lifecycle_prefix_maker_after_post prefix))))
         False
         (integer_of_int
           (sint (buy_limit (lifecycle_prefix_maker_after_limit prefix))))
         0 False 0 0 0
         0 0 0 0 0  0 0 0 0 0"
  | "lifecycle_outcome_transport (Cross_Cxx_Error error prefix) =
       Lifecycle_Transport (cross_cxx_error_stage error) True
         (integer_of_int (sint (lifecycle_prefix_price_n prefix)))
         (integer_of_int (sint (lifecycle_prefix_price_d prefix)))
         (integer_of_int (sint (lifecycle_prefix_posted_amount prefix)))
         (integer_of_int
           (sint (sell_balance (lifecycle_prefix_maker_after_post prefix))))
         (integer_of_int
           (sint (sell_liabilities (lifecycle_prefix_maker_after_post prefix))))
         (integer_of_int
           (sint (buy_limit (lifecycle_prefix_maker_after_post prefix))))
         (integer_of_int
           (sint (buy_balance (lifecycle_prefix_maker_after_post prefix))))
         (integer_of_int
           (sint (buy_liabilities (lifecycle_prefix_maker_after_post prefix))))
         True
         (integer_of_int
           (sint (buy_limit (lifecycle_prefix_maker_after_limit prefix))))
         (integer_of_int
           (sint (can_buy_at_most
             (lifecycle_prefix_maker_after_limit prefix))))
         False 0 0 0
         0 0 0 0 0  0 0 0 0 0"
  | "lifecycle_outcome_transport (Crossed trace) =
       Lifecycle_Transport 12 True
         (integer_of_int (sint (lifecycle_price_n trace)))
         (integer_of_int (sint (lifecycle_price_d trace)))
         (integer_of_int (sint (lifecycle_posted_amount trace)))
         (integer_of_int
           (sint (sell_balance (lifecycle_maker_after_post trace))))
         (integer_of_int
           (sint (sell_liabilities (lifecycle_maker_after_post trace))))
         (integer_of_int
           (sint (buy_limit (lifecycle_maker_after_post trace))))
         (integer_of_int
           (sint (buy_balance (lifecycle_maker_after_post trace))))
         (integer_of_int
           (sint (buy_liabilities (lifecycle_maker_after_post trace))))
         True
         (integer_of_int
           (sint (buy_limit (lifecycle_maker_after_limit trace))))
         (integer_of_int
           (sint (can_buy_at_most (lifecycle_maker_after_limit trace))))
         True
         (integer_of_int
           (sint (cross_wheat_received (lifecycle_cross_result trace))))
         (integer_of_int
           (sint (cross_sheep_send (lifecycle_cross_result trace))))
         (integer_of_int
           (sint (cross_offer_amount (lifecycle_cross_result trace))))
         (integer_of_int
           (sint (sell_balance (cross_maker (lifecycle_cross_result trace)))))
         (integer_of_int
           (sint (sell_liabilities
             (cross_maker (lifecycle_cross_result trace)))))
         (integer_of_int
           (sint (buy_limit (cross_maker (lifecycle_cross_result trace)))))
         (integer_of_int
           (sint (buy_balance (cross_maker (lifecycle_cross_result trace)))))
         (integer_of_int
           (sint (buy_liabilities
             (cross_maker (lifecycle_cross_result trace)))))
         (integer_of_int
           (sint (sell_balance (cross_taker (lifecycle_cross_result trace)))))
         (integer_of_int
           (sint (sell_liabilities
             (cross_taker (lifecycle_cross_result trace)))))
         (integer_of_int
           (sint (buy_limit (cross_taker (lifecycle_cross_result trace)))))
         (integer_of_int
           (sint (buy_balance (cross_taker (lifecycle_cross_result trace)))))
         (integer_of_int
           (sint (buy_liabilities
             (cross_taker (lifecycle_cross_result trace)))))"

definition offer_lifecycle_test ::
    "integer \<Rightarrow> bool \<Rightarrow> integer \<Rightarrow> integer \<Rightarrow>
      integer \<Rightarrow> integer \<Rightarrow> integer \<Rightarrow> integer \<Rightarrow>
      integer \<Rightarrow> integer \<Rightarrow> integer \<Rightarrow>
      lifecycle_transport"
  where
    "offer_lifecycle_test ledger_version is_buy price_n price_d amount
        maker_sell_balance maker_sell_liabilities maker_buy_limit
        maker_buy_balance maker_buy_liabilities new_buy_limit =
      (let request =
         (if is_buy
          then Manage_Buy
            (word_of_int (int_of_integer price_n) :: int32)
            (word_of_int (int_of_integer price_d) :: int32)
            (word_of_int (int_of_integer amount) :: int64)
          else Manage_Sell
            (word_of_int (int_of_integer price_n) :: int32)
            (word_of_int (int_of_integer price_d) :: int32)
            (word_of_int (int_of_integer amount) :: int64));
         maker =
           \<lparr>sell_balance =
              (word_of_int (int_of_integer maker_sell_balance) :: int64),
            sell_liabilities =
              (word_of_int (int_of_integer maker_sell_liabilities) :: int64),
            buy_limit =
              (word_of_int (int_of_integer maker_buy_limit) :: int64),
            buy_balance =
              (word_of_int (int_of_integer maker_buy_balance) :: int64),
            buy_liabilities =
              (word_of_int (int_of_integer maker_buy_liabilities) :: int64)\<rparr>;
         outcome = run_offer_lifecycle
           (word_of_int (int_of_integer ledger_version) :: uint32) request maker
           (word_of_int (int_of_integer new_buy_limit) :: int64)
       in lifecycle_outcome_transport outcome)"

export_code big_multiply_test big_divide_or_throw_test
    big_divide_or_throw128_test big_multiply_unsigned_test
    big_divide_unsigned_test big_divide_nothrow_test
    big_divide_unsigned128_test big_divide128_nothrow_test
    check_price_error_bound_test
    calculate_offer_value_test
    calculate_offer_amount_from_value_test
    apply_price_error_thresholds_test
    exchange_v10_without_price_error_thresholds_test exchange_v10_test
    adjust_offer_test offer_selling_liabilities_test
    offer_buying_liabilities_test
    offer_lifecycle_test Lifecycle_Transport
    Cxx_Round_Down Cxx_Round_Up Exchange_Normal Exchange_Strict_Send
    Exchange_Strict_Receive Exchange_Result_Transport Cxx_Ok Cxx_Err
    Cxx_Assertion_Failed Cxx_Overflow Cxx_Runtime_Error
  in SML module_name Offer_Exchange_Model
  file_prefix offer_exchange_model

end
