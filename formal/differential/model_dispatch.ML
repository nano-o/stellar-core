(*  Project dispatch for the generic model runner
    ($ISABELLE_TOOLING_ROOT/model-runner/runner.ML).

    This file is trusted semantic code: it converts and routes, it never
    decides. Allowed here: splitting a record into fields, decimal text to
    integers and back, range checks against the declared C++ type of each
    parameter, selecting the exported function for the tag, and formatting the
    result. Not allowed: domain arithmetic, or branching on values beyond
    choosing the tag's function and reporting a parse or range failure. Review
    it against the exported signatures in Offer_Exchange_Test_Interface.thy.

    Record convention: `v1 <tag> <case_id> <inputs...>` in, `OK <fields...>` or
    `ERR <code>` out, where the code is the C++ failure the model reports
    (ASSERTION, OVERFLOW, RUNTIME). Cross-record structure (duplicate case ids,
    the `#schema` prelude) is checked by run.sh, not here. *)

structure Model_Dispatch =
struct

exception Reject of string

fun fail message = raise Reject message

fun is_digit character = #"0" <= character andalso character <= #"9"

fun parse_decimal field_name input =
  let
    val size = String.size input
    val (negative, first_digit) =
      if size > 0 andalso String.sub (input, 0) = #"-"
      then (true, 1)
      else (false, 0)

    fun accumulate index value =
      if index = size
      then value
      else
        let
          val character = String.sub (input, index)
          val digit = Char.ord character - Char.ord #"0"
        in
          if is_digit character
          then accumulate (index + 1)
                 (IntInf.+ (IntInf.* (value, 10), IntInf.fromInt digit))
          else fail
                 ("invalid decimal " ^ field_name ^ ": " ^ input)
        end
  in
    if first_digit = size
    then fail ("empty decimal " ^ field_name)
    else
      let
        val magnitude = accumulate first_digit 0
      in
        if negative then IntInf.~ magnitude else magnitude
      end
  end

val int32_min = IntInf.~ 2147483648
val int32_max = 2147483647 : IntInf.int
val uint32_max = 4294967295 : IntInf.int
val int64_min = IntInf.~ 9223372036854775808
val int64_max = 9223372036854775807 : IntInf.int
val uint128_max =
  340282366920938463463374607431768211455 : IntInf.int
val uint64_max = 18446744073709551615 : IntInf.int

fun require_range field_name minimum maximum value =
  if value < minimum orelse value > maximum
  then fail
         (field_name ^ " is outside its C++ range: " ^ IntInf.toString value)
  else ()

fun valid_case_id_character character =
  Char.isAlphaNum character orelse
  character = #"_" orelse character = #"-" orelse character = #"."

fun require_case_id case_id =
  if String.size case_id = 0
  then fail "case_id is empty"
  else if List.all valid_case_id_character (String.explode case_id)
  then ()
  else fail ("invalid case_id: " ^ case_id)

fun join_tabs fields = String.concatWith "\t" fields

fun format_decimal value =
  let
    val text = IntInf.toString value
  in
    if String.isPrefix "~" text
    then "-" ^ String.extract (text, 1, NONE)
    else text
  end

fun error_name Offer_Exchange_Model.Cxx_Assertion_Failed = "ASSERTION"
  | error_name Offer_Exchange_Model.Cxx_Overflow = "OVERFLOW"
  | error_name Offer_Exchange_Model.Cxx_Runtime_Error = "RUNTIME"

fun parse_bool field_name "0" = false
  | parse_bool field_name "1" = true
  | parse_bool field_name input =
      fail ("invalid boolean " ^ field_name ^ ": " ^ input)

fun parse_rounding "DOWN" = Offer_Exchange_Model.Cxx_Round_Down
  | parse_rounding "UP" = Offer_Exchange_Model.Cxx_Round_Up
  | parse_rounding input =
      fail ("invalid rounding: " ^ input)

fun parse_exchange_rounding "NORMAL" =
      Offer_Exchange_Model.Exchange_Normal
  | parse_exchange_rounding "STRICT_SEND" =
      Offer_Exchange_Model.Exchange_Strict_Send
  | parse_exchange_rounding "STRICT_RECEIVE" =
      Offer_Exchange_Model.Exchange_Strict_Receive
  | parse_exchange_rounding input =
      fail ("invalid exchange rounding: " ^ input)

fun process_big_divide case_id a_text b_text c_text
    rounding_text =
  let
    val _ = require_case_id case_id
    val a = parse_decimal "A" a_text
    val b = parse_decimal "B" b_text
    val c = parse_decimal "C" c_text
    val rounding = parse_rounding rounding_text
    val _ = require_range "A" int64_min int64_max a
    val _ = require_range "B" int64_min int64_max b
    val _ = require_range "C" int64_min int64_max c
    val suffix =
      (case Offer_Exchange_Model.big_divide_or_throw_test
          a b c rounding of
        Offer_Exchange_Model.Cxx_Ok value =>
          ["OK", format_decimal value]
      | Offer_Exchange_Model.Cxx_Err error =>
          ["ERR", error_name error])
  in
    join_tabs suffix
  end

fun process_big_divide128 case_id a_text b_text
    rounding_text =
  let
    val _ = require_case_id case_id
    val a = parse_decimal "a" a_text
    val b = parse_decimal "B" b_text
    val rounding = parse_rounding rounding_text
    val _ = require_range "a" 0 uint128_max a
    val _ = require_range "B" int64_min int64_max b
    val suffix =
      (case Offer_Exchange_Model.big_divide_or_throw128_test
          a b rounding of
        Offer_Exchange_Model.Cxx_Ok value =>
          ["OK", format_decimal value]
      | Offer_Exchange_Model.Cxx_Err error =>
          ["ERR", error_name error])
  in
    join_tabs suffix
  end

fun process_big_multiply case_id a_text b_text =
  let
    val _ = require_case_id case_id
    val a = parse_decimal "a" a_text
    val b = parse_decimal "b" b_text
    val _ = require_range "a" int64_min int64_max a
    val _ = require_range "b" int64_min int64_max b
    val suffix =
      (case Offer_Exchange_Model.big_multiply_test a b of
        Offer_Exchange_Model.Cxx_Ok value =>
          ["OK", format_decimal value]
      | Offer_Exchange_Model.Cxx_Err error =>
          ["ERR", error_name error])
  in
    join_tabs suffix
  end

fun process_big_multiply_unsigned case_id a_text b_text =
  let
    val _ = require_case_id case_id
    val a = parse_decimal "a" a_text
    val b = parse_decimal "b" b_text
    val _ = require_range "a" 0 uint64_max a
    val _ = require_range "b" 0 uint64_max b
    val value = Offer_Exchange_Model.big_multiply_unsigned_test a b
  in
    join_tabs ["OK", format_decimal value]
  end

(* The no-throw helpers return a Boolean and write an out-parameter.  Both are
   transported as result fields: the flag as 0/1, then the value. *)
fun flag_value_suffix result =
  (case result of
    Offer_Exchange_Model.Cxx_Ok (flag, value) =>
      ["OK", if flag then "1" else "0", format_decimal value]
  | Offer_Exchange_Model.Cxx_Err error =>
      ["ERR", error_name error])

fun process_big_divide_unsigned case_id a_text b_text c_text
    rounding_text =
  let
    val _ = require_case_id case_id
    val a = parse_decimal "A" a_text
    val b = parse_decimal "B" b_text
    val c = parse_decimal "C" c_text
    val rounding = parse_rounding rounding_text
    val _ = require_range "A" 0 uint64_max a
    val _ = require_range "B" 0 uint64_max b
    val _ = require_range "C" 0 uint64_max c
    val suffix = flag_value_suffix
      (Offer_Exchange_Model.big_divide_unsigned_test a b c rounding)
  in
    join_tabs suffix
  end

fun process_big_divide_nothrow case_id a_text b_text c_text
    rounding_text =
  let
    val _ = require_case_id case_id
    val a = parse_decimal "A" a_text
    val b = parse_decimal "B" b_text
    val c = parse_decimal "C" c_text
    val rounding = parse_rounding rounding_text
    val _ = require_range "A" int64_min int64_max a
    val _ = require_range "B" int64_min int64_max b
    val _ = require_range "C" int64_min int64_max c
    val suffix = flag_value_suffix
      (Offer_Exchange_Model.big_divide_nothrow_test a b c rounding)
  in
    join_tabs suffix
  end

fun process_big_divide_unsigned128 case_id a_text b_text
    rounding_text =
  let
    val _ = require_case_id case_id
    val a = parse_decimal "a" a_text
    val b = parse_decimal "B" b_text
    val rounding = parse_rounding rounding_text
    val _ = require_range "a" 0 uint128_max a
    val _ = require_range "B" 0 uint64_max b
    val suffix = flag_value_suffix
      (Offer_Exchange_Model.big_divide_unsigned128_test a b rounding)
  in
    join_tabs suffix
  end

fun process_big_divide128_nothrow case_id a_text b_text
    rounding_text =
  let
    val _ = require_case_id case_id
    val a = parse_decimal "a" a_text
    val b = parse_decimal "B" b_text
    val rounding = parse_rounding rounding_text
    val _ = require_range "a" 0 uint128_max a
    val _ = require_range "B" int64_min int64_max b
    val suffix = flag_value_suffix
      (Offer_Exchange_Model.big_divide128_nothrow_test a b rounding)
  in
    join_tabs suffix
  end

fun process_price_error_bound case_id price_n_text
    price_d_text wheat_receive_text sheep_send_text can_favor_wheat_text =
  let
    val _ = require_case_id case_id
    val price_n = parse_decimal "price_n" price_n_text
    val price_d = parse_decimal "price_d" price_d_text
    val wheat_receive =
      parse_decimal "wheat_receive" wheat_receive_text
    val sheep_send = parse_decimal "sheep_send" sheep_send_text
    val can_favor_wheat =
      parse_bool "can_favor_wheat" can_favor_wheat_text
    val _ = require_range "price_n" int32_min int32_max price_n
    val _ = require_range "price_d" int32_min int32_max price_d
    val _ =
      require_range "wheat_receive" int64_min int64_max wheat_receive
    val _ = require_range "sheep_send" int64_min int64_max sheep_send
    val suffix =
      (case Offer_Exchange_Model.check_price_error_bound_test
          price_n price_d wheat_receive sheep_send can_favor_wheat of
        Offer_Exchange_Model.Cxx_Ok value =>
          ["OK", if value then "1" else "0"]
      | Offer_Exchange_Model.Cxx_Err error =>
          ["ERR", error_name error])
  in
    join_tabs suffix
  end

fun process_offer_value case_id price_n_text price_d_text
    max_send_text max_receive_text =
  let
    val _ = require_case_id case_id
    val price_n = parse_decimal "price_n" price_n_text
    val price_d = parse_decimal "price_d" price_d_text
    val max_send = parse_decimal "max_send" max_send_text
    val max_receive = parse_decimal "max_receive" max_receive_text
    val _ = require_range "price_n" int32_min int32_max price_n
    val _ = require_range "price_d" int32_min int32_max price_d
    val _ = require_range "max_send" int64_min int64_max max_send
    val _ = require_range "max_receive" int64_min int64_max max_receive
    val suffix =
      (case Offer_Exchange_Model.calculate_offer_value_test
          price_n price_d max_send max_receive of
        Offer_Exchange_Model.Cxx_Ok value =>
          ["OK", format_decimal value]
      | Offer_Exchange_Model.Cxx_Err error =>
          ["ERR", error_name error])
  in
    join_tabs suffix
  end

fun process_offer_amount_from_value case_id
    price_n_text price_d_text max_send_text max_receive_text =
  let
    val _ = require_case_id case_id
    val price_n = parse_decimal "price_n" price_n_text
    val price_d = parse_decimal "price_d" price_d_text
    val max_send = parse_decimal "max_send" max_send_text
    val max_receive = parse_decimal "max_receive" max_receive_text
    val _ = require_range "price_n" int32_min int32_max price_n
    val _ = require_range "price_d" int32_min int32_max price_d
    val _ = require_range "max_send" int64_min int64_max max_send
    val _ = require_range "max_receive" int64_min int64_max max_receive
    val suffix =
      (case Offer_Exchange_Model.calculate_offer_amount_from_value_test
          price_n price_d max_send max_receive of
        Offer_Exchange_Model.Cxx_Ok value =>
          ["OK", format_decimal value]
      | Offer_Exchange_Model.Cxx_Err error =>
          ["ERR", error_name error])
  in
    join_tabs suffix
  end

fun process_adjust_offer case_id price_n_text price_d_text
    max_wheat_send_text max_sheep_receive_text ledger_version_text =
  let
    val _ = require_case_id case_id
    val price_n = parse_decimal "price_n" price_n_text
    val price_d = parse_decimal "price_d" price_d_text
    val max_wheat_send =
      parse_decimal "max_wheat_send" max_wheat_send_text
    val max_sheep_receive =
      parse_decimal "max_sheep_receive" max_sheep_receive_text
    val ledger_version =
      parse_decimal "ledger_version" ledger_version_text
    val _ = require_range "price_n" int32_min int32_max price_n
    val _ = require_range "price_d" int32_min int32_max price_d
    val _ = require_range "ledger_version" 0 uint32_max ledger_version
    val _ = require_range "max_wheat_send"
      int64_min int64_max max_wheat_send
    val _ = require_range "max_sheep_receive"
      int64_min int64_max max_sheep_receive
    val suffix =
      (case Offer_Exchange_Model.adjust_offer_test
          price_n price_d max_wheat_send max_sheep_receive
          ledger_version of
        Offer_Exchange_Model.Cxx_Ok value =>
          ["OK", format_decimal value]
      | Offer_Exchange_Model.Cxx_Err error =>
          ["ERR", error_name error])
  in
    join_tabs suffix
  end

fun process_adjustment_liability model case_id
    price_n_text price_d_text ledger_version_text amount_text =
  let
    val _ = require_case_id case_id
    val price_n = parse_decimal "price_n" price_n_text
    val price_d = parse_decimal "price_d" price_d_text
    val ledger_version =
      parse_decimal "ledger_version" ledger_version_text
    val amount = parse_decimal "amount" amount_text
    val _ = require_range "price_n" int32_min int32_max price_n
    val _ = require_range "price_d" int32_min int32_max price_d
    val _ = require_range "ledger_version" 0 uint32_max ledger_version
    val _ = require_range "amount" int64_min int64_max amount
    val suffix =
      (case model price_n price_d ledger_version amount of
        Offer_Exchange_Model.Cxx_Ok value =>
          ["OK", format_decimal value]
      | Offer_Exchange_Model.Cxx_Err error =>
          ["ERR", error_name error])
  in
    join_tabs suffix
  end

fun bool_field value = if value then "1" else "0"

fun process_offer_lifecycle is_buy case_id price_n_text
    price_d_text ledger_version_text amount_text maker_sell_balance_text
    maker_sell_liabilities_text maker_buy_limit_text maker_buy_balance_text
    maker_buy_liabilities_text new_buy_limit_text =
  let
    val _ = require_case_id case_id
    val price_n = parse_decimal "price_n" price_n_text
    val price_d = parse_decimal "price_d" price_d_text
    val ledger_version =
      parse_decimal "ledger_version" ledger_version_text
    val amount = parse_decimal "amount" amount_text
    val maker_sell_balance =
      parse_decimal "maker_sell_balance" maker_sell_balance_text
    val maker_sell_liabilities =
      parse_decimal "maker_sell_liabilities"
        maker_sell_liabilities_text
    val maker_buy_limit =
      parse_decimal "maker_buy_limit" maker_buy_limit_text
    val maker_buy_balance =
      parse_decimal "maker_buy_balance" maker_buy_balance_text
    val maker_buy_liabilities =
      parse_decimal "maker_buy_liabilities"
        maker_buy_liabilities_text
    val new_buy_limit =
      parse_decimal "new_buy_limit" new_buy_limit_text
    val _ = require_range "price_n" int32_min int32_max price_n
    val _ = require_range "price_d" int32_min int32_max price_d
    val _ = require_range "ledger_version" 0 uint32_max ledger_version
    val _ = require_range "amount" int64_min int64_max amount
    val _ = require_range "maker_sell_balance"
      int64_min int64_max maker_sell_balance
    val _ = require_range "maker_sell_liabilities"
      int64_min int64_max maker_sell_liabilities
    val _ = require_range "maker_buy_limit"
      int64_min int64_max maker_buy_limit
    val _ = require_range "maker_buy_balance"
      int64_min int64_max maker_buy_balance
    val _ = require_range "maker_buy_liabilities"
      int64_min int64_max maker_buy_liabilities
    val _ = require_range "new_buy_limit"
      int64_min int64_max new_buy_limit
    val suffix =
      (case Offer_Exchange_Model.offer_lifecycle_test ledger_version is_buy
          price_n price_d amount maker_sell_balance maker_sell_liabilities
          maker_buy_limit maker_buy_balance maker_buy_liabilities
          new_buy_limit of
        Offer_Exchange_Model.Lifecycle_Transport
          (stage, post_created,
           canonical_price_n, canonical_price_d, posted_amount,
           maker_post_sell_balance, maker_post_sell_liabilities,
           maker_post_buy_limit, maker_post_buy_balance,
           maker_post_buy_liabilities, limit_changed, resulting_buy_limit,
           resulting_buy_capacity, cross_succeeded, wheat_received,
           sheep_sent, remaining_offer, final_maker_sell_balance,
           final_maker_sell_liabilities, final_maker_buy_limit,
           final_maker_buy_balance, final_maker_buy_liabilities,
           final_taker_sell_balance, final_taker_sell_liabilities,
           final_taker_buy_limit, final_taker_buy_balance,
           final_taker_buy_liabilities) =>
          ["OK", format_decimal stage,
           bool_field post_created, format_decimal canonical_price_n,
           format_decimal canonical_price_d, format_decimal posted_amount,
           format_decimal maker_post_sell_balance,
           format_decimal maker_post_sell_liabilities,
           format_decimal maker_post_buy_limit,
           format_decimal maker_post_buy_balance,
           format_decimal maker_post_buy_liabilities,
           bool_field limit_changed, format_decimal resulting_buy_limit,
           format_decimal resulting_buy_capacity,
           bool_field cross_succeeded, format_decimal wheat_received,
           format_decimal sheep_sent, format_decimal remaining_offer,
           format_decimal final_maker_sell_balance,
           format_decimal final_maker_sell_liabilities,
           format_decimal final_maker_buy_limit,
           format_decimal final_maker_buy_balance,
           format_decimal final_maker_buy_liabilities,
           format_decimal final_taker_sell_balance,
           format_decimal final_taker_sell_liabilities,
           format_decimal final_taker_buy_limit,
           format_decimal final_taker_buy_balance,
           format_decimal final_taker_buy_liabilities])
  in
    join_tabs suffix
  end

fun process_apply_price_error_thresholds case_id
    price_n_text price_d_text wheat_receive_text sheep_send_text
    wheat_stays_text rounding_text =
  let
    val _ = require_case_id case_id
    val price_n = parse_decimal "price_n" price_n_text
    val price_d = parse_decimal "price_d" price_d_text
    val wheat_receive =
      parse_decimal "wheat_receive" wheat_receive_text
    val sheep_send = parse_decimal "sheep_send" sheep_send_text
    val wheat_stays = parse_bool "wheat_stays" wheat_stays_text
    val rounding = parse_exchange_rounding rounding_text
    val _ = require_range "price_n" int32_min int32_max price_n
    val _ = require_range "price_d" int32_min int32_max price_d
    val _ =
      require_range "wheat_receive" int64_min int64_max wheat_receive
    val _ = require_range "sheep_send" int64_min int64_max sheep_send
    val suffix =
      (case Offer_Exchange_Model.apply_price_error_thresholds_test
          price_n price_d wheat_receive sheep_send wheat_stays rounding of
        Offer_Exchange_Model.Cxx_Ok
            (Offer_Exchange_Model.Exchange_Result_Transport
              (actual_wheat_receive, actual_sheep_send,
               actual_wheat_stays)) =>
          ["OK", format_decimal actual_wheat_receive,
           format_decimal actual_sheep_send,
           if actual_wheat_stays then "1" else "0"]
      | Offer_Exchange_Model.Cxx_Err error =>
          ["ERR", error_name error])
  in
    join_tabs suffix
  end

fun process_exchange_v10_like model case_id price_n_text
    price_d_text max_wheat_send_text
    max_wheat_receive_text max_sheep_send_text max_sheep_receive_text
    rounding_text ledger_version_text =
  let
    val _ = require_case_id case_id
    val price_n = parse_decimal "price_n" price_n_text
    val price_d = parse_decimal "price_d" price_d_text
    val max_wheat_send =
      parse_decimal "max_wheat_send" max_wheat_send_text
    val max_wheat_receive =
      parse_decimal "max_wheat_receive" max_wheat_receive_text
    val max_sheep_send =
      parse_decimal "max_sheep_send" max_sheep_send_text
    val max_sheep_receive =
      parse_decimal "max_sheep_receive" max_sheep_receive_text
    val rounding = parse_exchange_rounding rounding_text
    val ledger_version =
      parse_decimal "ledger_version" ledger_version_text
    val _ = require_range "price_n" int32_min int32_max price_n
    val _ = require_range "price_d" int32_min int32_max price_d
    val _ = require_range "ledger_version" 0 uint32_max ledger_version
    val _ = require_range "max_wheat_send"
      int64_min int64_max max_wheat_send
    val _ = require_range "max_wheat_receive"
      int64_min int64_max max_wheat_receive
    val _ = require_range "max_sheep_send"
      int64_min int64_max max_sheep_send
    val _ = require_range "max_sheep_receive"
      int64_min int64_max max_sheep_receive
    val suffix =
      (case model price_n price_d max_wheat_send max_wheat_receive
          max_sheep_send max_sheep_receive rounding ledger_version of
        Offer_Exchange_Model.Cxx_Ok
            (Offer_Exchange_Model.Exchange_Result_Transport
              (actual_wheat_receive, actual_sheep_send,
               actual_wheat_stays)) =>
          ["OK", format_decimal actual_wheat_receive,
           format_decimal actual_sheep_send,
           if actual_wheat_stays then "1" else "0"]
      | Offer_Exchange_Model.Cxx_Err error =>
          ["ERR", error_name error])
  in
    join_tabs suffix
  end

fun process_exchange_v10_without_price_error_thresholds     case_id price_n_text price_d_text max_wheat_send_text
    max_wheat_receive_text max_sheep_send_text max_sheep_receive_text
    rounding_text ledger_version_text =
  process_exchange_v10_like
    Offer_Exchange_Model.exchange_v10_without_price_error_thresholds_test
    case_id price_n_text price_d_text max_wheat_send_text
    max_wheat_receive_text max_sheep_send_text max_sheep_receive_text
    rounding_text ledger_version_text

fun process_exchange_v10 case_id price_n_text price_d_text
    max_wheat_send_text max_wheat_receive_text max_sheep_send_text
    max_sheep_receive_text rounding_text ledger_version_text =
  process_exchange_v10_like Offer_Exchange_Model.exchange_v10_test
    case_id price_n_text price_d_text max_wheat_send_text
    max_wheat_receive_text max_sheep_send_text max_sheep_receive_text
    rounding_text ledger_version_text

fun dispatch line =
  let
    val fields = String.fields (fn character => character = #"\t") line
  in
    case fields of
      ["v1", "offer_value", case_id, price_n, price_d,
       max_send, max_receive] =>
        process_offer_value case_id price_n price_d
          max_send max_receive
    | ["v1", "offer_amount_from_value", case_id, price_n, price_d,
       max_send, max_receive] =>
        process_offer_amount_from_value           case_id price_n price_d max_send max_receive
    | ["v1", "big_multiply", case_id, a, b] =>
        process_big_multiply case_id a b
    | ["v1", "price_error_bound", case_id, price_n, price_d,
       wheat_receive, sheep_send, can_favor_wheat] =>
        process_price_error_bound case_id price_n
          price_d wheat_receive sheep_send can_favor_wheat
    | ["v1", "big_divide", case_id, a, b, c, rounding] =>
        process_big_divide case_id a b c rounding
    | ["v1", "big_divide_128", case_id, a, b, rounding] =>
        process_big_divide128 case_id a b rounding
    | ["v1", "big_multiply_unsigned", case_id, a, b] =>
        process_big_multiply_unsigned case_id a b
    | ["v1", "big_divide_unsigned", case_id, a, b, c, rounding] =>
        process_big_divide_unsigned case_id a b c
          rounding
    | ["v1", "big_divide_nothrow", case_id, a, b, c, rounding] =>
        process_big_divide_nothrow case_id a b c
          rounding
    | ["v1", "big_divide_unsigned_128", case_id, a, b, rounding] =>
        process_big_divide_unsigned128 case_id a b
          rounding
    | ["v1", "big_divide_128_nothrow", case_id, a, b, rounding] =>
        process_big_divide128_nothrow case_id a b
          rounding
    | ["v1", "apply_price_error_thresholds", case_id, price_n, price_d,
       wheat_receive, sheep_send, wheat_stays, rounding] =>
        process_apply_price_error_thresholds case_id
          price_n price_d wheat_receive sheep_send wheat_stays rounding
    | ["v1", "exchange_v10_without_price_error_thresholds", case_id,
       price_n, price_d, max_wheat_send, max_wheat_receive, max_sheep_send,
       max_sheep_receive, rounding, ledger_version] =>
        process_exchange_v10_without_price_error_thresholds
          case_id price_n price_d max_wheat_send max_wheat_receive
          max_sheep_send max_sheep_receive rounding ledger_version
    | ["v1", "exchange_v10", case_id, price_n, price_d, max_wheat_send,
       max_wheat_receive, max_sheep_send, max_sheep_receive, rounding,
       ledger_version] =>
        process_exchange_v10 case_id price_n price_d
          max_wheat_send max_wheat_receive max_sheep_send max_sheep_receive
          rounding ledger_version
    | ["v1", "adjust_offer", case_id, price_n, price_d, max_wheat_send,
       max_sheep_receive, ledger_version] =>
        process_adjust_offer case_id price_n
          price_d max_wheat_send max_sheep_receive ledger_version
    | ["v1", "offer_selling_liabilities", case_id, price_n, price_d,
       ledger_version, amount] =>
        process_adjustment_liability
          Offer_Exchange_Model.offer_selling_liabilities_test
          case_id price_n price_d ledger_version amount
    | ["v1", "offer_buying_liabilities", case_id, price_n, price_d,
       ledger_version, amount] =>
        process_adjustment_liability
          Offer_Exchange_Model.offer_buying_liabilities_test
          case_id price_n price_d ledger_version amount
    | ["v1", "offer_lifecycle_sell", case_id, price_n, price_d, ledger_version,
       amount, maker_sell_balance, maker_sell_liabilities, maker_buy_limit,
       maker_buy_balance, maker_buy_liabilities, new_buy_limit] =>
        process_offer_lifecycle false case_id
          price_n price_d ledger_version amount maker_sell_balance
          maker_sell_liabilities maker_buy_limit maker_buy_balance
          maker_buy_liabilities new_buy_limit
    | ["v1", "offer_lifecycle_buy", case_id, price_n, price_d, ledger_version,
       amount, maker_sell_balance, maker_sell_liabilities, maker_buy_limit,
       maker_buy_balance, maker_buy_liabilities, new_buy_limit] =>
        process_offer_lifecycle true case_id
          price_n price_d ledger_version amount maker_sell_balance
          maker_sell_liabilities maker_buy_limit maker_buy_balance
          maker_buy_liabilities new_buy_limit
    | version :: _ =>
        if version <> "v1"
        then fail ("unknown record version: " ^ version)
        else fail "malformed or unsupported v1 record"
    | [] => fail "malformed record"
  end

end
