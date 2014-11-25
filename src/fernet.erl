-module(fernet).

%% fernet: fernet library's entry point.

-export([generate_key/0, encode_key/1, decode_key/1, generate_token/2]).
-define(VERSION, 128).
-define(BLOCKSIZE, 16).

% API

-spec generate_key() -> binary().
generate_key() ->
  crypto:strong_rand_bytes(32).

-spec encode_key(binary()) -> list().
encode_key(Key) ->
  binary_to_list(base64url:encode(Key)).

-spec decode_key(list()) -> binary().
decode_key(Key) ->
  base64url:decode(Key).

-spec encode_token(binary()) -> list().
encode_token(Token) ->
  binary_to_list(base64url:encode(Token)).

-spec generate_token(list(), binary()) -> list().
generate_token(Message, Key) ->
  generate_token(Message, generate_iv(), timestamp_to_seconds(now()), Key).

generate_token(Message, IV, Seconds, Key) ->
  Encoded_Seconds = seconds_to_binary(Seconds),
  Padded = pkcs7:pad(list_to_binary(Message)),
  Cyphertext = block_encrypt(extract_encryption_key(Key), IV, Padded),
  Hmac = generate_hmac(Seconds, IV, Cyphertext, extract_signing_key(Key)),
  << <<?VERSION>>/binary, Encoded_Seconds/binary, IV/binary, Cyphertext/binary, Hmac/binary >>.

%% Internals

block_encrypt(Key, IV, Padded) ->
  crypto:block_encrypt(aes_cbc128, Key, IV, Padded).

% Take an Erlang now() return and calculate the total number of seconds since
% the Epoch.
-spec timestamp_to_seconds({integer(), integer(), integer()}) -> integer().
timestamp_to_seconds({MegaSecs, Secs, MicroSecs}) ->
  round(((MegaSecs*1000000 + Secs)*1000000 + MicroSecs) / 1000000).

-spec generate_iv() -> binary().
generate_iv() ->
  crypto:strong_rand_bytes(16).

%% Returns the signing key from a 256byte Fernet Key
-spec extract_signing_key(binary()) -> binary().
extract_signing_key(Key) ->
  binary_part(Key, {0, 16}).

%% Returns the encryption key from a 256byte Fernet Key
-spec extract_encryption_key(binary()) -> binary().
extract_encryption_key(Key) ->
  binary_part(Key, {16, 16}).

generate_hmac(Seconds, IV, Cyphertext, Key) ->
  Encoded_Seconds = seconds_to_binary(Seconds),
  generate_hmac(Key, << <<?VERSION>>/binary, Encoded_Seconds/binary, IV/binary, Cyphertext/binary >>).

generate_hmac(Key, Bytes) ->
  base16(crypto:hmac(sha256, Key, Bytes)).

-spec seconds_to_binary(integer()) -> binary().
seconds_to_binary(Seconds) ->
  pad_to_8(binary:encode_unsigned(Seconds)).

-spec pad_to_8(binary()) -> binary().
pad_to_8(Binary) ->
   case (8 - size(Binary) rem 8) rem 8
     of 0 -> Binary
      ; N -> <<0:(N*8), Binary/binary>>
   end.

-spec base16(binary()) -> <<_:_*16>>.
base16(Data) ->
   << <<(hex(N div 16)), (hex(N rem 16))>> || <<N>> <= Data >>.

hex(N) when N < 10 ->
  N + $0;
hex(N) when N < 16 ->
  N - 10 + $a.

%% Tests
-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

generate_key_test() ->
  ?assertEqual(32, byte_size(generate_key())).

generate_iv_test() ->
  ?assertEqual(16, byte_size(generate_iv())).

% timestamp_to_seconds should return the number of seconds since the Unixtime
% Epoch represented by a tuple {MegaSecs, Secs, MicroSecs} as returned by now()
timestamp_to_seconds_test() ->
  ?assertEqual(1412525041, timestamp_to_seconds({1412,525041,377060})).

encode_key_test() ->
  Key = <<115, 15, 244, 199, 175, 61, 70, 146,
         62, 142, 212, 81, 238, 129, 60, 135, 247,
         144, 176, 162, 38, 188, 150, 169, 45,
         228, 155, 94, 156, 5, 225, 238>>,
  ?assertEqual("cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4", encode_key(Key)).

decode_key_test() ->
  Key = "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=",
  ?assertEqual(<<115, 15, 244, 199, 175, 61, 70, 146, 62, 142, 212, 81, 238,
                 129, 60, 135, 247, 144, 176, 162, 38, 188, 150, 169, 45, 228,
                 155, 94, 156, 5, 225, 238>>, decode_key(Key)).

extract_signing_key_test() ->
  Key = extract_signing_key(<<115, 15, 244, 199, 175, 61, 70, 146, 62, 142, 212, 81, 238, 129, 60, 135, 247, 144, 176, 162, 38, 188, 150, 169, 45, 228, 155, 94, 156, 5, 225, 238 >>),
  ?assertEqual(<<115, 15, 244, 199, 175, 61, 70, 146, 62, 142, 212, 81, 238, 129, 60, 135>>, Key).

% 1985-10-26T01:20:00-07:00 == 499162800 Seconds since the epoch
generate_token_test() ->
  Tok = generate_token("hello", <<0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15>>, 499162800, decode_key("cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=")),
  ?assertEqual("gAAAAAAdwJ6wAAECAwQFBgcICQoLDA0ODy021cpGVWKZ_eEwCGM4BLLF_5CV9dOPmrhuVUPgJobwOz7JcbmrR64jVmpU4IwqDA==", encode_token(Tok)).


generate_hmac_test() ->
  Hmac = generate_hmac(<<38, 183, 72, 8, 49, 250, 199, 115, 59, 118, 228, 30, 51, 199, 73, 16>>,
                       <<128, 0, 0, 0, 0, 84, 116, 204, 93, 212, 213, 44, 147,
                         52, 18, 109, 205, 200, 207, 169, 169, 218, 26, 197,
                         194, 0, 15, 209, 69, 43, 22, 9, 144, 199, 196, 190,
                         87, 188, 201, 189, 206, 179, 93, 252, 89, 228, 158,
                          172, 11, 57, 29, 13, 248, 192, 75, 124, 241>>),
  ?assertEqual(<< "07501fedf10da64f9f1e2c6012d2a780495ff031f88cf21471711a93423f57b0" >>, Hmac).

seconds_to_binary_test() ->
  ?assertEqual(<<0, 0, 0, 0, 29, 192, 158, 176>>, seconds_to_binary(499162800)).

pad_to_8_test() ->
  ?assertEqual(<<0, 0, 0, 0, 1, 2, 3, 4>>, pad_to_8(<<1, 2, 3, 4>>)),
  ?assertEqual(<<1, 2, 3, 4, 1, 2, 3, 4>>, pad_to_8(<<1, 2, 3, 4, 1, 2, 3, 4>>)).

block_encrypt_test() ->
  Key = <<247, 144, 176, 162, 38, 188, 150, 169, 45, 228, 155, 94, 156, 5, 225, 238>>,
  Message = <<104, 101, 108, 108, 111, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11>>,
  ?assertEqual(<<45, 54, 213, 202, 70, 85, 98, 153, 253, 225, 48, 8, 99, 56, 4, 178>>, block_encrypt(Key, <<0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15>>, Message)).

extract_encryption_key_test() ->
  Key = "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=",
  DecodedKey = decode_key(Key),
  ExpectedBytes = <<247, 144, 176, 162, 38, 188, 150, 169, 45, 228, 155, 94, 156, 5, 225, 238>>,
  ?assertEqual(ExpectedBytes, extract_encryption_key(DecodedKey)).

pad_string_test() ->
  ExpectedBytes = <<104, 101, 108, 108, 111, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0>>,
  ?assertEqual(ExpectedBytes, pkcs7:pad(list_to_binary("hello"))).

% requires gen_hmac_test

-endif.

%% End of Module.

%[
%  {
%    "token": "gAAAAAAdwJ6wAAECAwQFBgcICQoLDA0ODy021cpGVWKZ_eEwCGM4BLLF_5CV9dOPmrhuVUPgJobwOz7JcbmrR64jVmpU4IwqDA==",
%    "now": "1985-10-26T01:20:00-07:00",
%    "iv": [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
%    "src": "hello",
%    "secret": "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4="
%  }
%]
