-module(fernet).

%% fernet: fernet library's entry point.

-export([generate_key/0, encode_key/1, decode_key/1,
         generate_token/2, verify_and_decrypt_token/3]).
-define(VERSION, 128).
-define(BLOCKSIZE, 16).
-define(PAYOFFSET, 9 + ?BLOCKSIZE).

-type key() :: binary().
-type encoded_key() :: string().
-type encoded_token() :: string().
-export_type([encoded_key/0, encoded_token/0]).

%%%%%%%%%%%%%%%%%%
%%% Public API %%%
%%%%%%%%%%%%%%%%%%

-spec generate_key() -> key().
generate_key() ->
  crypto:strong_rand_bytes(32).

-spec encode_key(key()) -> encoded_key().
encode_key(Key) ->
  binary_to_list(base64url:encode(Key)).

-spec decode_key(encoded_key()) -> key().
decode_key(Key) ->
  base64url:decode(Key).

-spec generate_token(iolist(), key()) -> encoded_token().
generate_token(Message, Key) ->
  generate_token(Message, generate_iv(), timestamp_to_seconds(now()), Key).

-spec verify_and_decrypt_token(encoded_token(), key(), Ignored::term()) ->
    {ok, iodata()}.
verify_and_decrypt_token(Token, Key, TTL) ->
  verify_and_decrypt_token(Token, Key, TTL, timestamp_to_seconds(now())).

%%%%%%%%%%%%%%%
%%% Private %%%
%%%%%%%%%%%%%%%

generate_token(Message, IV, Seconds, Key) ->
  EncodedSeconds = seconds_to_binary(Seconds),
  Padded = pkcs7:pad(iolist_to_binary(Message)),
  <<SigningKey:16/binary, EncryptionKey:16/binary>> = Key,
  CypherText = block_encrypt(EncryptionKey, IV, Padded),
  Payload = <<?VERSION, EncodedSeconds/binary, IV/binary, CypherText/binary>>,
  Hmac = generate_hmac(SigningKey, Payload),
  encode_token(<<Payload/binary, Hmac/binary>>).

encode_token(Token) ->
  binary_to_list(base64url:encode(Token)).

decode_token(EncodedToken) ->
  base64url:decode(EncodedToken).

verify_and_decrypt_token(EncodedToken, Key, _TTL, _Now) ->
  %% TODO: Verify - see Ruby source for rules...
  DecodedToken = decode_token(EncodedToken),
  MsgSize = byte_size(DecodedToken)-32,
  <<_Vsn:1/binary, _EncodedSeconds:1/binary, IV:16/binary,
    Message:MsgSize/binary, _Hmac:32/binary>> = DecodedToken,
  {ok, block_decrypt(decode_key(Key), IV, Message)}.

block_encrypt(Key, IV, Padded) ->
  crypto:block_encrypt(aes_cbc128, Key, IV, Padded).

block_decrypt(Key, IV, Cypher) ->
  io:format("Cypher: ~p~n", [Cypher]),
  crypto:block_decrypt(aes_cbc128, Key, IV, Cypher).

% Take an Erlang now() return and calculate the total number of seconds since
% the Epoch.
-spec timestamp_to_seconds({integer(), integer(), integer()}) -> integer().
timestamp_to_seconds({MegaSecs, Secs, MicroSecs}) ->
  round(((MegaSecs*1000000 + Secs)*1000000 + MicroSecs) / 1000000).

-spec generate_iv() -> binary().
generate_iv() ->
  crypto:strong_rand_bytes(16).


generate_hmac(SigningKey, Bytes) ->
  base16(crypto:hmac(sha256, SigningKey, Bytes)).

-spec seconds_to_binary(integer()) -> binary().
seconds_to_binary(Seconds) ->
  pad_to_8(binary:encode_unsigned(Seconds)).

-spec pad_to_8(binary()) -> binary().
pad_to_8(Binary) ->
   case (8 - byte_size(Binary) rem 8) rem 8
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

%% pad_message(Message) ->
%%    Pkcs7 = pkcs7:pad(list_to_binary(Message)),
%%    <<Pkcs7/binary, 0:((32-(size(Pkcs7) rem 32))*8)>>.

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

%[
%  {
%    "token": "gAAAAAAdwJ6wAAECAwQFBgcICQoLDA0ODy021cpGVWKZ_eEwCGM4BLLF_5CV9dOPmrhuVUPgJobwOz7JcbmrR64jVmpU4IwqDA==",
%    "now": "1985-10-26T01:20:00-07:00",
%    "iv": [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
%    "src": "hello",
%    "secret": "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4="
%  }
%]
% 1985-10-26T01:20:00-07:00 == 499162800 Seconds since the epoch
%
generate_token_test() ->
  Tok = generate_token("hello", <<0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15>>, 499162800, decode_key("cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=")),
  ?assertEqual("gAAAAAAdwJ6wAAECAwQFBgcICQoLDA0ODy021cpGVWKZ_eEwCGM4BLLF_5CV9dOPmrhuVUPgJobwOz7JcbmrR64jVmpU4IwqDA==", Tok).

generate_hmac_test() ->
  SigningKey = <<115, 15, 244, 199, 175, 61, 70, 146, 62, 142, 212, 81, 238, 129, 60, 135>>,
  Payload = <<128, 0, 0, 0, 0, 29, 192, 158, 176, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 45, 54, 213, 202, 70, 85, 98, 153, 253, 225, 48, 8, 99, 56, 4, 178>>,
  ExpectedHmac = <<"c5ff9095f5d38f9ab86e5543e02686f03b3ec971b9ab47ae23566a54e08c2a0c">>,
  Hmac = generate_hmac(SigningKey, Payload),
  ?assertEqual(ExpectedHmac, Hmac).

generate_hmac4_test() ->
  Encoded_Seconds = <<0, 0, 0, 0, 29, 192, 158, 176>>,
  IV = <<0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15>>,
  CypherText = <<45, 54, 213, 202, 70, 85, 98, 153, 253, 225, 48, 8, 99, 56, 4, 178>>,
  SigningKey = <<115, 15, 244, 199, 175, 61, 70, 146, 62, 142, 212, 81, 238, 129, 60, 135>>,
  Hmac = generate_hmac(Encoded_Seconds, IV, CypherText, SigningKey),
  ?assertEqual(<<"c5ff9095f5d38f9ab86e5543e02686f03b3ec971b9ab47ae23566a54e08c2a0c">>, Hmac).

seconds_to_binary_test() ->
  ?assertEqual(<<0, 0, 0, 0, 29, 192, 158, 176>>, seconds_to_binary(499162800)).

pad_to_8_test() ->
  ?assertEqual(<<0, 0, 0, 0, 1, 2, 3, 4>>, pad_to_8(<<1, 2, 3, 4>>)),
  ?assertEqual(<<1, 2, 3, 4, 1, 2, 3, 4>>, pad_to_8(<<1, 2, 3, 4, 1, 2, 3, 4>>)).

block_encrypt_test() ->
  Key = <<247, 144, 176, 162, 38, 188, 150, 169, 45, 228, 155, 94, 156, 5, 225, 238>>,
  Message = <<104, 101, 108, 108, 111, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11>>,
  IV = <<0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15>>,
  ?assertEqual(<<45, 54, 213, 202, 70, 85, 98, 153, 253, 225, 48, 8, 99, 56, 4, 178>>, block_encrypt(Key, IV, Message)).

extract_encryption_key_test() ->
  Key = "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=",
  DecodedKey = decode_key(Key),
  ExpectedBytes = <<247, 144, 176, 162, 38, 188, 150, 169, 45, 228, 155, 94, 156, 5, 225, 238>>,
  ?assertEqual(ExpectedBytes, extract_encryption_key(DecodedKey)).

%% pad_message_test() ->
%%   ExpectedBytes = <<104, 101, 108, 108, 111, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0>>,
%%   ?assertEqual(ExpectedBytes, pad_message("hello")).

%% [
%%   {
%%     "token": "gAAAAAAdwJ6wAAECAwQFBgcICQoLDA0ODy021cpGVWKZ_eEwCGM4BLLF_5CV9dOPmrhuVUPgJobwOz7JcbmrR64jVmpU4IwqDA==",
%%     "now": "1985-10-26T01:20:01-07:00",
%%     "ttl_sec": 60,
%%     "src": "hello",
%%     "secret": "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4="
%%   }
%% ]

%% verify_and_decrypt_token_test() ->
%%     Token = "gAAAAAAdwJ6wAAECAwQFBgcICQoLDA0ODy021cpGVWKZ_eEwCGM4BLLF_5CV9dOPmrhuVUPgJobwOz7JcbmrR64jVmpU4IwqDA==",
%%     TTL = 60,
%%     Secret = "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=",
%%     Now = 499162800,
%%     {ok, Message} = verify_and_decrypt_token(Token, Secret, TTL, Now),
%%     ?assertEqual("hello", Message).

extract_iv_from_token(Token) ->
  binary_part(Token, {9, 16}).

extract_message_from_token(Token) ->
  %% TODO: Why 33? taken from the Ruby implementation
  binary_part(Token, {?PAYOFFSET,  byte_size(Token) - 32}).

extract_signing_key(Key) ->
  binary_part(Key, {0, 16}).

extract_encryption_key(Key) ->
  binary_part(Key, {16, 16}).

generate_hmac(Encoded_Seconds, IV, Cyphertext, SigningKey) ->
  generate_hmac(SigningKey, << <<?VERSION>>/binary, Encoded_Seconds/binary, IV/binary, Cyphertext/binary >>).
-endif.

%% End of Module.
