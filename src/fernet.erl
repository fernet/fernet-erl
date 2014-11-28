%%%-------------------------------------------------------------------
%%% @author Kevin McDermott <kevin@heroku.com>
%%% @copyright (C) 2014, Heroku
%%% @doc
%%%
%%% Implements fernet token generation and verification.
%%%
%%% See https://github.com/fernet/spec
%%%
%%% @end
%%% Created : 28 Nov 2014 by Kevin McDermott <kevin@heroku.com>
%%%-------------------------------------------------------------------
-module(fernet).

-export([generate_key/0, encode_key/1, decode_key/1,
         generate_token/2, verify_and_decrypt_token/3]).
-define(VERSION, 128).
-define(BLOCKSIZE, 16).
-define(HMACSIZE, 32).
-define(IVSIZE, 16).
-define(TSSIZE, 8).
-define(MAX_SKEW, 60).
-define(PAYOFFSET, 9 + ?BLOCKSIZE).

-type key() :: binary().
-type encoded_key() :: string().
-type encoded_token() :: string().
-export_type([encoded_key/0, encoded_token/0]).

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Generate a pseudorandom 32byte key.
%%
%% @end
%%--------------------------------------------------------------------
-spec generate_key() -> key().
generate_key() ->
  crypto:strong_rand_bytes(32).

%%--------------------------------------------------------------------
%% @doc
%% Encode a key using base64url encoding format.
%%
%% @end
%%--------------------------------------------------------------------
-spec encode_key(key()) -> encoded_key().
encode_key(Key) ->
  binary_to_list(base64url:encode(Key)).

%%--------------------------------------------------------------------
%% @doc
%% Decode a base64url encoded key.
%%
%% @end
%%--------------------------------------------------------------------
-spec decode_key(encoded_key()) -> key().
decode_key(Key) ->
  base64url:decode(Key).

%%--------------------------------------------------------------------
%% @doc
%% Generate a token for the provided Message using the supplied Key.
%%
%% @end
%%--------------------------------------------------------------------
-spec generate_token(iolist(), key()) -> encoded_token().
generate_token(Message, Key) ->
  generate_token(Message, generate_iv(), timestamp_to_seconds(now()), Key).


%%--------------------------------------------------------------------
%% @doc
%% Verify a token and extract the message 
%%
%% @end
%%--------------------------------------------------------------------
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
  Payload = payload(EncodedSeconds, IV, CypherText),
  Hmac = hmac(SigningKey, Payload),
  encode_token(<<Payload/binary, Hmac/binary>>).

payload(EncodedSeconds, IV, CypherText) ->
    <<?VERSION,  EncodedSeconds/binary, IV/binary, CypherText/binary>>.

hmac(Key, Payload) ->
    crypto:hmac(sha256, Key, Payload).

encode_token(Token) ->
  binary_to_list(base64url:encode(Token)).

decode_token(EncodedToken) ->
  base64url:decode(EncodedToken).

validate(Vsn, Now, TS, TTL, _Hmac, _TermsUsedInHMAC, F) -> 
  try validate_vsn(Vsn), validate_ttl(Now, TS, TTL) of
    ok ->
      F()
  catch
    throw:Reason ->
      {error, Reason}
  end.

validate_vsn(<<128>>) -> ok;
validate_vsn(_) -> throw(bad_version).

validate_ttl(Now, TS, TTL) ->
   Diff = timer:now_diff(seconds_to_timestamp(Now), seconds_to_timestamp(TS)),
   AbsDiff = abs(Diff),
   if Diff < 0, AbsDiff < ?MAX_SKEW -> ok; % in the past but within skew
     Diff < 0 -> throw(too_new); % in the past, with way too large of a  skew
     Diff >= 0, Diff < TTL -> ok; % absolutely okay
     Diff > 0, Diff > TTL, Diff-TTL < ?MAX_SKEW -> ok; % past the TTL, but within skew
     Diff > 0, Diff > TTL -> throw(too_old)
   end.

verify_and_decrypt_token(EncodedToken, Key, TTL, Now) ->
  %% TODO: Verify - see Ruby source for rules...
  DecodedToken = decode_token(EncodedToken),
  MsgSize = byte_size(DecodedToken)-(1 + ?TSSIZE + ?IVSIZE + ?HMACSIZE),
  <<Vsn:1/binary, TS:8/binary, IV:16/binary, CypherText:MsgSize/binary,
    _Hmac:32/binary>> = DecodedToken,
  validate(Vsn, Now, binary_to_seconds(TS), TTL, _Hmac, ok, fun () ->
    <<_SigningKey:16/binary, EncryptionKey:16/binary>> = decode_key(Key),
    {ok, pkcs7:unpad(block_decrypt(EncryptionKey, IV, CypherText))}
    end).

block_encrypt(Key, IV, Padded) ->
  crypto:block_encrypt(aes_cbc128, Key, IV, Padded).

block_decrypt(Key, IV, Cypher) ->
  crypto:block_decrypt(aes_cbc128, Key, IV, Cypher).

% Take an Erlang now() return and calculate the total number of seconds since
% the Epoch.
-spec timestamp_to_seconds(erlang:timestamp()) -> integer().
timestamp_to_seconds({MegaSecs, Secs, MicroSecs}) ->
  round(((MegaSecs*1000000 + Secs)*1000000 + MicroSecs) / 1000000).

% Take a number of seconds since the Epoch and return an Erlang timestamp().
% -spec seconds_to_timestamp(integer()) -> {integer(), integer(), integer()}.
-spec seconds_to_timestamp(integer()) -> erlang:timestamp().
seconds_to_timestamp(Seconds) ->
  {Seconds div 1000000, Seconds rem 1000000, 0}.

-spec generate_iv() -> binary().
generate_iv() ->
  crypto:strong_rand_bytes(16).

-spec seconds_to_binary(integer()) -> binary().
seconds_to_binary(Seconds) ->
  <<Seconds:64/big-unsigned>>.

-spec binary_to_seconds(binary()) -> integer().
binary_to_seconds(<<Bin:64>>) ->
  Bin.

%% Tests
-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

% generate_key should generate a 32-byte binary
generate_key_test() ->
  ?assertEqual(32, byte_size(generate_key())).

% generate_key should generate a 16-byte binary
generate_iv_test() ->
  ?assertEqual(16, byte_size(generate_iv())).

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
  ?assertEqual(decode_token("gAAAAAAdwJ6wAAECAwQFBgcICQoLDA0ODy021cpGVWKZ_eEwCGM4BLLF_5CV9dOPmrhuVUPgJobwOz7JcbmrR64jVmpU4IwqDA=="),
               decode_token(Tok)).

generate_hmac_test() ->
  SigningKey = <<115, 15, 244, 199, 175, 61, 70, 146, 62, 142, 212, 81, 238, 129, 60, 135>>,
  Payload = <<128, 0, 0, 0, 0, 29, 192, 158, 176, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 45, 54, 213, 202, 70, 85, 98, 153, 253, 225, 48, 8, 99, 56, 4, 178>>,
  ExpectedHmac = <<"c5ff9095f5d38f9ab86e5543e02686f03b3ec971b9ab47ae23566a54e08c2a0c">>,
  Hmac = base16(hmac(SigningKey, Payload)),
  ?assertEqual(ExpectedHmac, Hmac).

generate_hmac4_test() ->
  Encoded_Seconds = <<0, 0, 0, 0, 29, 192, 158, 176>>,
  IV = <<0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15>>,
  CypherText = <<45, 54, 213, 202, 70, 85, 98, 153, 253, 225, 48, 8, 99, 56, 4, 178>>,
  SigningKey = <<115, 15, 244, 199, 175, 61, 70, 146, 62, 142, 212, 81, 238, 129, 60, 135>>,
  Hmac = base16(hmac(SigningKey, payload(Encoded_Seconds, IV, CypherText))),
  ?assertEqual(<<"c5ff9095f5d38f9ab86e5543e02686f03b3ec971b9ab47ae23566a54e08c2a0c">>, Hmac).

%% Convert seconds since the Unixtime Epoch to a 64-bit unsigned big-endian integer.
seconds_to_binary_test() ->
  ?assertEqual(<<0, 0, 0, 0, 29, 192, 158, 176>>, seconds_to_binary(499162800)).

%% Convert a 64-bit unsigned big-endian integer to seconds since the Unixtime
%% Epoch.
binary_to_seconds_test() ->
  ?assertEqual(499162800, binary_to_seconds(<<0, 0, 0, 0, 29, 192, 158, 176>>)).

% timestamp_to_seconds should return the number of seconds since the Unixtime
% Epoch represented by a tuple {MegaSecs, Secs, MicroSecs} as returned by now()
timestamp_to_seconds_test() ->
  ?assertEqual(1412525041, timestamp_to_seconds({1412,525041,377060})).

% seconds_to_timestamp should return a tuple of {MegaSecs, Secs, MicroSecs} from
% a number of seconds since the Unixtime epoch, droppping the MicroSecs.
seconds_to_timestamp_test() ->
  ?assertEqual({1412,525041,0}, seconds_to_timestamp(1412525041)).

block_encrypt_test() ->
  Key = <<247, 144, 176, 162, 38, 188, 150, 169, 45, 228, 155, 94, 156, 5, 225, 238>>,
  Message = <<104, 101, 108, 108, 111, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11>>,
  IV = <<0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15>>,
  ?assertEqual(<<45, 54, 213, 202, 70, 85, 98, 153, 253, 225, 48, 8, 99, 56, 4, 178>>, block_encrypt(Key, IV, Message)).

-spec base16(binary()) -> <<_:_*16>>.
base16(Data) ->
   << <<(hex(N div 16)), (hex(N rem 16))>> || <<N>> <= Data >>.

hex(N) when N < 10 ->
  N + $0;
hex(N) when N < 16 ->
  N - 10 + $a.

%% [
%%   {
%%     "token": "gAAAAAAdwJ6wAAECAwQFBgcICQoLDA0ODy021cpGVWKZ_eEwCGM4BLLF_5CV9dOPmrhuVUPgJobwOz7JcbmrR64jVmpU4IwqDA==",
%%     "now": "1985-10-26T01:20:01-07:00",
%%     "ttl_sec": 60,
%%     "src": "hello",
%%     "secret": "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4="
%%   }
%% ]

verify_and_decrypt_token_test() ->
    Token = "gAAAAAAdwJ6wAAECAwQFBgcICQoLDA0ODy021cpGVWKZ_eEwCGM4BLLF_5CV9dOPmrhuVUPgJobwOz7JcbmrR64jVmpU4IwqDA==",
    TTL = 60,
    Secret = "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=",
    Now = 499162800,
    {ok, Message} = verify_and_decrypt_token(Token, Secret, TTL, Now),
    ?assertEqual("hello", binary_to_list(Message)).

verify_and_decrypt_token_expired_ttl_test() ->
    Token = "gAAAAAAdwJ6wAAECAwQFBgcICQoLDA0ODy021cpGVWKZ_eEwCGM4BLLF_5CV9dOPmrhuVUPgJobwOz7JcbmrR64jVmpU4IwqDA==",
    TTL = 60,
    Secret = "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=",
    Now = 499162800 + 70,
    {error, too_old} = verify_and_decrypt_token(Token, Secret, TTL, Now).

verify_and_decrypt_token_too_new_ttl_test() ->
    Token = "gAAAAAAdwJ6wAAECAwQFBgcICQoLDA0ODy021cpGVWKZ_eEwCGM4BLLF_5CV9dOPmrhuVUPgJobwOz7JcbmrR64jVmpU4IwqDA==",
    TTL = 60,
    Secret = "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=",
    Now = 499162800 - 70,
    {error, too_new} = verify_and_decrypt_token(Token, Secret, TTL, Now).

verify_and_decrypt_token_invalid_version_test() ->
    Token = "gQAAAAAdwJ6wAAECAwQFBgcICQoLDA0ODy021cpGVWKZ_eEwCGM4BLKY7covSkDHw9ma-418Z5yfJ0bAi-R_TUVpW6VSXlO8JA==", 
    TTL = 60,
    Secret = "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=",
    Now = 499162800,
    {error, bad_version} = verify_and_decrypt_token(Token, Secret, TTL, Now).
-endif.

%% End of Module.
