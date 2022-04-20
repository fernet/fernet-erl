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

-export([generate_key/0, generate_encoded_key/0, encode_key/1, encode_key/2, decode_key/1,
         generate_token/2, verify_and_decrypt_token/3]).

-ifdef(TEST).

-export([verify_and_decrypt_token/4, generate_token/4]).

-endif.

-define(VERSION, 128).
-define(BLOCKSIZE, 16).
-define(HMACSIZE, 32).
-define(IVSIZE, 16).
-define(TSSIZE, 8).
-define(MAX_SKEW, 60).

-type key() :: <<_:256>>.
-type signing_key() :: <<_:128>>.
-type encryption_key() :: <<_:128>>.
-type encoded_key() :: binary().
-type encoded_token() :: binary().

-export_type([key/0, signing_key/0, encryption_key/0, encoded_key/0, encoded_token/0]).

%%%===================================================================
%%% API
%%%===================================================================
%% @doc Generate a pseudorandom 32 bytes key.
-spec generate_key() -> key().
generate_key() ->
    crypto:strong_rand_bytes(32).

%% @doc Generate a pseudorandom 32 bytes key, and encode it with the
%% proper base64url format for interoperability.
-spec generate_encoded_key() -> encoded_key().
generate_encoded_key() ->
    base64url:encode_mime(
        crypto:strong_rand_bytes(32)).

%% @doc Encode a key using base64url encoding format for interoperability
-spec encode_key(key()) -> encoded_key().
encode_key(<<Key:32/binary>>) ->
    base64url:encode_mime(Key).

%% @doc Encode a signing key and an encryption key using base64url
%% encoding format for interoperability
-spec encode_key(signing_key(), encryption_key()) -> encoded_key().
encode_key(<<SigningKey:16/binary>>, <<EncryptionKey:16/binary>>) ->
    Key = <<SigningKey/binary, EncryptionKey/binary>>,
    base64url:encode_mime(Key).

%% @doc Decode a base64url encoded key.
-spec decode_key(encoded_key()) -> key().
decode_key(Key) ->
    base64url:decode(Key).

%% @doc Generate a token for the provided Message using the supplied Key.
-spec generate_token(iodata(), key()) -> encoded_token().
generate_token(Message, Key) ->
    generate_token(Message, generate_iv(), erlang_system_seconds(), Key).

%% @doc Verify a token and extract the message
-spec verify_and_decrypt_token(encoded_token(), key(), TTL :: integer() | infinity) ->
                                  {ok, binary()} | {error, atom()}.
verify_and_decrypt_token(Token, Key, infinity) ->
    verify_and_decrypt_token(Token, Key, infinity, undefined);
verify_and_decrypt_token(Token, Key, TTL) ->
    verify_and_decrypt_token(Token, Key, TTL, erlang_system_seconds()).

%%%===================================================================
%%% Private
%%%===================================================================
generate_token(Message, IV, Seconds, Key) ->
    EncodedSeconds = seconds_to_binary(Seconds),
    Padded = pkcs7:pad(iolist_to_binary(Message)),
    <<SigningKey:16/binary, EncryptionKey:16/binary>> = base64url:decode(Key),
    CypherText = block_encrypt(EncryptionKey, IV, Padded),
    Payload = payload(EncodedSeconds, IV, CypherText),
    Hmac = hmac(SigningKey, Payload),
    encode_token(<<Payload/binary, Hmac/binary>>).

verify_and_decrypt_token(EncodedToken, Key, TTL, Now) ->
    try DecodedToken = decode_token(EncodedToken),
        MsgSize = byte_size(DecodedToken) - (1 + ?TSSIZE + ?IVSIZE + ?HMACSIZE),
        validate_msg_size(MsgSize),
        <<Vsn:1/binary, TS:8/binary, IV:16/binary, CypherText:MsgSize/binary, Hmac:32/binary>> =
            DecodedToken,
        <<SigningKey:16/binary, EncryptionKey:16/binary>> = decode_key(Key),
        validate_vsn(Vsn),
        validate_ttl(Now, binary_to_seconds(TS), TTL),
        validate_hmac(Hmac, SigningKey, {TS, IV, CypherText}),
        block_decrypt(EncryptionKey, IV, CypherText)
    of
        Decrypted ->
            unpad(Decrypted)
    catch
        invalid_base64 = Err ->
            {error, Err};
        too_short = Err ->
            {error, Err};
        payload_size_not_multiple_of_block_size = Err ->
            {error, Err};
        bad_version = Err ->
            {error, Err};
        too_old = Err ->
            {error, Err};
        too_new = Err ->
            {error, Err};
        incorrect_mac = Err ->
            {error, Err}
    end.

unpad(Decrypted) ->
    try
        {ok, pkcs7:unpad(Decrypted)}
    catch
        error:_ ->
            {error, payload_padding}
    end.

encode_token(Token) ->
    base64url:encode_mime(Token).

decode_token(EncodedToken) ->
    try
        base64url:decode(EncodedToken)
    catch
        error:badarg ->
            throw(invalid_base64)
    end.

%%-------------------------------------------------------------------
%% Validation Helpers
%%-------------------------------------------------------------------
validate_msg_size(MsgSize) when MsgSize < 0 ->
    throw(too_short);
validate_msg_size(MsgSize) when MsgSize rem ?BLOCKSIZE =/= 0 ->
    throw(payload_size_not_multiple_of_block_size);
validate_msg_size(_) ->
    ok.

validate_vsn(<<128>>) ->
    ok;
validate_vsn(_) ->
    throw(bad_version).

validate_ttl(_, _, infinity) ->
    ok;
validate_ttl(Now, TS, TTL) ->
    case Now - TS of
        Diff when Diff < 0, abs(Diff) < ?MAX_SKEW ->
            ok; % in the past but within skew
        Diff when Diff < 0 ->
            throw(too_new); % in the past, with way too large of a  skew
        Diff when Diff >= 0, Diff < TTL ->
            ok; % absolutely okay
        Diff when Diff > 0, Diff > TTL ->
            throw(too_old) % according to spec, skew doesn't apply here
    end.

validate_hmac(Hmac, SigningKey, {TS, IV, CypherText}) ->
    ReHmac = hmac(SigningKey, payload(TS, IV, CypherText)),
    case verify_in_constant_time(Hmac, ReHmac) of
        true ->
            ok;
        false ->
            throw(incorrect_mac)
    end.

%%-------------------------------------------------------------------
%% Crypto Helpers
%%-------------------------------------------------------------------
payload(EncodedSeconds, IV, CypherText) ->
    <<?VERSION, EncodedSeconds/binary, IV/binary, CypherText/binary>>.

hmac(Key, Payload) ->
    crypto:mac(hmac, sha256, Key, Payload).

%% @doc Verifies two hashes for matching purpose, in constant time. That allows
%% a safer verification as no attacker can use the time it takes to compare hash
%% values to find an attack vector (past figuring out the complexity)
verify_in_constant_time(X, Y) ->
    case byte_size(X) == byte_size(Y) of
        true ->
            verify_in_constant_time(X, Y, 0);
        false ->
            false
    end.

verify_in_constant_time(<<X, RestX/binary>>, <<Y, RestY/binary>>, Result) ->
    verify_in_constant_time(RestX, RestY, X bxor Y bor Result);
verify_in_constant_time(<<>>, <<>>, Result) ->
    Result == 0.

block_encrypt(Key, IV, Padded) ->
    crypto:crypto_one_time(aes_128_cbc, Key, IV, Padded, true).

block_decrypt(Key, IV, Cypher) ->
    crypto:crypto_one_time(aes_128_cbc, Key, IV, Cypher, false).

-spec generate_iv() -> <<_:128>>.
generate_iv() ->
    crypto:strong_rand_bytes(16).

%%-------------------------------------------------------------------
%% Time Helpers
%%-------------------------------------------------------------------
-spec seconds_to_binary(integer()) -> binary().
seconds_to_binary(Seconds) ->
    <<Seconds:64/big-unsigned>>.

-spec binary_to_seconds(binary()) -> integer().
binary_to_seconds(<<Bin:64>>) ->
    Bin.

-spec erlang_system_seconds() -> integer().
erlang_system_seconds() ->
    try
        erlang:system_time(seconds)
    catch
        error:undef -> % Pre 18.0
            timestamp_to_seconds(os:timestamp())
    end.

-spec timestamp_to_seconds(erlang:timestamp()) -> integer().
timestamp_to_seconds({MegaSecs, Secs, MicroSecs}) ->
    round(((MegaSecs * 1000000 + Secs) * 1000000 + MicroSecs) / 1000000).

%%%===================================================================
%%% Tests
%%%===================================================================
-ifdef(TEST).

-include_lib("eunit/include/eunit.hrl").

% timestamp_to_seconds should return the number of seconds since the Unixtime
% Epoch represented by a tuple {MegaSecs, Secs, MicroSecs} as returned by now()
timestamp_to_seconds_test() ->
    ?assertEqual(1412525041, timestamp_to_seconds({1412, 525041, 377060})).

% generate_key should generate a 32-byte binary
generate_key_test() ->
    ?assertEqual(32, byte_size(generate_key())).

% generate_key should generate a 32-byte binary
generate_encoded_key_test() ->
    ?assertEqual(32, byte_size(decode_key(generate_encoded_key()))).

% generate_iv should generate a 16-byte binary
generate_iv_test() ->
    ?assertEqual(16, byte_size(generate_iv())).

encode_key_test() ->
    Key = test_key(),
    ?assertEqual(<<"cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=">>, encode_key(Key)).

decode_key_test() ->
    Key = "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=",
    ?assertEqual(test_key(), decode_key(Key)).

test_key() ->
    <<115, 15, 244, 199, 175, 61, 70, 146, 62, 142, 212, 81, 238, 129, 60, 135, 247, 144, 176,
      162, 38, 188, 150, 169, 45, 228, 155, 94, 156, 5, 225, 238>>.

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
generate_token_test_() ->
    Tok = generate_token("hello",
                         <<0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15>>,
                         499162800,
                         "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4="),
    [?_assertEqual(<<"gAAAAAAdwJ6wAAECAwQFBgcICQoLDA0ODy021cpGVWKZ_eEwCGM4BLLF_5CV9dOPmrhuVUPgJobwOz7JcbmrR64jVmpU4IwqDA==">>,
                   Tok),
     ?_assertEqual(decode_token("gAAAAAAdwJ6wAAECAwQFBgcICQoLDA0ODy021cpGVWKZ_eEwCGM4BLLF_5CV9dOPmrhuVUPgJobwOz7JcbmrR64jVmpU4IwqDA=="),
                   decode_token(Tok))].

generate_hmac_test() ->
    SigningKey = <<115, 15, 244, 199, 175, 61, 70, 146, 62, 142, 212, 81, 238, 129, 60, 135>>,
    Payload =
        <<128, 0, 0, 0, 0, 29, 192, 158, 176, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
          15, 45, 54, 213, 202, 70, 85, 98, 153, 253, 225, 48, 8, 99, 56, 4, 178>>,
    ExpectedHmac = <<"c5ff9095f5d38f9ab86e5543e02686f03b3ec971b9ab47ae23566a54e08c2a0c">>,
    Hmac = base16(hmac(SigningKey, Payload)),
    ?assertEqual(ExpectedHmac, Hmac).

generate_hmac4_test() ->
    EncodedSeconds = <<0, 0, 0, 0, 29, 192, 158, 176>>,
    IV = <<0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15>>,
    CypherText = <<45, 54, 213, 202, 70, 85, 98, 153, 253, 225, 48, 8, 99, 56, 4, 178>>,
    SigningKey = <<115, 15, 244, 199, 175, 61, 70, 146, 62, 142, 212, 81, 238, 129, 60, 135>>,
    Hmac = base16(hmac(SigningKey, payload(EncodedSeconds, IV, CypherText))),
    ?assertEqual(<<"c5ff9095f5d38f9ab86e5543e02686f03b3ec971b9ab47ae23566a54e08c2a0c">>,
                 Hmac).

%% Convert seconds since the Unixtime Epoch to a 64-bit unsigned big-endian integer.
seconds_to_binary_test() ->
    ?assertEqual(<<0, 0, 0, 0, 29, 192, 158, 176>>, seconds_to_binary(499162800)).

%% Convert a 64-bit unsigned big-endian integer to seconds since the Unixtime
%% Epoch.
binary_to_seconds_test() ->
    ?assertEqual(499162800, binary_to_seconds(<<0, 0, 0, 0, 29, 192, 158, 176>>)).

block_encrypt_test() ->
    Key = <<247, 144, 176, 162, 38, 188, 150, 169, 45, 228, 155, 94, 156, 5, 225, 238>>,
    Message = <<104, 101, 108, 108, 111, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11>>,
    IV = <<0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15>>,
    ?assertEqual(<<45, 54, 213, 202, 70, 85, 98, 153, 253, 225, 48, 8, 99, 56, 4, 178>>,
                 block_encrypt(Key, IV, Message)).

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
    Token =
        "gAAAAAAdwJ6wAAECAwQFBgcICQoLDA0ODy021cpGVWKZ_eEwCGM4BLLF_5CV9dOPmrhuVUPgJobwOz7JcbmrR64jVmpU4IwqDA==",
    TTL = 60,
    Secret = "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=",
    Now = 499162800,
    {ok, Message} = verify_and_decrypt_token(Token, Secret, TTL, Now),
    ?assertEqual(<<"hello">>, Message).

verify_and_decrypt_token_expired_ttl_test() ->
    Token =
        "gAAAAAAdwJ6wAAECAwQFBgcICQoLDA0ODy021cpGVWKZ_eEwCGM4BLLF_5CV9dOPmrhuVUPgJobwOz7JcbmrR64jVmpU4IwqDA==",
    TTL = 60,
    Secret = "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=",
    Now = 499162800 + 121,
    {error, too_old} = verify_and_decrypt_token(Token, Secret, TTL, Now).

verify_and_decrypt_token_too_new_ttl_test() ->
    Token =
        "gAAAAAAdwJ6wAAECAwQFBgcICQoLDA0ODy021cpGVWKZ_eEwCGM4BLLF_5CV9dOPmrhuVUPgJobwOz7JcbmrR64jVmpU4IwqDA==",
    TTL = 60,
    Secret = "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=",
    Now = 499162800 - 70,
    {error, too_new} = verify_and_decrypt_token(Token, Secret, TTL, Now).

verify_and_decrypt_token_ignore_ttl_test() ->
    Token =
        "gAAAAAAdwJ6wAAECAwQFBgcICQoLDA0ODy021cpGVWKZ_eEwCGM4BLLF_5CV9dOPmrhuVUPgJobwOz7JcbmrR64jVmpU4IwqDA==",
    TTL = infinity,
    Secret = "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=",
    Now = 499162800 - 70,
    {ok, <<"hello">>} = verify_and_decrypt_token(Token, Secret, TTL, Now).

verify_and_decrypt_token_invalid_version_test() ->
    Token =
        "gQAAAAAdwJ6wAAECAwQFBgcICQoLDA0ODy021cpGVWKZ_eEwCGM4BLKY7covSkDHw9ma-418Z5yfJ0bAi-R_TUVpW6VSXlO8JA==",
    TTL = 60,
    Secret = "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=",
    Now = 499162800,
    {error, bad_version} = verify_and_decrypt_token(Token, Secret, TTL, Now).

%% From https://github.com/fernet/spec/blob/master/invalid.json

invalid_incorrect_mac_test() ->
    Token =
        "gAAAAAAdwJ6xAAECAwQFBgcICQoLDA0OD3HkMATM5lFqGaerZ-fWPAl1-szkFVzXTuGb4hR8AKtwcaX1YdykQUFBQUFBQUFBQQ==",
    Now = 499162800,
    TTL = 60,
    Secret = "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=",
    ?assertEqual({error, incorrect_mac}, verify_and_decrypt_token(Token, Secret, TTL, Now)).

invalid_too_short_test() ->
    Token = "gAAAAAAdwJ6xAAECAwQFBgcICQoLDA0OD3HkMATM5lFqGaerZ-fWPA==",
    Now = 499162800,
    TTL = 60,
    Secret = "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=",
    ?assertEqual({error, too_short}, verify_and_decrypt_token(Token, Secret, TTL, Now)).

invalid_invalid_base64_test() ->
    Token =
        "%%%%%%%%%%%%%AECAwQFBgcICQoLDA0OD3HkMATM5lFqGaerZ-fWPAl1-szkFVzXTuGb4hR8AKtwcaX1YdykRtfsH-p1YsUD2Q==",
    Now = 499162800,
    TTL = 60,
    Secret = "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=",
    ?assertEqual({error, invalid_base64}, verify_and_decrypt_token(Token, Secret, TTL, Now)).

invalid_payload_size_to_block_size_test() ->
    Token =
        "gAAAAAAdwJ6xAAECAwQFBgcICQoLDA0OD3HkMATM5lFqGaerZ-fWPOm73QeoCk9uGib28Xe5vz6oxq5nmxbx_v7mrfyudzUm",
    Now = 499162800,
    TTL = 60,
    Secret = "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=",
    ?assertEqual({error, payload_size_not_multiple_of_block_size},
                 verify_and_decrypt_token(Token, Secret, TTL, Now)).

invalid_payload_padding_test() ->
    Token =
        "gAAAAAAdwJ6xAAECAwQFBgcICQoLDA0ODz4LEpdELGQAad7aNEHbf-JkLPIpuiYRLQ3RtXatOYREu2FWke6CnJNYIbkuKNqOhw==",
    Now = 499162800,
    TTL = 60,
    Secret = "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=",
    ?assertEqual({error, payload_padding}, verify_and_decrypt_token(Token, Secret, TTL, Now)).

invalid_far_future_skew_test() ->
    Token =
        "gAAAAAAdwStRAAECAwQFBgcICQoLDA0OD3HkMATM5lFqGaerZ-fWPAnja1xKYyhd-Y6mSkTOyTGJmw2Xc2a6kBd-iX9b_qXQcw==",
    Now = 499162800,
    TTL = 60,
    Secret = "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=",
    ?assertEqual({error, too_new}, verify_and_decrypt_token(Token, Secret, TTL, Now)).

invalid_expired_ttl_test() ->
    Token =
        "gAAAAAAdwJ6xAAECAwQFBgcICQoLDA0OD3HkMATM5lFqGaerZ-fWPAl1-szkFVzXTuGb4hR8AKtwcaX1YdykRtfsH-p1YsUD2Q==",
    Now = 499162800 + 90,
    TTL = 60,
    Secret = "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=",
    ?assertEqual({error, too_old}, verify_and_decrypt_token(Token, Secret, TTL, Now)).

invalid_incorrect_iv_test() ->
    %% An invalid IV causes a padding error!
    Token =
        "gAAAAAAdwJ6xBQECAwQFBgcICQoLDA0OD3HkMATM5lFqGaerZ-fWPAkLhFLHpGtDBRLRTZeUfWgHSv49TF2AUEZ1TIvcZjK1zQ=",
    Now = 499162800,
    TTL = 60,
    Secret = "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=",
    ?assertEqual({error, payload_padding}, verify_and_decrypt_token(Token, Secret, TTL, Now)).

-endif.
