-module(fernet_spec_SUITE).

-behaviour(ct_suite).

-include_lib("eunit/include/eunit.hrl").
-include_lib("common_test/include/ct.hrl").

-export([all/0, verify_test/1, invalid_test/1, generate_test/1]).

-define(EPOCH_OFFSET, 62167219200).

%% Specific test cases or groups to run.  The test case is named as a
%% single atom.  Groups are named as {group, GroupName}.  The tests
%% will run in the order given in the list.
all() ->
    [verify_test, invalid_test, generate_test].

%%====================================================================
%% Setup and teardown
%%====================================================================

read_fixture_file(Config, Filename) ->
    DataDir = ?config(data_dir, Config),
    file:read_file(
        filename:join(DataDir, Filename)).

timestamp_to_seconds(Timestamp) ->
    DateTime = ec_date:parse(binary_to_list(Timestamp)),
    {Date, {Hours, Minutes, Seconds, _Offset}} = DateTime,
    Time = {Hours, Minutes, Seconds},
    calendar:datetime_to_gregorian_seconds({Date, Time}) - ?EPOCH_OFFSET.

%%====================================================================
%% Tests
%%====================================================================

verify_test(Config) ->
    {ok, Raw} = read_fixture_file(Config, "verify.json"),
    lists:foreach(fun(V) ->
                     Src = maps:get(src, V),
                     Now = timestamp_to_seconds(maps:get(now, V)),
                     {ok, Src} =
                         fernet:verify_and_decrypt_token(
                             maps:get(token, V), maps:get(secret, V), maps:get(ttl_sec, V), Now)
                  end,
                  jsx:decode(Raw, [{labels, attempt_atom}, return_maps])),
    Config.

invalid_test(Config) ->
    {ok, Raw} = read_fixture_file(Config, "invalid.json"),
    lists:foreach(fun(V) ->
                     Now = timestamp_to_seconds(maps:get(now, V)),
                     %% Note, this doesn't check the desc field.
                     {error, _} =
                         fernet:verify_and_decrypt_token(
                             maps:get(token, V), maps:get(secret, V), maps:get(ttl_sec, V), Now)
                  end,
                  jsx:decode(Raw, [{labels, attempt_atom}, return_maps])),
    Config.

generate_test(Config) ->
    {ok, Raw} = read_fixture_file(Config, "generate.json"),
    lists:foreach(fun(V) ->
                     Now = timestamp_to_seconds(maps:get(now, V)),
                     Token = maps:get(token, V),
                     Token =
                         fernet:generate_token(
                             maps:get(src, V),
                             list_to_binary(maps:get(iv, V)),
                             Now,
                             maps:get(secret, V))
                  end,
                  jsx:decode(Raw, [{labels, attempt_atom}, return_maps])),
    Config.
