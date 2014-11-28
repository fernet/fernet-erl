# fernet for Erlang#

This is an Erlang implementation of the [https://github.com/fernet/spec](Fernet
specification) which "takes a user-provided message (an arbitrary sequence of
bytes), a key (256 bits), and the current time, and produces a token, which
contains the message in a form that can't be read or altered without the key."

## Interface ##

The `all/2` function gives an ordering of all nodes:

    1> fernet:generate_token("hello", ""
    [{192,198,2,1},{127,0,0,1},{255,0,0,1},{198,2,1,2}]
    1> Key = fernet:generate_key().
    <<183,88,242,112,75,57,77,51,186,199,75,192,143,226,186,
    238,248,154,13,66,136,151,200,66,53,179,25,124,205,...>>
    2> fernet:generate_token("hello", Key).
    "gAAAAABUePOv15TqGfU53xE8Ve2oK9okoFzRGZB-bzyqZg1kRaclkXPzz6x15I-yHoT1vnhPCd6pdkskwqc5wyDF-wjVMdpauw"