# fernet for Erlang #

This is an Erlang implementation of the [Fernet specification](https://github.com/fernet/spec) which

 > "takes a user-provided message (an arbitrary sequence of
 > bytes), a key (256 bits), and the current time, and produces a token, which
 > contains the message in a form that can't be read or altered without the key."

## Interface ##

```erlang
1> Key = fernet:generate_encoded_key().
<<"iXOktbuC7QYXM9aF_m49VAqdkZ6jQBMsqjYwEHTm5ps=">>

2> Token = fernet:generate_token("hello", Key).
<<"gAAAAABVguk6wOivag6ZN_76fP2EXltZGJ9yPLLXKg4aBR9ekbhVnYmkJOuqTGl_GlmNlg6Z_KDl2wb1duRV41CNbF931n4LgA==">>

3> fernet:verify_and_decrypt_token(Token, Key, infinity).
{ok,<<"hello">>}

4> TTL = 10. % seconds
10

5> fernet:verify_and_decrypt_token(Token, Key, TTL).
{error, too_old}
```
