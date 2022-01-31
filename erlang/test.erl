-module(test).
-compile({no_auto_import,[register/2]}).
-import(opaque,[register/2,
                register/3,
                create_cred_req/1,
                create_cred_resp/4,
                recover_cred/4,
                user_auth/2,
                create_reg_req/1,
                create_reg_resp/1,
                create_reg_resp/2,
                finalize_reg/3,
                store_rec/2]).

test_reg_no_sks() ->
    Ids = {<<"idU">>, <<"idS">>},
    Sks = <<0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31>>,

    {Rec_ns, Ek_ns} = opaque:register("asdf", Ids),
    io:format("rec: ~s~n", [[io_lib:format("~2.16.0b",[X]) || <<X:8>> <= Rec_ns ]]),
    io:format("ek: ~s~n", [[io_lib:format("~2.16.0b",[X]) || <<X:8>> <= Ek_ns ]]),

    {Rec, Ek} = opaque:register("asdf", Ids, Sks),
    io:format("rec: ~s~n", [[io_lib:format("~2.16.0b",[X]) || <<X:8>> <= Rec ]]),
    io:format("ek: ~s~n", [[io_lib:format("~2.16.0b",[X]) || <<X:8>> <= Ek ]]),

    {Sec, Pub} = opaque:create_cred_req("asdf"),
    io:format("sec: ~s~n", [[io_lib:format("~2.16.0b",[X]) || <<X:8>> <= Sec ]]),
    io:format("pub: ~s~n", [[io_lib:format("~2.16.0b",[X]) || <<X:8>> <= Pub ]]),

    {Resp, Sk_serv, Sec_serv} = opaque:create_cred_resp(Pub, Rec, Ids, "context"),
    io:format("resp: ~s~n", [[io_lib:format("~2.16.0b",[X]) || <<X:8>> <= Resp ]]),
    io:format("sk: ~s~n", [[io_lib:format("~2.16.0b",[X]) || <<X:8>> <= Sk_serv ]]),
    io:format("sec: ~s~n", [[io_lib:format("~2.16.0b",[X]) || <<X:8>> <= Sec_serv ]]),

    {Sk_user, AuthU, Export_key} = opaque:recover_cred(Resp, Sec, "context", Ids),
    io:format("sk: ~s~n", [[io_lib:format("~2.16.0b",[X]) || <<X:8>> <= Sk_user ]]),
    io:format("authU: ~s~n", [[io_lib:format("~2.16.0b",[X]) || <<X:8>> <= AuthU ]]),
    io:format("ek: ~s~n", [[io_lib:format("~2.16.0b",[X]) || <<X:8>> <= Export_key ]]),

    ok = opaque:user_auth(Sec_serv, AuthU).

test_private_reg() ->
    {Sec_user, M} = opaque:create_reg_req("asdf"),
    {Sec_serv, Pub} = opaque:create_reg_resp(M),
    Ids = {<<"idU">>, <<"idS">>},
    {Rec0, Export_key} = opaque:finalize_reg(Sec_user, Pub, Ids),
    Rec = opaque:store_rec(Sec_serv, Rec0),

    {SSec, SPub} = opaque:create_cred_req("asdf"),
    {Resp, Sk, SSec_serv} = opaque:create_cred_resp(SPub, Rec, Ids, "context"),
    {Sk, AuthU, Export_key} = opaque:recover_cred(Resp, SSec, "context", Ids),
    ok = opaque:user_auth(SSec_serv, AuthU).

test_private_1kreg() ->
    {Sec_user, M} = opaque:create_reg_req("asdf"),
    SkS = <<0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31>>,
    {Sec_serv, Pub} = opaque:create_reg_resp(M, SkS),
    Ids = {nil, nil},
    {Rec0, Export_key} = opaque:finalize_reg(Sec_user, Pub, Ids),
    Rec = opaque:store_rec(Sec_serv, Rec0),

    {SSec, SPub} = opaque:create_cred_req("asdf"),
    {Resp, Sk, SSec_serv} = opaque:create_cred_resp(SPub, Rec, Ids, "context"),
    {Sk, AuthU, Export_key} = opaque:recover_cred(Resp, SSec, "context", Ids),
    ok = opaque:user_auth(SSec_serv, AuthU).

test_reg_sks() ->
    Ids = {<<"idU">>, <<"idS">>},
    Sks = <<0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31>>,

    {Rec, Ek} = opaque:register("asdf", Ids, Sks),
    io:format("rec: ~s~n", [[io_lib:format("~2.16.0b",[X]) || <<X:8>> <= Rec ]]),
    io:format("ek: ~s~n", [[io_lib:format("~2.16.0b",[X]) || <<X:8>> <= Ek ]]),

    {Sec, Pub} = opaque:create_cred_req("asdf"),
    io:format("sec: ~s~n", [[io_lib:format("~2.16.0b",[X]) || <<X:8>> <= Sec ]]),
    io:format("pub: ~s~n", [[io_lib:format("~2.16.0b",[X]) || <<X:8>> <= Pub ]]),

    {Resp, Sk_serv, Sec_serv} = opaque:create_cred_resp(Pub, Rec, Ids, "context"),
    io:format("resp: ~s~n", [[io_lib:format("~2.16.0b",[X]) || <<X:8>> <= Resp ]]),
    io:format("sk: ~s~n", [[io_lib:format("~2.16.0b",[X]) || <<X:8>> <= Sk_serv ]]),
    io:format("sec: ~s~n", [[io_lib:format("~2.16.0b",[X]) || <<X:8>> <= Sec_serv ]]),

    {Sk_user, AuthU, Export_key} = opaque:recover_cred(Resp, Sec, "context", Ids),
    io:format("sk: ~s~n", [[io_lib:format("~2.16.0b",[X]) || <<X:8>> <= Sk_user ]]),
    io:format("authU: ~s~n", [[io_lib:format("~2.16.0b",[X]) || <<X:8>> <= AuthU ]]),
    io:format("ek: ~s~n", [[io_lib:format("~2.16.0b",[X]) || <<X:8>> <= Export_key ]]),

    ok = opaque:user_auth(Sec_serv, AuthU).


main([]) ->
   test_reg_no_sks(),
   test_reg_sks(),
   test_private_reg(),
   test_private_1kreg(),
   io:format("all ok~n", []).
