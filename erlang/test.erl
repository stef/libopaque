-module(test).
-import(opaque,[register/3,
                register/4,
                create_cred_req/1,
                create_cred_resp/5,
                recover_cred/5,
                recover_cred/6,
                user_auth/2,
                create_reg_req/1,
                create_reg_resp/1,
                create_reg_resp/2,
                finalize_reg/4,
                store_rec/2,
                store_rec/3]).

test_reg_no_pks() ->
    Cfg = {inSecEnv, notPackaged, notPackaged, inSecEnv, inSecEnv},
    Ids = {<<"idU">>, <<"idS">>},
    Sks = <<0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31>>,

    {Rec_ns, Ek_ns} = opaque:register("asdf", Cfg, Ids),
    io:format("rec: ~s~n", [[io_lib:format("~2.16.0b",[X]) || <<X:8>> <= Rec_ns ]]),
    io:format("ek: ~s~n", [[io_lib:format("~2.16.0b",[X]) || <<X:8>> <= Ek_ns ]]),

    {Rec, Ek} = opaque:register("asdf", Sks, Cfg, Ids),
    io:format("rec: ~s~n", [[io_lib:format("~2.16.0b",[X]) || <<X:8>> <= Rec ]]),
    io:format("ek: ~s~n", [[io_lib:format("~2.16.0b",[X]) || <<X:8>> <= Ek ]]),

    {Sec, Pub} = opaque:create_cred_req("asdf"),
    io:format("sec: ~s~n", [[io_lib:format("~2.16.0b",[X]) || <<X:8>> <= Sec ]]),
    io:format("pub: ~s~n", [[io_lib:format("~2.16.0b",[X]) || <<X:8>> <= Pub ]]),

    Infos = {<<0,1,2,3,4>>,<<5,6,7,8>>},
    {Resp, Sk_serv, Sec_serv} = opaque:create_cred_resp(Pub, Rec, Cfg, Ids, Infos),
    io:format("resp: ~s~n", [[io_lib:format("~2.16.0b",[X]) || <<X:8>> <= Resp ]]),
    io:format("sk: ~s~n", [[io_lib:format("~2.16.0b",[X]) || <<X:8>> <= Sk_serv ]]),
    io:format("sec: ~s~n", [[io_lib:format("~2.16.0b",[X]) || <<X:8>> <= Sec_serv ]]),

    PkS = <<"\x8f\x40\xc5\xad\xb6\x8f\x25\x62\x4a\xe5\xb2\x14\xea\x76\x7a\x6e\xc9\x4d\x82\x9d\x3d\x7b\x5e\x1a\xd1\xba\x6f\x3e\x21\x38\x28\x5f">>,
    {Sk_user, AuthU, Export_key, {IdU, IdS}} = opaque:recover_cred(Resp, Sec, PkS, Cfg, Infos, {<<"">>,<<"">>}),
    io:format("sk: ~s~n", [[io_lib:format("~2.16.0b",[X]) || <<X:8>> <= Sk_user ]]),
    io:format("authU: ~s~n", [[io_lib:format("~2.16.0b",[X]) || <<X:8>> <= AuthU ]]),
    io:format("ek: ~s~n", [[io_lib:format("~2.16.0b",[X]) || <<X:8>> <= Export_key ]]),
    io:format("idU: ~s~n", [[io_lib:format("~2.16.0b",[X]) || <<X:8>> <= IdU ]]),
    io:format("idS: ~s~n", [[io_lib:format("~2.16.0b",[X]) || <<X:8>> <= IdS ]]),

    ok = opaque:user_auth(Sec_serv, AuthU).

test_private_reg() ->
    {Sec_user, M} = opaque:create_reg_req("asdf"),
    {Sec_serv, Pub} = opaque:create_reg_resp(M),
    Cfg = {inSecEnv, notPackaged, inClrEnv, inSecEnv, inSecEnv},
    Ids = {<<"idU">>, <<"idS">>},
    {Rec0, Export_key} = opaque:finalize_reg(Sec_user, Pub, Cfg, Ids),
    Rec = opaque:store_rec(Sec_serv, Rec0),

    {SSec, SPub} = opaque:create_cred_req("asdf"),
    Infos = {<<0,1,2,3,4>>,<<5,6,7,8>>},
    {Resp, Sk, SSec_serv} = opaque:create_cred_resp(SPub, Rec, Cfg, Ids, Infos),
    {Sk, AuthU, Export_key, {IdU, IdS}} = opaque:recover_cred(Resp, SSec, Cfg, Infos, {<<"">>,<<"">>}),
    ok = opaque:user_auth(SSec_serv, AuthU).

test_private_1kreg() ->
    {Sec_user, M} = opaque:create_reg_req("asdf"),
    PkS = <<"\x8f\x40\xc5\xad\xb6\x8f\x25\x62\x4a\xe5\xb2\x14\xea\x76\x7a\x6e\xc9\x4d\x82\x9d\x3d\x7b\x5e\x1a\xd1\xba\x6f\x3e\x21\x38\x28\x5f">>,
    {Sec_serv, Pub} = opaque:create_reg_resp(M, PkS),
    Cfg = {inSecEnv, notPackaged, notPackaged, inSecEnv, inSecEnv},
    Ids = {<<"idU">>, <<"idS">>},
    {Rec0, Export_key} = opaque:finalize_reg(Sec_user, Pub, Cfg, Ids),
    Sks = <<0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31>>,
    Rec = opaque:store_rec(Sec_serv, Sks, Rec0),

    {SSec, SPub} = opaque:create_cred_req("asdf"),
    Infos = {<<0,1,2,3,4>>,<<5,6,7,8>>},
    {Resp, Sk, SSec_serv} = opaque:create_cred_resp(SPub, Rec, Cfg, Ids, Infos),
    {Sk, AuthU, Export_key, {IdU, IdS}} = opaque:recover_cred(Resp, SSec, PkS, Cfg, Infos, {<<"">>,<<"">>}),
    ok = opaque:user_auth(SSec_serv, AuthU).

test_reg_pks() ->
    Cfg = {inSecEnv, notPackaged, inClrEnv, inSecEnv, inSecEnv},
    Ids = {<<"idU">>, <<"idS">>},
    Sks = <<0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31>>,

    {Rec_ns, Ek_ns} = opaque:register("asdf", Cfg, Ids),
    io:format("rec: ~s~n", [[io_lib:format("~2.16.0b",[X]) || <<X:8>> <= Rec_ns ]]),
    io:format("ek: ~s~n", [[io_lib:format("~2.16.0b",[X]) || <<X:8>> <= Ek_ns ]]),

    {Rec, Ek} = opaque:register("asdf", Sks, Cfg, Ids),
    io:format("rec: ~s~n", [[io_lib:format("~2.16.0b",[X]) || <<X:8>> <= Rec ]]),
    io:format("ek: ~s~n", [[io_lib:format("~2.16.0b",[X]) || <<X:8>> <= Ek ]]),

    {Sec, Pub} = opaque:create_cred_req("asdf"),
    io:format("sec: ~s~n", [[io_lib:format("~2.16.0b",[X]) || <<X:8>> <= Sec ]]),
    io:format("pub: ~s~n", [[io_lib:format("~2.16.0b",[X]) || <<X:8>> <= Pub ]]),

    Infos = {<<0,1,2,3,4>>,<<5,6,7,8>>},
    {Resp, Sk_serv, Sec_serv} = opaque:create_cred_resp(Pub, Rec, Cfg, Ids, Infos),
    io:format("resp: ~s~n", [[io_lib:format("~2.16.0b",[X]) || <<X:8>> <= Resp ]]),
    io:format("sk: ~s~n", [[io_lib:format("~2.16.0b",[X]) || <<X:8>> <= Sk_serv ]]),
    io:format("sec: ~s~n", [[io_lib:format("~2.16.0b",[X]) || <<X:8>> <= Sec_serv ]]),

    {Sk_user, AuthU, Export_key, {IdU, IdS}} = opaque:recover_cred(Resp, Sec, Cfg, Infos, {<<"">>,<<"">>}),
    io:format("sk: ~s~n", [[io_lib:format("~2.16.0b",[X]) || <<X:8>> <= Sk_user ]]),
    io:format("authU: ~s~n", [[io_lib:format("~2.16.0b",[X]) || <<X:8>> <= AuthU ]]),
    io:format("ek: ~s~n", [[io_lib:format("~2.16.0b",[X]) || <<X:8>> <= Export_key ]]),
    io:format("idU: ~s~n", [[io_lib:format("~2.16.0b",[X]) || <<X:8>> <= IdU ]]),
    io:format("idS: ~s~n", [[io_lib:format("~2.16.0b",[X]) || <<X:8>> <= IdS ]]),

    ok = opaque:user_auth(Sec_serv, AuthU).


main([]) ->
    test_reg_no_pks(),
    test_reg_pks(),
    test_private_reg(),
    test_private_1kreg().
