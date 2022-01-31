-module(opaque).

-export([init/0,
         register/2,
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
-on_load(init/0).

init() ->
    case os:getenv("NIF_DIR") of
        false -> Path = ".";
        Path -> Path
    end,
    ok = erlang:load_nif(Path ++ "/opaque", 0).

register(_,_) ->
  erlang:nif_error("opaque bindings library not loaded").

register(_,_,_) ->
  erlang:nif_error("opaque bindings library not loaded").

create_cred_req(_) ->
  erlang:nif_error("opaque bindings library not loaded").

create_cred_resp(_,_,_,_) ->
  erlang:nif_error("opaque bindings library not loaded").

recover_cred(_,_,_,_) ->
  erlang:nif_error("opaque bindings library not loaded").

user_auth(_,_) ->
  erlang:nif_error("opaque bindings library not loaded").

create_reg_req(_) ->
  erlang:nif_error("opaque bindings library not loaded").

create_reg_resp(_) ->
  erlang:nif_error("opaque bindings library not loaded").

create_reg_resp(_,_) ->
  erlang:nif_error("opaque bindings library not loaded").

finalize_reg(_,_,_) ->
  erlang:nif_error("opaque bindings library not loaded").

store_rec(_,_) ->
  erlang:nif_error("opaque bindings library not loaded").
