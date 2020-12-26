%%%-------------------------------------------------------------------
%%% @author root
%%% @copyright (C) 2020, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 25. 12月 2020 下午8:18
%%%-------------------------------------------------------------------
-module(emqx_tcp_app).
-author("root").

-behaviour(application).

-emqx_plugin(protocol).

-export([start/2, stop/1]).
-export([start_listener/1, start_listener/3, stop_listener/1, stop_listener/3]).

-include("../include/emqx_mqtt.hrl").
-type listener() :: {esockd:proto(), esockd:listen_on(), [esockd:option()]}.

%% 启动应用
start(_Type, _Args) ->
  start_listener(), emqx_tcp_sup:start_link().

%% 停止应用
stop(_State) -> stop_listener().

%% 根据配置开启监听
start_listener() ->
  lists:foreach(fun start_listener/1, listeners_confs()).

%% 停止所有的监听
stop_listener() ->
  lists:foreach(fun stop_listener/1, listeners_confs()).

-spec start_listener(listener()) -> {ok, pid()} |{error, term()}.
start_listener({Proto, ListenOn, Options}) ->
  case start_listener(Proto, ListenOn, Options) of
    {ok, _} ->
      io:format("Start emqx-tcp:~s listener on ~s successfully.~n", [Proto, format(ListenOn)]);
    {error, Reason} ->
      io:format(standard_error,
        "Failed to start emqx-tcp:~s listener "
        "on ~s - ~p~n!",
        [Proto, format(ListenOn), Reason])
  end.

-spec start_listener(esockd:proto(), esockd:listen_on(), [esockd:option()]) -> {ok, pid()} | {error, term()}.
start_listener(tcp, ListenOn, Options) ->
  start_tcp_listener('emqx-tcp:tcp', ListenOn, Options);
start_listener(ssl, ListenOn, Options) ->
  start_tcp_listener('emqx-tcp:ssl', ListenOn, Options).

start_tcp_listener(Name, ListenOn, Options) ->
  SockOpts = esockd:parse_opt(Options),
  esockd:open(Name, ListenOn, merge_default(SockOpts), {emqx_tcp_connection, start_link, [Options -- SockOpts]}).

merge_default(Options) ->
  case lists:keytake(tcp_options, 1, Options) of
    {value, {tcp_options, TcpOpts}, Options1} ->
      [{tcp_options,
        emqx_misc:merge_opts([binary, {packet, raw},
          {reuseaddr, true}, {backlog, 512},
          {nodelay, true}],
          TcpOpts)}
        | Options1];
    false ->
      [{tcp_options,
        [binary, {packet, raw}, {reuseaddr, true},
          {backlog, 512}, {nodelay, true}]}
        | Options]
  end.

listeners_confs() ->
  [{Proto, ListenOn, wrap_proto_options(Options)} || {Proto, ListenOn, Options} <- env(listeners, [])].

wrap_proto_options(Opts) ->
  ProtoOpts = [{K, env(K)} || K <- protokeys(), env(K) =/= undefined],
  ProtoOpts ++ Opts.

protokeys() ->
  [idle_timeout, up_topic, dn_topic, max_packet_size,enable_stats, force_gc_policy, force_shutdown_policy].

-spec stop_listener(listener()) -> ok | {error, term()}.
stop_listener({Proto, ListenOn, Opts}) ->
  case stop_listener(Proto, ListenOn, Opts) of
    ok ->
      io:format("Stop emqx-tcp:~s listener on ~s successfully.~n", [Proto, format(ListenOn)]);
    {error, Reason} ->
      io:format(standard_error,
        "Failed to stop emqx-tcp:~s listener "
        "on ~s - ~p~n.",
        [Proto, format(ListenOn), Reason])
  end.

-spec stop_listener(esockd:proto(), esockd:listen_on(),
    [esockd:option()]) -> ok | {error, term()}.

stop_listener(tcp, ListenOn, _Opts) ->
  esockd:close('emqx-tcp:tcp', ListenOn);
stop_listener(Proto, ListenOn, _Opts)
  when Proto == ssl; Proto == tls ->
  esockd:close('emqx-tcp:ssl', ListenOn).

format(Port) when is_integer(Port) ->
  io_lib:format("0.0.0.0:~w", [Port]);
format({Addr, Port}) when is_list(Addr) ->
  io_lib:format("~s:~w", [Addr, Port]);
format({Addr, Port}) when is_tuple(Addr) ->
  io_lib:format("~s:~w", [inet:ntoa(Addr), Port]).

env(Key) -> env(Key, undefined).

env(Key, Default) ->
  application:get_env(emqx_tcp, Key, Default).

