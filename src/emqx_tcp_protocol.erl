%%%-------------------------------------------------------------------
%%% @author root
%%% @copyright (C) 2020, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 25. 12月 2020 下午8:18
%%%-------------------------------------------------------------------
-module(emqx_tcp_protocol).
-author("root").

-export([logger_header/0]).
-include("../include/emqx_tcp.hrl").
-include("../include/emqx.hrl").
-include("../include/logger.hrl").

-import(proplists, [get_value/2]).

-import(emqx_misc, [maybe_apply/2]).

-export([init/2, received/2, deliver/2, terminate/2, maybe_gc_and_check_oom/2]).

-export([info/1, client_id/1, stats/1]).

%% 进程状态定义
-record(pstate,
{peername, sockname, peercert, client_id, username,
  keepalive, sendfun, conn_pid, connected = false,
  up_topic, dn_topic, proto_ver, conn_mod, connected_at,
  gc_state, recv_stats, send_stats}).


init(SocketOpts = #{sockname := Sockname, peername := Peername, peercert := Peercert, sendfun := SendFun}, Options) ->
  #pstate{
    sockname = Sockname,
    peername = Peername,
    peercert = Peercert,
    up_topic = get_value(up_topic, Options),%% 上行数据
    dn_topic = get_value(dn_topic, Options),%% 下行数据
    conn_pid = self(), sendfun = SendFun,%% 发送函数
    gc_state = init_gc_state(),%% gc状态
    conn_mod = maps:get(conn_mod, SocketOpts, undefined), %% 连接模块
    recv_stats = #{msg => 0, pkt => 0}, %% 接收统计
    send_stats = #{msg => 0, pkt => 0}}.%% 发送统计

init_gc_state() ->
  GcPolicy = application:get_env(emqx_tcp, force_gc_policy, undefined),
  maybe_apply(fun emqx_gc:init/1, GcPolicy).

%% 连接包接收，为连接状态
received(Packet = #tcp_packet_conn{},PState = #pstate{connected = false}) ->
%%  处理数据包，连接状态设置为true
  process(Packet, PState#pstate{connected = true});
%% 已经连接状态下处理
received(#tcp_packet_conn{}, PState = #pstate{connected = true}) ->
  {error, protocol_has_connected, PState};
received(_Packet, PState = #pstate{connected = false}) ->
  {error, protocol_not_connected, PState};
received(Packet, PState) -> process(Packet, PState).

process(#tcp_packet_conn{client_id = ClientId,keepalive = Keepalive, username = Username, password = Password}, PState) ->
%%
  PState1 = prepare_adapter_topic(PState#pstate{client_id = ClientId, username = Username, keepalive = Keepalive, connected_at = erlang:system_time(millisecond)}),
%%  客户端信息
  ClientInfo = clientinfo(PState1),
%%  执行钩子函数，回调设备连接信息
  _ = run_hooks('client.connect', [conninfo(PState1)], undefined),
%%  连接回复
  connack(case emqx_access_control:authenticate(ClientInfo#{password => Password}) of
            {ok, _ClientInfo0} ->
              emqx_logger:set_metadata_clientid(ClientId),
              ok = emqx_cm:register_channel(ClientId, info(PState1), stats(PState1)),
              autosubcribe(PState1),
              start_keepalive(Keepalive, PState1),
              {0, PState1};
            {error, Reason} ->
              begin
                logger:log(warning, #{},
                  #{report_cb =>
                  fun (_) ->
                    {logger_header() ++ "TCP Client ~s (Username: '~s') login failed for ~p", [ClientId, Username, Reason]}
                  end,
                    mfa => {emqx_tcp_protocol, process, 2}, line => 113})
              end,
              {1, <<"Authentication Failure">>, PState1}
          end);
%% 处理业务数据
process(Packet = #tcp_packet_datatrans{}, PState) ->
  do_publish(Packet, PState);
%% 处理ping数据
process(#tcp_packet_ping{}, PState) ->
  deliver(pong, PState);
%% 连接断开
process(#tcp_packet_disconn{}, PState) ->
  {stop, normal, PState};
%% 未知数据包
process(Packet, PState) ->
  {error, {unknown_packet, Packet}, PState}.

terminate(_Reason, #pstate{client_id = undefined}) ->
  ok;
terminate(_Reason, #pstate{connected = false}) -> ok;
terminate(Reason, PState) ->
  begin
    logger:log(info, #{},
      #{report_cb =>
      fun (_) ->
        {logger_header() ++ "Shutdown for ~p", [Reason]}
      end,
        mfa => {emqx_tcp_protocol, terminate, 2}, line => 134})
  end,
  ConnInfo = conninfo(PState),
  ConnInfo1 = maps:put(disconnected_at, erlang:system_time(millisecond), ConnInfo),
  ok = emqx_hooks:run('client.disconnected', [clientinfo(PState), Reason, ConnInfo1]).

info(PState) ->
  maps:from_list(info([conninfo, conn_state, clientinfo, session, will_msg], PState)).

info(Keys, PState) when is_list(Keys) -> [{Key, info(Key, PState)} || Key <- Keys];
%% 连接信息
info(conninfo, PState) -> conninfo(PState);
%% 客户信息
info(clientinfo, PState) -> clientinfo(PState);
%% 连接session
info(session, _) -> undefined;
%% 连接状态
info(conn_state, #pstate{connected = Connected}) ->
  Connected;
%% 遗嘱消息
info(will_msg, _) -> undefined.

client_id(#pstate{client_id = ClientId}) -> ClientId.

%% 统计
stats(#pstate{recv_stats =
#{pkt := RecvPkt, msg := RecvMsg},
  send_stats = #{pkt := SendPkt, msg := SendMsg}}) ->
  [{recv_pkt, RecvPkt}, {recv_msg, RecvMsg}, {send_pkt, SendPkt}, {send_msg, SendMsg}].

%% keepalive消息发送
start_keepalive(0, _PState) -> ignore;
start_keepalive(Secs, _PState) when Secs > 0 -> self() ! {keepalive, start, round(Secs)}.

clientinfo(#pstate{client_id = ClientId, username = Username, peername = {Peerhost, _}, peercert = Peercert}) ->
  with_cert(#{zone => undefined, protocol => tcp,
    peerhost => Peerhost, clientid => ClientId,
    username => Username, peercert => Peercert,
    is_bridge => false, is_supuser => false,
    mountpoint => undefined, ws_cookie => undefined,
    sockport => 8090},
    Peercert).

with_cert(ClientInfo, undefined) -> ClientInfo;
with_cert(ClientInfo, Peercert) -> ClientInfo#{dn => esockd_peercert:subject(Peercert), cn => esockd_peercert:common_name(Peercert)}.

conninfo(#pstate{sockname = Sockname,
  peername = Peername, peercert = Peercert,
  client_id = ClientId, username = Username,
  keepalive = Keepalive, connected = Connected,
  connected_at = ConnectedAt, conn_mod = ConnMod,
  proto_ver = ProtoVer}) ->
  #{socktype => tcp, sockname => Sockname,
    peername => Peername, peercert => Peercert,
    conn_mod => ConnMod, proto_name => <<"tcp">>,
    proto_ver => ProtoVer, clean_start => true,
    clientid => ClientId, username => Username,
    conn_props => [], connected => Connected,
    connected_at => ConnectedAt, keepalive => Keepalive,
    receive_maximum => 0, expiry_interval => 0}.

prepare_adapter_topic(PState = #pstate{up_topic = UpTopic, dn_topic = DnTopic}) ->
  PState#pstate{up_topic = replvar(UpTopic, PState), dn_topic = replvar(DnTopic, PState)}.

replvar(undefined, _PState) -> undefined;
replvar(Topic, #pstate{client_id = ClientId, username = Username}) ->
  iolist_to_binary(re:replace(re:replace(Topic, "%c", ClientId), "%u", to_binary(Username))).

autosubcribe(#pstate{dn_topic = Topic}) when Topic == undefined; Topic == "" -> ok;
autosubcribe(PState = #pstate{dn_topic = Topic,
  client_id = ClientId}) ->
  SubOpts = #{rap => 0, nl => 0, qos => 0, rh => 0},
  emqx:subscribe(Topic, ClientId, SubOpts),
  ok = emqx_hooks:run('session.subscribed', [clientinfo(PState), Topic, SubOpts#{is_new => true}]).

connack({0, PState}) ->
  _ = run_hooks('client.connack', [conninfo(PState), success], undefined),
  run_hooks('client.connected', [clientinfo(PState), conninfo(PState)]),
  deliver({connack, 0, <<"Connect Successfully">>}, PState);
connack({Code, Msg, PState}) ->
  _ = run_hooks('client.connack', [conninfo(PState), not_authorized], undefined),
  deliver({connack, Code, Msg}, PState).

do_publish(#tcp_packet_datatrans{data = Data}, PState = #pstate{up_topic = Topic}) ->
  Msg = emqx_message:make(emqx_tcp_connector, Topic, Data),
  emqx:publish(Msg),
  {ok, PState}.

deliver({message, #message{payload = Payload}}, PState) ->
  send(#tcp_packet_datatrans{data = Payload, length = byte_size(Payload)}, PState);
deliver({connack, Code, Msg}, PState) -> send(#tcp_packet_connack{code = Code, msg = Msg}, PState);
deliver(pong, PState) -> send(#tcp_packet_pong{}, PState);
deliver(Delivery, _PState) -> {error, {not_supported_delivery, Delivery}}.

send(Packet, PState = #pstate{proto_ver = Ver, sendfun = {Fun, Args}}) ->
  case erlang:apply(Fun, [Packet, #{version => Ver}] ++ Args) of
    ok -> trace(send, Packet), {ok, PState};
    {ok, Data} ->
      trace(send, Packet),
      NPState = maybe_gc_and_check_oom(iolist_size(Data), PState),
      {ok, inc_stats(send,
          begin
            case tuple_to_list(Packet) of
              [tcp_packet_conn | _] -> conn;
              [tcp_packet_connack | _] -> connack;
              [tcp_packet_datatrans | _] -> datatrans;
              [tcp_packet_ping | _] -> ping;
              [tcp_packet_pong | _] -> pong;
              [tcp_packet_disconn | _] -> disconn
            end
          end,
          NPState)};
    {error, Reason} -> {error, Reason}
  end.

trace(recv, Packet) ->
  begin
    logger:log(debug, #{},
      #{report_cb => fun (_) -> {logger_header() ++ "RECV ~s", [emqx_tcp_frame:format(Packet)]} end, mfa => {emqx_tcp_protocol, trace, 2}, line => 292})
  end;
trace(send, Packet) ->
  begin
    logger:log(debug, #{},
      #{report_cb =>
      fun (_) ->
        {logger_header() ++ "SEND ~s", [emqx_tcp_frame:format(Packet)]}
      end,
        mfa => {emqx_tcp_protocol, trace, 2}, line => 294})
  end.

maybe_gc_and_check_oom(_Oct, PState = #pstate{gc_state = undefined}) ->
  PState;
maybe_gc_and_check_oom(Oct, PState = #pstate{gc_state = GCSt}) ->
  {IsGC, GCSt1} = emqx_gc:run(1, Oct, GCSt),
  if IsGC ->
    Policy = application:get_env(emqx_tcp, force_shutdown_policy, undefined),
    case emqx_oom:check(emqx_oom:init(Policy)) of
      ok -> ok;
      Shutdown -> self() ! Shutdown
    end;
    true -> ok
  end,
  PState#pstate{gc_state = GCSt1}.

-compile({inline, [{run_hooks, 2}, {run_hooks, 3}]}).

run_hooks(Name, Args) ->
  ok = emqx_metrics:inc(Name), emqx_hooks:run(Name, Args).

run_hooks(Name, Args, Acc) ->
  ok = emqx_metrics:inc(Name),
  emqx_hooks:run_fold(Name, Args, Acc).

inc_stats(recv, Type, PState = #pstate{recv_stats = Stats}) ->
  PState#pstate{recv_stats = inc_stats(Type, Stats)};
inc_stats(send, Type, PState = #pstate{send_stats = Stats}) ->
  PState#pstate{send_stats = inc_stats(Type, Stats)}.

inc_stats(Type, Stats = #{pkt := PktCnt, msg := MsgCnt}) ->
  Stats#{pkt := PktCnt + 1,
    msg :=
    case Type =:= datatrans of
      true -> MsgCnt + 1;
      false -> MsgCnt
    end}.

to_binary(A) when is_atom(A) -> atom_to_binary(A, utf8);
to_binary(B) when is_binary(B) -> B.

logger_header() -> "[TCP-Proto] ".
