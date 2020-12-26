%%%-------------------------------------------------------------------
%%% @author root
%%% @copyright (C) 2020, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 25. 12月 2020 下午8:18
%%%-------------------------------------------------------------------
-module(emqx_tcp_connection).
-author("root").

-export([logger_header/0]).

-behaviour(gen_statem).

-include("../include/emqx_tcp.hrl").
-include("../include/emqx.hrl").
-include("../include/logger.hrl").


-export([start_link/3]).
-export([info/1, stats/1]).
-export([kick/1]).
-export([idle/3, connected/3]).
-export([init/1, callback_mode/0, code_change/4, terminate/3]).

-export([send/4]).

-record(state,
{transport, socket, peername, sockname, sockstate, active_n, pstate, parse_state, keepalive, rate_limit, limit_timer, enable_stats, stats_timer, idle_timeout}).



start_link(Transport, Socket, Options) ->
  {ok, proc_lib:spawn_link(emqx_tcp_connection, init, [{Transport, Socket, Options}])}.

-spec info(pid() | #state{}) -> map().
info(CPid) when is_pid(CPid) -> call(CPid, info);
info(State = #state{pstate = PState}) ->
  ChanInfo = emqx_tcp_protocol:info(PState),
  SockInfo = maps:from_list(info([socktype, peername, sockname, sockstate, active_n], State)),
  ChanInfo#{sockinfo => SockInfo}.

info(Keys, State) when is_list(Keys) -> [{Key, info(Key, State)} || Key <- Keys];
info(socktype, #state{transport = Transport, socket = Socket}) -> Transport:type(Socket);
info(peername, #state{peername = Peername}) -> Peername;
info(sockname, #state{sockname = Sockname}) -> Sockname;
info(sockstate, #state{sockstate = SockSt}) -> SockSt;
info(active_n, #state{active_n = ActiveN}) -> ActiveN;
info(limiter, #state{rate_limit = RateLimit}) -> rate_limit_info(RateLimit).

rate_limit_info(undefined) -> #{};
rate_limit_info(Limit) -> esockd_rate_limit:info(Limit).

%% 连接统计信息
stats(CPid) when is_pid(CPid) -> call(CPid, stats);
stats(#state{transport = Transport, socket = Socket, pstate = PState}) ->
%%  socket统计
  SockStats = case Transport:getstat(Socket, [recv_oct, recv_cnt, send_oct, send_cnt, send_pend]) of
                {ok, Ss} -> Ss;
                {error, _} -> []
              end,
%%  追加信息
  lists:append([SockStats, emqx_misc:proc_stats(), emqx_tcp_protocol:stats(PState)]).

kick(CPid) -> call(CPid, kick).

call(CPid, Req) -> gen_statem:call(CPid, Req, infinity).

%% 初始化
init({Transport, RawSocket, Options}) ->
  case Transport:wait(RawSocket) of
    {ok, Socket} -> do_init(Transport, Socket, Options);
    {error, Reason}
      when Reason =:= enotconn;Reason =:= einval;Reason =:= closed ->
      Transport:fast_close(RawSocket), exit(normal);
    {error, timeout} ->
      Transport:fast_close(RawSocket),
      exit({shutdown, ssl_upgrade_timeout});
    {error, Reason} ->
      Transport:fast_close(RawSocket), exit(Reason)
  end.
%% 连接初始化
do_init(Transport, Socket, Options) ->
  %%  获取远程套接口的名字，包括它的IP和端口，确保进程断开
  {ok, Peername} = Transport:ensure_ok_or_exit(peername, [Socket]),
  %%  获取本地套接口的名字，包括它的IP和端口，确保进程断开
  {ok, Sockname} = Transport:ensure_ok_or_exit(sockname, [Socket]),
  %% 安全连接关闭
  Peercert = Transport:ensure_ok_or_exit(peercert, [Socket]),
  %% 日志打印
  emqx_logger:set_metadata_peername(esockd:format(Peername)),
  %% 连接速率限制
  RateLimit = init_limiter(proplists:get_value(rate_limit, Options)),
  %% 读包配置
  ActiveN = proplists:get_value(active_n, Options, 100),
  %% 连接信息封装
  ConnInfo = #{
    socktype => Transport:type(Socket), %% 连接类型
    peername => Peername, sockname => Sockname,%% 连接的ip和端口
    peercert => Peercert, %% 安全连接
    %% 发送函数
    sendfun => {fun emqx_tcp_connection:send/4, [Transport, Socket]}, conn_mod => emqx_tcp_connection},
  %% 进程状态
  PState = emqx_tcp_protocol:init(ConnInfo, Options),
  %% 最大的数据
  MaxSize = proplists:get_value(max_packet_size, Options, 65535),
  %% 解析状态
  ParseState = emqx_tcp_frame:initial_parse_state(#{max_size => MaxSize}),
  %% 开启统计
  EnableStats = proplists:get_value(enable_stats, Options, true),
  %% 空闲超时时间
  IdleTimout = proplists:get_value(idle_timeout, Options, 30000),
  %% 保存当前进程的状态
  State = #state{transport = Transport, socket = Socket,
    peername = Peername, sockstate = running,
    active_n = ActiveN, rate_limit = RateLimit,
    pstate = PState, parse_state = ParseState,
    enable_stats = EnableStats, idle_timeout = IdleTimout},

  gen_statem:enter_loop(emqx_tcp_connection, [{hibernate_after, 2 * IdleTimout}], idle, State, self(), [IdleTimout]).

%% 发送数据包
send(Packet, Opts, Transport, Socket) ->
%%  序列话数据包
  Data = emqx_tcp_frame:serialize(Packet, Opts),
%%  异步发送
  case Transport:async_send(Socket, Data) of
%%    发送成功
    ok -> {ok, Data};
%%    发送失败
    {error, Reason} -> {error, Reason}
  end.

init_limiter(undefined) -> undefined;
init_limiter({Rate, Burst}) -> esockd_rate_limit:new(Rate, Burst).

callback_mode() -> [state_functions, state_enter].

idle(enter, _, State) -> ok = activate_socket(State), keep_state_and_data;
idle(timeout, _Timeout, State) -> {stop, {shutdown, idle_timeout}, State};
idle(cast, {incoming, Packet}, State) -> handle_incoming(Packet, fun (NState) -> {next_state, connected, NState} end, State);
idle(EventType, Content, State) -> handle(EventType, Content, State).

connected(enter, _, _State) -> keep_state_and_data;

connected(cast, {incoming, Packet}, State) ->
  handle_incoming(Packet, fun (NState) -> {keep_state, NState} end, State);
connected(info, {deliver, _Topic, Message}, State = #state{pstate = PState}) ->
  case emqx_tcp_protocol:deliver({message, Message}, PState) of
    {ok, NPState} ->
      NState = State#state{pstate = NPState},
      {keep_state, NState};
    {error, Reason} -> shutdown(Reason, State)
  end;
connected(info, {keepalive, start, Interval}, State) -> Keepalive = emqx_keepalive:init(Interval),
  _ = emqx_misc:start_timer(Interval, {keepalive, check}),
  {keep_state, State#state{keepalive = Keepalive}};
connected(EventType, Content, State) ->
  handle(EventType, Content, State).

handle({call, From}, info, State) ->
  reply(From, info(State), State);
handle({call, From}, stats, State) ->
  reply(From, stats(State), State);
handle({call, From}, kick, State) ->
  ok = gen_statem:reply(From, ok),
  shutdown(kicked, State);
handle({call, From}, Req, State) ->
  begin
    logger:log(error, #{},
      #{report_cb =>
      fun (_) ->
        {logger_header() ++ "Unexpected call: ~p",
          [Req]}
      end,
        mfa => {emqx_tcp_connection, handle, 3}, line => 264})
  end,
  reply(From, ignored, State);
handle(cast, Msg, State) ->
  begin
    logger:log(error, #{},
      #{report_cb =>
      fun (_) ->
        {logger_header() ++ "Unexpected cast: ~p",
          [Msg]}
      end,
        mfa => {emqx_tcp_connection, handle, 3}, line => 269})
  end,
  {keep_state, State};
handle(info, {Inet, _Sock, Data}, State = #state{pstate = PState}) when Inet == tcp; Inet == ssl -> Oct = iolist_size(Data),
  begin
    logger:log(debug, #{},
      #{report_cb =>
      fun (_) -> {logger_header() ++ "RECV ~p", [Data]}
      end,
        mfa => {emqx_tcp_connection, handle, 3}, line => 276})
  end,
  emqx_pd:inc_counter(incoming_bytes, Oct),
  ok = emqx_metrics:inc('bytes.received', Oct),
  NPState = emqx_tcp_protocol:maybe_gc_and_check_oom(Oct, PState),
  process_incoming(Data, [], State#state{pstate = NPState});
%% 处理socket连接错误
handle(info, {Error, _Sock, Reason}, State) when Error == tcp_error; Error == ssl_error ->
  shutdown(Reason, State);
%% 处理socket关闭错误
handle(info, {Closed, _Sock}, State) when Closed == tcp_closed; Closed == ssl_closed ->
  shutdown(closed, State);
%% 处理socket关闭错误
handle(info, {Passive, _Sock}, State) when Passive == tcp_passive; Passive == ssl_passive ->
  NState = ensure_rate_limit(State),
  ok = activate_socket(NState),
  {keep_state, NState};
handle(info, activate_socket, State) ->
  ok = activate_socket(State#state{sockstate = running}),
  {keep_state, State#state{sockstate = running, limit_timer = undefined}};
handle(info, {inet_reply, _Sock, ok}, State) ->
  {keep_state, State};
handle(info, {inet_reply, _Sock, {error, Reason}}, State) ->
  shutdown(Reason, State);
%% 超时错误
handle(info, {timeout, Timer, emit_stats}, State = #state{stats_timer = Timer, pstate = PState}) ->
%%  获取客户id
  ClientId = emqx_tcp_protocol:client_id(PState),
  emqx_cm:set_chan_stats(ClientId, stats(State)),
%%  关闭定时统计
  {keep_state, ensure_stats_timer(State#state{stats_timer = undefined})};
%% keepalive 消息处理
handle(info, {timeout, _Ref, {keepalive, check}}, State = #state{transport = Transport, socket = Socket, keepalive = Keepalive}) ->
  case Transport:getstat(Socket, [recv_oct]) of
    {ok, [{recv_oct, RecvOct}]} ->
      case emqx_keepalive:check(RecvOct, Keepalive) of
        {ok, NKeepalive} -> {keep_state, State#state{keepalive = NKeepalive}};
        {error, timeout} -> shutdown(keepalive_timeout, State)
      end;
    {error, Reason} -> shutdown({sockerr, Reason}, State)
  end;
handle(info, {shutdown, discard, {ClientId, ByPid}},
    State) ->
  begin
    logger:log(error, #{},
      #{report_cb =>
      fun (_) ->
        {logger_header() ++ "Discarded by ~s:~p", [ClientId, ByPid]}
      end,
        mfa => {emqx_tcp_connection, handle, 3}, line => 332})
  end,
  shutdown(discard, State);
%% 客户端冲突关闭
handle(info, {shutdown, conflict, {ClientId, NewPid}}, State) ->
  begin
    logger:log(warning, #{},
      #{report_cb =>
      fun (_) ->
        {logger_header() ++
          "Clientid '~s' conflict with ~p",
          [ClientId, NewPid]}
      end,
        mfa => {emqx_tcp_connection, handle, 3}, line => 336})
  end,
  shutdown(conflict, State);
handle(info, {shutdown, Reason}, State) ->
  shutdown(Reason, State);
%% 未知异常处理
handle(info, Info, State) ->
  begin
    logger:log(error, #{},
      #{report_cb =>
      fun (_) ->
        {logger_header() ++ "Unexpected info: ~p",
          [Info]}
      end,
        mfa => {emqx_tcp_connection, handle, 3}, line => 343})
  end,
  {keep_state, State}.

code_change({down, Vsn}, State, Data, _Extra) when Vsn =:= "4.2.0"; Vsn =:= "4.2.1" -> {ok, State, Data};
code_change(Vsn, State, Data = #state{pstate = PState}, _Extra) when Vsn =:= "4.2.0"; Vsn =:= "4.2.1" ->
  Fun = element(8, PState),
  {_, [Transport, Socket]} = erlang:fun_info(Fun, env),
  NPState = setelement(8, PState, {fun emqx_tcp_connection:send/4, [Transport, Socket]}),
  NParseState = case element(9, Data) of
                  {none, Options} -> {none, Options};
                  {more, Cont} when is_function(Cont) ->
                    case erlang:fun_info(Cont, env) of
                      {_, [{none, Options}]} -> {none, Options};
                      {_, [Rest, Options]} -> {more, {1, 1, Rest, Options}};
                      {_, [Flag, Rest, Options]} ->
                        {more, {3, Flag, Rest, Options}}
                    end
                end,
  {ok, State,
    Data#state{pstate = NPState,
      parse_state = NParseState}}.

terminate(Reason, _StateName, #state{transport = Transport, socket = Socket, pstate = PState}) ->
  begin
    logger:log(debug, #{},
      #{report_cb => fun (_) -> {logger_header() ++ "Terminated for ~p", [Reason]} end,
        mfa => {emqx_tcp_connection, terminate, 3},
        line => 374})
  end,
  Transport:fast_close(Socket),
  case {PState, Reason} of
    {undefined, _} -> ok;
    {_, {shutdown, Error}} ->
      emqx_tcp_protocol:terminate(Error, PState);
    {_, Reason} ->
      emqx_tcp_protocol:terminate(Reason, PState)
  end.
%% 空数据匹配
process_incoming(<<>>, Packets, State) ->
  {keep_state, State, next_events(Packets)};
%% 有数据进来，然后获取当前数据包的处理状态
process_incoming(Data, Packets, State = #state{parse_state = ParseState}) ->
%%  解析数据帧,返回{ok, NParseState}或者{ok, Packet, Rest, NParseState}
  try emqx_tcp_frame:parse(Data, ParseState) of
%%    解析完毕，没有剩余数据要处理
    {ok, NParseState} ->
%%      设置解析状态
      NState = State#state{parse_state = NParseState},
%%      进入下一个状态处理完整的数据包
      {keep_state, NState, next_events(Packets)};
%%    有剩余数据继续
    {ok, Packet, Rest, NParseState} ->
%%    修改进程的解析状态
      NState = State#state{parse_state = NParseState},
%%    处理剩余数据包
      process_incoming(Rest, [Packet | Packets], NState);
    {error, Reason} -> shutdown(Reason, State)
  catch
    error:Reason:Stk ->
      begin
        logger:log(error, #{},
          #{report_cb =>
          fun (_) ->
            {logger_header() ++
              "Parse failed for ~p~n\n             "
              "    Stacktrace:~p~nError data:~p",
              [Reason, Stk, Data]}
          end,
            mfa => {emqx_tcp_connection, process_incoming, 2}, line => 403})
      end,
      shutdown(parse_error, State)
  end.

%% 从Packets 列表中取出每个数据包，然后逐个处理
next_events(Packets) when is_list(Packets) -> [next_events(Packet) || Packet <- lists:reverse(Packets)];
%% 异步发送单个数据包去处理
next_events(Packet) -> {next_event, cast, {incoming, Packet}}.

%% 处理进来的数据包
handle_incoming(Packet, SuccFun, State = #state{pstate = PState}) ->
%%  emqx_tcp_protocol 模块接收数据
  case emqx_tcp_protocol:received(Packet, PState) of
%%    接收成功处理
    {ok, NPState} -> SuccFun(State#state{pstate = NPState});
%%   接收错误，关闭
    {error, Reason} -> shutdown(Reason, State);
%%   接收错误，关闭
    {error, Reason, NPState} ->
      shutdown(Reason, State#state{pstate = NPState});
%%   错误停止
    {stop, Error, NPState} ->
      stop(Error, State#state{pstate = NPState})
  end.

%%确认限速
ensure_rate_limit(State = #state{rate_limit = Rl}) ->
  Limiters = [{Rl, #state.rate_limit, emqx_pd:reset_counter(incoming_bytes)}],
  ensure_rate_limit(Limiters, State).

ensure_rate_limit([], State) -> State;
ensure_rate_limit([{undefined, _Pos, _Cnt} | Limiters], State) ->
  ensure_rate_limit(Limiters, State);
ensure_rate_limit([{Rl, Pos, Cnt} | Limiters], State) ->
  case esockd_rate_limit:check(Cnt, Rl) of
    {0, Rl1} ->
      ensure_rate_limit(Limiters, setelement(Pos, State, Rl1));
    {Pause, Rl1} ->
      begin
        logger:log(debug, #{},
          #{report_cb =>
          fun (_) -> {logger_header() ++ "Rate limit pause connection ~pms", [Pause]} end,
            mfa => {emqx_tcp_connection, ensure_rate_limit, 1},
            line => 443})
      end,
      TRef = erlang:send_after(Pause, self(), activate_socket),
      setelement(Pos, State#state{sockstate = blocked, limit_timer = TRef}, Rl1)
  end.

%% 设置socket ativate值
activate_socket(#state{sockstate = blocked}) -> ok;
activate_socket(#state{transport = Transport, socket = Socket, active_n = N}) ->
  case Transport:setopts(Socket, [{active, N}]) of
    ok -> ok;
    {error, Reason} -> self() ! {shutdown, Reason}, ok
  end.

%% 确认统计
ensure_stats_timer(State = #state{enable_stats = true, stats_timer = undefined, idle_timeout = IdleTimeout}) ->
  State#state{stats_timer = emqx_misc:start_timer(IdleTimeout, emit_stats)};
ensure_stats_timer(State) -> State.

reply(From, Reply, State) -> {keep_state, State, [{reply, From, Reply}]}.

shutdown(Reason = {shutdown, _}, State) -> stop(Reason, State);
shutdown(Reason, State) -> stop({shutdown, Reason}, State).
stop(Reason, State) -> {stop, Reason, State}.
logger_header() -> "[TCP-Conn] ".


