%%%-------------------------------------------------------------------
%%% @author root
%%% @copyright (C) 2020, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 25. 12月 2020 下午8:18
%%%-------------------------------------------------------------------
-module(emqx_tcp_frame).
-author("root").

-include("../include/emqx_tcp.hrl").

-export([initial_parse_state/1, parse/2, serialize/2]).

-export([format/1]).

initial_parse_state(Options) when is_map(Options) ->
  {none, merge_opts(Options)}.

merge_opts(Options) ->
  maps:merge(#{max_size => 65535, version => 1}, Options).

%% 空数据包
parse(<<>>, {none, Options}) -> {ok, {none, Options}};
%% 匹配4个字节的包类型
parse(<<Type:4, Flags:4, Rest/binary>>, {none, Options}) ->
  io_lib:format("parse(Type=~p, Flags=~p)", [Type, Flags]),
  parse_frame_type(Type, Flags, Rest, Options);
parse(Bin, {more, {Type, Flags, Rest, Options}}) when is_binary(Bin) ->
  parse_frame_type(Type, Flags, <<Rest/binary, Bin/binary>>, Options).

parse_frame_type(1, 1, Rest, Options) ->
%%  从Rest去匹配数据，函数返回{more, Rest}或者{连接数据包和剩余数据包}
  case run_read_funs([fun read_length_binary/1], Rest) of

    {ok, Rest1, [ConnPayload]} ->
%%      解析连接数据包的负载
      case parse_conn_payload(ConnPayload) of
        {error, Reason} -> {error, Reason};
%%        匹配到{Keepalive，ClientId，Username，Password}
        {Keepalive, ClientId, Username, Password} ->
          Pkt = #tcp_packet_conn{client_id = ClientId, keepalive = Keepalive, username = Username, password = Password, version = 1},
          {ok, Pkt, Rest1, {none, Options#{version => 1}}}
      end;
    {more, Rest} -> {ok, {more, {1, 1, Rest, Options}}}
  end;

%% 业务数据包 type = 1 连接包
parse_frame_type(1, Version, _Rest, _Options) ->
  {error, {not_supported_version, Version}};

%% 业务数据包 type = 4
parse_frame_type(3, Flags, Rest, Options = #{max_size := MaxSize}) ->

  case run_read_funs([fun read_length_binary/1], Rest) of
    {ok, Rest1, [Data]} ->
      case byte_size(Data) of
        Len when Len > MaxSize ->
          {error, {max_size_limit, Len, MaxSize}};
        Len ->
          Pkt = #tcp_packet_datatrans{length = Len, data = Data},
          {ok, Pkt, Rest1, {none, Options}}
      end;
%%    如果有更多
    {more, Rest} -> {ok, {more, {3, Flags, Rest, Options}}}
  end;
%% ping 数据包 type = 4
parse_frame_type(4, _Flags, Rest, Options) ->
  {ok, #tcp_packet_ping{}, Rest, {none, Options}};
%% 断开连接包 type = 6
parse_frame_type(6, _Flags, Rest, Options) ->
  {ok, #tcp_packet_disconn{}, Rest, {none, Options}};
%% 其他非法数据包
parse_frame_type(Type, Flags, Rest, Options) ->
  {error, {illegal_frame, {Type, Flags, Rest, Options}}}.

%% 解析连接负载，读取客户 ClientId
parse_conn_payload(<<K:8, L1:16, ClientId:L1/binary>>) ->
  {K, ClientId, undefined, undefined};
%% 读取用户名
parse_conn_payload(<<K:8, L1:16, ClientId:L1/binary, L2:16, Username:L2/binary>>) ->
  {K, ClientId, Username, undefined};
%% 读取用户密码
parse_conn_payload(<<K:8, L1:16, ClientId:L1/binary, L2:16, Username:L2/binary, L3:16, Password:L3/binary>>) ->
  {K, ClientId, Username, Password};
%% 其他非法连接负载
parse_conn_payload(_) ->
  {error, invalid_conn_payload_format}.

%% socket读方法
-spec run_read_funs(list(), binary()) -> {ok, binary(), ReadResult :: list()} |{more, binary()}.
run_read_funs(Funs, Bin) when is_list(Funs) and is_binary(Bin) ->
  case run_read_funs(Funs, Bin, []) of
    {ok, Remaining, Results} -> {ok, Remaining, Results};
    {pause, _, _} -> {more, Bin}
  end.

run_read_funs([], Bin, Acc) -> {ok, Bin, lists:reverse(Acc)};
run_read_funs([Fun | RFuns], Bin, Acc) ->
  case Fun(Bin) of
    {more, Bin} -> {pause, Bin, lists:reverse(Acc)};
    {Content, RestBin} -> run_read_funs(RFuns, RestBin, [Content | Acc])
  end.

%% 读数据长度
-spec read_length_binary(binary()) -> {more, binary()} |{Content :: binary(), Rest :: binary()}.
%% 小于2，返回有更多
read_length_binary(Bin) when byte_size(Bin) < 2 -> {more, Bin};
%% 从Bin 匹配2个字节的长度Len,其余的赋值给Rest
read_length_binary(<<Len:16, Rest/binary>> = Bin) ->
%%  如果Rest的长度等于 Len
  case byte_size(Rest) >= Len of
%%    如果false，说明还有更多
    false -> {more, Bin};
%%    如果刚好，就可以取出一个数据
    true ->
%%      从Rest中匹配长度为Len的内容Content，剩余的赋值给Rest1
      <<Content:Len/binary, Rest1/binary>> = Rest,
%%    返回配的内容和剩余的数值
      {Content, Rest1}
  end.

%% tcp连接数据包序列化
serialize(#tcp_packet_conn{client_id = ClientId, keepalive = Keepalive, username = Username, password = Password, version = Version}, _Opts) ->
%%  负载区数据二进制编码
  Payload = <<Keepalive:8, (lbin(ClientId))/binary, (encode_username_and_passowrd(Username, Password))/binary>>,
%%  长度编码
  LenOfPaylaod = byte_size(Payload),
%%  构建二进制数据 4个byte的类型，4个byte的版本，16个byte的长度，8 byte Keepalive,ClientId,username,password
  <<1:4, Version:4, LenOfPaylaod:16, Payload/binary>>;
%% 连接包回复
serialize(#tcp_packet_connack{code = Code, msg = Msg}, _Opts) -> <<2:4, Code:4, (lbin(Msg))/binary>>;
%% 业务数据包
serialize(#tcp_packet_datatrans{data = Data}, _Opts) -> <<3:4, 0:4, (lbin(Data))/binary>>;
%% 心跳包
serialize(#tcp_packet_ping{}, _Opts) -> <<4:4, 0:4>>;
serialize(#tcp_packet_pong{}, _Opts) -> <<5:4, 0:4>>;
%% 断开连接
serialize(#tcp_packet_disconn{}, _Opts) -> <<6:4, 0:4>>.

%% 未定义的用户名和密码 编码返回空
encode_username_and_passowrd(undefined, undefined) ->
  <<>>;
%%
encode_username_and_passowrd(Username, undefined) ->
  <<(lbin(Username))/binary>>;
encode_username_and_passowrd(Username, Password) when is_binary(Username), is_binary(Password) ->
  <<(lbin(Username))/binary, (lbin(Password))/binary>>;
encode_username_and_passowrd(Username, Password) ->
  error({not_supported_username_password, Username, Password}).

%% 数据长度编码
lbin(B) when is_binary(B) ->
  <<(byte_size(B)):16, B/binary>>.

format(#tcp_packet_conn{client_id = ClientId, username = Username}) ->
  io_lib:format("CONNECT(client_id=~s, username=~p)", [ClientId, Username]);
format(#tcp_packet_connack{code = Code, msg = Msg}) ->
  io_lib:format("CONNACK(code=~p, msg=~s)", [Code, Msg]);
format(#tcp_packet_datatrans{length = Len, data = Data}) ->
  io_lib:format("DATATRANS(length=~p, data=~p)", [Len, Data]);
format(#tcp_packet_ping{}) -> io_lib:format("PING", []);
format(#tcp_packet_pong{}) -> io_lib:format("PONG", []);
format(#tcp_packet_disconn{}) -> io_lib:format("DISCONN", []).

