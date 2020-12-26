%%%-------------------------------------------------------------------
%%% @author root
%%% @copyright (C) 2020, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 25. 12月 2020 下午8:19
%%%-------------------------------------------------------------------
-module(emqx_tcp_sup).
-author("root").
%% 监听者行为模式
-behaviour(supervisor).

%% 启动模块方法
-export([start_link/0]).

%% 回调初始化方法
-export([init/1]).

%% 监听者启动函数
start_link() ->
  %% 调用模块emqx_tcp_sup的方法
  supervisor:start_link({local, emqx_tcp_sup},emqx_tcp_sup,[]).

%% 回调初始化方法
init([]) -> {ok, {{one_for_one, 1, 5}, []}}.
