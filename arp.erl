-module(arp).
-export([main/2]).
main(FD, ArpTable) ->
    io:format("start arp process ~n"),
    receive
        {request, RequestIp} ->
            io:format("hello:~p~n",[RequestIp]),
            main(FD, ArpTable);
            
        Other ->
            io:format("not supported:~p~n",[Other]),
            main(FD, ArpTable)
    end.
