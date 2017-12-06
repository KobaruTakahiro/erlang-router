-module(routingTable).
-export([main/1]).

-include("routingTable.hrl").

main(IpTable) ->
    io:format("routingTable:main(ipTable) ~n"),
    receive
        {From, requestIP, RequestIP} ->
            io:format("routingTable:main recieve {From, requestIP, RequestIP}~n"),
            case getRoutingTable(RequestIP, IpTable) of
                {ok, DestIPAddress} ->
                    From ! {responseIP, DestIPAddress};
                false ->
                    From ! {error, "not found routing table record"} 
            end
    end,
    main(IpTable).

    
getRoutingTable(RequestIP, IpTable) ->
    io:format("routingTable:getRoutingTable(RequestIP, IpTable) ~n"),
    io:format("request ip : ~w~n", [RequestIP]),
    io:format("ip table   : ~w~n", [IpTable]),
    {ok, RequestIP}.
