-module(interface).
-export([getInterface/0, searchInterface/1, matchNetMaskAddress/1]).

-include("ethernet.hrl").

getInterface() ->
    {ok, IfLists} = inet:getifaddrs(),
    Listen = lists:filter(fun(Elm) -> interfaceList(Elm) end, IfLists),
    Listen.

interfaceList(Elm) ->
    {Name, _} = Elm,
    string:find(Name, "eth") =/= nomatch.

%sarch to MacAddress
searchInterface({macAddress, Interface, DestMacAddress}) ->
    {_, Eopt} = Interface,
    [{flags, _}, {hwaddr, Hwaddr}, {addr, _}, {netmask, _}, {broadaddr, _}] = Eopt,
    if
        Hwaddr =:= DestMacAddress ->
            true;
        true ->
            false
    end;

% search to Ethernet
searchInterface({ethernet, Interface, Ethernet}) ->
    searchInterface({macAddress, Interface, Ethernet#ethernetHeader.destMacAddress});

% search to ip address and netmask
searchInterface({ipNetMaskAddress, Interface, DestIpAddress}) ->
    {_, Eopt} = Interface,
    [{flags, _}, {hwaddr, _}, {addr, Addr}, {netmask, NetMask}, {broadaddr, _}] = Eopt,
    NetMaskAddress = lists:zip3(tuple_to_list(Addr), tuple_to_list(NetMask), DestIpAddress),
    Func = fun(Elm) -> matchNetMaskAddress(Elm) end,
    IsNetMask = lists:all(Func, NetMaskAddress),
    if
        IsNetMask ->
            true;
        true ->
            false
    end.

matchNetMaskAddress(Elm) ->
    io:format("interface:matchNetMaskAddress(Elm) ~n"),
    {NetOctet, Mask, SendOctet} = Elm,
    NetOctetMask = NetOctet band Mask,
    SendOctetMask = SendOctet band Mask,
    if
        NetOctetMask == SendOctetMask ->
            true;
        true ->
            false
    end.
