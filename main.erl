-module(main).
-export([main/0, followPacket/3, matchNetMaskAddress/1]).

-define(ETH_P_IP, 16#0008).
-define(ETH_P_ALL, 16#0300).
-include("ethernet.hrl").
-include("ip.hrl").
-include("arp.hrl").

init() ->
    {ok, IfLists} = inet:getifaddrs(),
    Listen = lists:filter(fun(Elm) -> interfaceList(Elm) end, IfLists),
    Listen.

main() ->
    ListenInterfaces = init(),
    io:format("Listen :  ~w~n", [ListenInterfaces]),
    {ok, FD} = procket:open(0, [
            {protocol, ?ETH_P_ALL},
            {type, raw},
            {family, packet}
        ]),
    ArpProc = spawn(arp, main, [FD, [], ListenInterfaces]),
    loop(FD, ArpProc).

interfaceList(Elm) ->
    {Name, _} = Elm,
    string:find(Name, "eth") =/= nomatch.


loop(FD, ArpProc) ->
    {Result, Buf} = procket:recvfrom(FD, 4096),
    if
        Result == error ->
            false;
        Result == ok ->
            {Ethernet, IPLayer, _} = parseBuf(Buf),
            if
                IPLayer == false ->
                    true;
                true ->
                    Dest = lists:filter(fun(Elm) -> searchInterface({ethernet, Elm, Ethernet}) end, getInterface()),
                    io:format("dest ~w~n", [Dest]),
                    io:format("dest length ~w~n", [length(Dest)]),
                    if
                        length(Dest) == 1 ->
                            _ = spawn(main, followPacket, [ArpProc, Ethernet, IPLayer]);
                        true ->
                            true
                    end
            end;
        true ->
            true
    end,
    loop(FD, ArpProc).

followPacket(ArpProc, Ethernet, IPLayer) ->
    io:format("followPacket ~n"),
    io:format("ethernet : ~w~n", [Ethernet]),
    io:format("ip layer : ~w~n", [IPLayer]),
    case Ethernet#ethernetHeader.type of
        ?TYPE_IPv4 ->
            io:format("IPv4 ~n"),
            DestARPTable = fetchSendMacAddress(ArpProc, IPLayer),
            lists:foreach(fun(Elm) -> sendMessageIP(Elm, Ethernet, IPLayer) end, DestARPTable);
        ?TYPE_ARP ->
            io:format("ARP ~n"),
            ArpProc ! {self(), responseMessage, Ethernet, IPLayer}
    end.

getInterface() ->
    {ok, IfLists} = inet:getifaddrs(),
    Listen = lists:filter(fun(Elm) -> interfaceList(Elm) end, IfLists),
    Listen.

searchInterface({ethernet, Interface, Ethernet}) ->
    io:format("interface : ~w~n", [Interface]),
    io:format("Ethernet :  ~w~n", [Ethernet]),
    searchInterface({macAddress, Interface, Ethernet#ethernetHeader.destMacAddress});

searchInterface({macAddress, Interface, DestMacAddress}) ->
    {_, Eopt} = Interface,
    [{flags, _}, {hwaddr, Hwaddr}, {addr, _}, {netmask, _}, {broadaddr, _}] = Eopt,
    io:format("search interface mac address ~n"),
    io:format("Interface : ~w~n", [Interface]),
    io:format("DestMacAddress : ~w~n", [DestMacAddress]),
    if
        Hwaddr =:= DestMacAddress ->
            true;
        true ->
            false
    end;

searchInterface({ipNetMaskAddress, Interface, DestIpAddress}) ->
    {_, Eopt} = Interface,
    [{flags, _}, {hwaddr, _}, {addr, Addr}, {netmask, NetMask}, {broadaddr, _}] = Eopt,
    NetMaskAddress = lists:zip3(tuple_to_list(Addr), tuple_to_list(NetMask), DestIpAddress),
    io:format("Net Mask Address : ~w~n", [NetMaskAddress]),
    Func = fun(Elm) -> matchNetMaskAddress(Elm) end,
    IsNetMask = lists:all(Func, NetMaskAddress),
    if
        IsNetMask ->
            true;
        true ->
            false
    end.

matchNetMaskAddress(Elm) ->
    {NetOctet, Mask, SendOctet} = Elm,
    NetOctetMask = NetOctet band Mask,
    SendOctetMask = SendOctet band Mask,
    io:format("net octet mask : ~w~n", [NetOctetMask]),
    io:format("send octet mask : ~w~n", [SendOctetMask]),
    if
        NetOctetMask == SendOctetMask ->
            io:format(" octet true ~n"),
            true;
        true ->
            io:format(" octet false ~n"),
            false
    end.

sendMessageIP(DestARPTable, Ethernet, IPLayer) ->
    io:format("send message ip ~n"),
    io:format("Dest ARP Table :  ~w~n", [DestARPTable]),
    io:format("ethernet :  ~w~n", [Ethernet]),
    io:format("ip layer :  ~w~n", [IPLayer]),
    DestIPAddress = DestARPTable#arpTable.ipAddress,
    Source = lists:filter(fun(Elm) -> searchInterface({ipNetMaskAddress, Elm, DestIPAddress}) end, getInterface()),
    io:format("Source interface :  ~w~n", [Source]),
    if
        length(Source) == 1 ->
            lists:foreach(fun(Elm) -> sendMessageInterface(Elm, DestARPTable, IPLayer) end, Source),
            true;
        true ->
            false
    end.

sendMessageInterface(Interface, DestARPTable, IPLayer) ->
    {IfName, Eopt} = Interface,
    [{flags, _}, {hwaddr, HwAddr}, {addr, _}, {netmask, _}, {broadaddr, _}] = Eopt,
    DestMacAddress = DestARPTable#arpTable.macAddress, 
    Ethernet = ethernet:to_binary(#ethernetHeader{sourceMacAddress=HwAddr, destMacAddress=DestMacAddress , type=?TYPE_IPv4}),
    {ok, FD} = procket:open(0, [
            {protocol, ?ETH_P_IP},
            {type, raw},
            {family, packet},
            {interface, IfName}
    ]),
    ok = packet:bind(FD, packet:ifindex(FD,IfName)),
    erlang:open_port({fd, FD, FD}, [binary, stream]),
    io:format("Ethernet : ~w~n", [Ethernet]),
    io:format("IPLayer : ~w~n", [IPLayer]),
    IpHeader = IPLayer#ip4Header.binary,
    Buf = <<Ethernet/bitstring, IpHeader/bitstring>>,
    io:format(" ---- send message interface buf : ~w~n", [Buf]),
    case procket:sendto(FD, Buf) of
        ok ->
            io:format("send : ok~n");
        {ok, Size} ->
            io:format("send size to : ~w~n", [Size]);
        {Case, Other} ->
            io:format("send to : ~w : ~w~n", [Case, Other])
    end.

fetchSendMacAddress(ArpProc, IPLayer) ->
    ArpProc ! {self(), requestMacAddress, IPLayer#ip4Header.destAddress},
    receive
        {responseMacAddress, ArpTable} ->
            io:format("----------- send message arp table :  ~w~n", [ArpTable]),
            ArpTable;
        Other ->
            io:format("send message not supported:~p~n",[Other]),
            false
    end.

% parse binary data
parseBuf(Buf) ->
    io:format(" ---- receive buf :~w~n ", [Buf]),
    {Ethernet, IPLayerBuf} = ethernet:parse(Buf),
    case Ethernet#ethernetHeader.type of
        ?TYPE_IPv4 ->
            {IPHeader, Data} = parseIPv4(IPLayerBuf),
            io:format("ip header ~w~n", [IPHeader]),
            {Ethernet, IPHeader, Data};
        ?TYPE_ARP ->
            {ARPHeader, Data} = arp:parseARP(IPLayerBuf),
            {Ethernet, ARPHeader, Data};
        Other ->
            io:format("Other ip type : ~w~n", [Other]),
            {Ethernet, false, false}
    end.

% parse IP v4 header
parseIPv4(Buf) ->
    <<Version:4, HeaderLen:4, Service:8, TotalLen:16,
        Identification:16, Flags:3, Fragment:13,
        Ttl:8, Protocol:8, Checksum:16,
        SourceAddress:32, DestAddress:32, Data/bitstring>> = Buf,

    IPHeader = #ip4Header{
        version=Version, headerLen=HeaderLen, service=Service, totalLen=TotalLen,
        identification=Identification, flags=Flags, fragment=Fragment,
        ttl=Ttl, protocol=Protocol, checksum=Checksum,
        sourceAddress=binary_to_list(binary:encode_unsigned(SourceAddress)), destAddress=binary_to_list(binary:encode_unsigned(DestAddress)),
        binary = Buf
    },
    {IPHeader, Data}.
