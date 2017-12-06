-module(main).
-export([main/0, followPacket/4]).

-define(ETH_P_IP, 16#0008).
-define(ETH_P_ALL, 16#0300).
-include("ethernet.hrl").
-include("ip.hrl").
-include("arp.hrl").

main() ->
    io:format("main:main()~n"),
    ListenInterfaces = interface:getInterface(),
    io:format("interface : ~w~n", [ListenInterfaces]),
    {ok, FD} = procket:open(0, [
            {protocol, ?ETH_P_ALL},
            {type, raw},
            {family, packet}
        ]),
    % arp main proccess
    ArpProc = spawn(arp, main, [FD, [], ListenInterfaces]),
    RoutingTableProc = spawn(routingTable, main, [[]]),
    loop(FD, ArpProc, RoutingTableProc).

loop(FD, ArpProc, RoutingTableProc) ->
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
                    % search receive interface
                    % whether the recieved packet is itself or not
                    Dest = lists:filter(fun(Elm) -> interface:searchInterface({ethernet, Elm, Ethernet}) end, interface:getInterface()),
                    if
                        length(Dest) == 1 ->
                            _ = spawn(main, followPacket, [ArpProc, RoutingTableProc, Ethernet, IPLayer]);
                        true ->
                            true
                    end
            end;
        true ->
            true
    end,
    loop(FD, ArpProc, RoutingTableProc).

followPacket(ArpProc, RoutingTableProc, Ethernet, IPLayer) ->
    io:format("main:followPacket(ArpProc, Ethernet, IPLayer) ~n"),
    io:format("    Ethernet :  ~w~n", [Ethernet]),
    io:format("    IPLayer  :  ~w~n", [IPLayer]),
    case Ethernet#ethernetHeader.type of
        ?TYPE_IPv4 ->
            case fetchMacAddress(ArpProc, RoutingTableProc, IPLayer#ip4Header.destAddress) of
                {success, DestARPTable} ->
                    lists:foreach(fun(Elm) -> sendMessageIP(Elm, Ethernet, IPLayer) end, DestARPTable);
                {error, _} ->
                    false
            end;
        ?TYPE_ARP ->
            ArpProc ! {self(), responseMessage, Ethernet, IPLayer}
    end.

sendMessageIP(ARPTableRecord, _, IPLayer) ->
    io:format("main:sendMessageIP(ARPTableRecord, Ethernet, IPLayer) ~n"),
    DestIPAddress = ARPTableRecord#arpTable.ipAddress,
    Source = lists:filter(fun(Elm) -> interface:searchInterface({ipNetMaskAddress, Elm, DestIPAddress}) end, interface:getInterface()),
    if
        length(Source) == 1 ->
            lists:foreach(fun(Elm) -> sendMessageInterface(Elm, ARPTableRecord, IPLayer) end, Source),
            true;
        true ->
            false
    end.

sendMessageInterface(Interface, ARPTableRecord, IPLayer) ->
    io:format("main:sendMessageInterface(Interface, ARPTableRecord, IPLayer) ~n"),
    io:format("    Interface : ~w~n", [Interface]),
    io:format("    ARPTableRecord : ~w~n", [ARPTableRecord]),
    io:format("    IPLayer : ~w~n", [IPLayer]),
    {IfName, Eopt} = Interface,
    [{flags, _}, {hwaddr, HwAddr}, {addr, _}, {netmask, _}, {broadaddr, _}] = Eopt,
    DestMacAddress = ARPTableRecord#arpTable.macAddress, 
    Ethernet = ethernet:to_binary(#ethernetHeader{sourceMacAddress=HwAddr, destMacAddress=DestMacAddress , type=?TYPE_IPv4}),
    {ok, FD} = procket:open(0, [
            {protocol, ?ETH_P_IP},
            {type, raw},
            {family, packet},
            {interface, IfName}
    ]),
    ok = packet:bind(FD, packet:ifindex(FD,IfName)),
    erlang:open_port({fd, FD, FD}, [binary, stream]),
    IpHeader = IPLayer#ip4Header.binary,
    Buf = <<Ethernet/bitstring, IpHeader/bitstring>>,
    io:format("    send buffer : ~w~n", [Buf]),
    case procket:sendto(FD, Buf) of
        ok ->
            true;
        {ok, _} ->
            true;
        {_, _} ->
            false
    end.

fetchMacAddress(ArpProc, RoutingTableProc, DestIPAddress) ->
    io:format("main:fetchMacAddress(ArpProc, IPLayer) ~n"),
    io:format("    DestIPAddress : ~w~n", [DestIPAddress]),
    Dest = lists:filter(fun(Elm) -> interface:searchInterface({ipNetMaskAddress, Elm, DestIPAddress}) end, interface:getInterface()),
    io:format("    dest interface : ~w~n", [Dest]),
    if
        Dest == [] ->
            searchRoutingTable(ArpProc, RoutingTableProc, DestIPAddress);
        length(Dest) == 1 ->
            connectedIPAddress(ArpProc, DestIPAddress);
        true ->
            false
    end.

searchRoutingTable(ArpProc, RoutingTableProc, DestIPAddress) ->
    io:format("main:searchRoutingTable(ArpProc, RoutingTableProc, DestIPAddress) ~n"),
    RoutingTableProc ! {self(), requestIP, DestIPAddress},
    receive
        {responseIP, DestAddress} ->
            io:format("main:fetchMacAddress receive {responseIP, DestAddress} ~n"),
            fetchArpTableRecord(ArpProc, DestAddress);
        {error, Message} ->
            io:format("sendMessageIP error : ~w~n", [Message]),
            {error, false}
    end.

connectedIPAddress(ArpProc, DestAddress) ->
    io:format("main:connectedIPAddress(ArpProc, DestAddress) ~n"),
    fetchArpTableRecord(ArpProc, DestAddress).

fetchArpTableRecord(ArpProc, DestIPAddress) ->
    io:format("main:fetchArpTableRecord(ArpProc, IPLayer) ~n"),
    ArpProc ! {self(), requestMacAddress, DestIPAddress},
    receive
        {responseMacAddress, ArpTable} ->
            io:format("main:fetchArpTableRecord receive {responseMacAddress, ArpTable} ~n"),
            {success, ArpTable};
        _ ->
            {error, false}
    end.


% parse binary data
parseBuf(Buf) ->
    io:format("main:parseBuf(Buf)~n "),
    {Ethernet, IPLayerBuf} = ethernet:parse(Buf),
    case Ethernet#ethernetHeader.type of
        ?TYPE_IPv4 ->
            {IPHeader, Data} = parseIPv4(IPLayerBuf),
            {Ethernet, IPHeader, Data};
        ?TYPE_ARP ->
            {ARPHeader, Data} = arp:parseARP(IPLayerBuf),
            {Ethernet, ARPHeader, Data};
        _ ->
            {Ethernet, false, false}
    end.

% parse IP v4 header
parseIPv4(Buf) ->
    io:format("main:parseIPv4(Buf)~n "),
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
