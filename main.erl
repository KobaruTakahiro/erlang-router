-module(main).
-export([main/0]).

-define(ETH_P_IP, 16#0008).
-define(ETH_P_ALL, 16#0300).
-include("ethernet.hrl").
-include("ip.hrl").

main() ->
    init(),
    {ok, FD} = procket:open(0, [
            {protocol, ?ETH_P_IP},
            {type, raw},
            {family, packet}
        ]),
    ArpProc = spawn(arp, main, [FD, []]),
    loop(FD, ArpProc).

init() ->
    {ok, IfLists} = inet:getifaddrs(),
    ListenInterfaces = lists:filter(fun(Elm) -> interfaceList(Elm) end, IfLists),
    io:format("~w~n", [ListenInterfaces]).

interfaceList(Elm) ->
    {Name, _} = Elm,
    string:find(Name, "eth"),
    string:find(Name, "eth") =/= nomatch.


loop(FD, ArpProc) ->
    {Result, Buf} = procket:recvfrom(FD, 4096),
    if
        Result == error ->
            false;
        Result == ok ->
            io:format("~n"),
            io:format("~w~n", [Buf]),
            io:format("~n"),
            sendMessage(ArpProc, Buf);
        true ->
            true
    end,
    loop(FD, ArpProc).

sendMessage(ArpProc, Buf) ->
    Data = parseBuf(Buf),
    ArpProc ! {request, Data},
    true.

% parse binary data
parseBuf(Buf) ->
    io:format("buf :~w~n ", [Buf]),
    {Ethernet, IPLayerBuf} = parseEthernet(Buf),
    IPLayer = case Ethernet#ethernetHeader.type of
        ?TYPE_IPv4 ->
            {IPHeader, _} = parseIPv4(IPLayerBuf),
            io:format("ip header ~w~n", [IPHeader]);
        ?TYPE_ARP ->
            {_, _} = parseARP(IPLayerBuf)
    end,
    io:format("ip layer : ~w~n ", [IPLayer]).

% parse ethernet frame
parseEthernet(Buf) ->
    <<DestMacAddress:48, SourceMacAddress:48, Type:16, Data/bitstring>> = Buf,

    Ethernet = #ethernetHeader{
        sourceMacAddress=binary:encode_unsigned(SourceMacAddress),
        destMacAddress=binary:encode_unsigned(DestMacAddress),
        type=Type
    },

    {Ethernet, Data}.

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
        sourceAddress=binary:encode_unsigned(SourceAddress), destAddress=binary:encode_unsigned(DestAddress)
    },
    {IPHeader, Data}.

parseARP(Buf) ->
    io:format("buf ~w~n", [Buf]),
    true.