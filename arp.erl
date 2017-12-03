-module(arp).
-export([main/3, parseARP/1, to_binary/1]).

-define(ETH_P_IP, 16#0008).
-define(ETH_P_ALL, 16#0300).
-include("ethernet.hrl").
-include("arp.hrl").

main(FD, ArpTable, Interfaces) ->
    io:format("start arp process ~n"),
    receive
        {From, requestMacAddress, RequestIp} ->
            io:format("request IP address :~p~n",[RequestIp]),
            Dest = lists:filter(fun(Elm) -> searchIPARPTable(Elm, RequestIp) end, ArpTable),
            if
                Dest == [] ->
                    io:format(" -------- dest empty ~n"),
                    broadcastARP(FD, RequestIp, Interfaces),
                    true;
                length(Dest) == 1 ->
                    io:format(" ------------ dest is ~w~n", [Dest]),
                    From ! {responseMacAddress, Dest},
                    true;
                true ->
                    io:format(" ----------- not ~w~n ", [Dest]),
                    [DestOne |_ ] = Dest,
                    From ! {responseMacAddress, [DestOne]},
                    false
            end,

            main(FD, ArpTable, Interfaces);

        {From, responseMessage, Ethernet, ARPHeader} ->
            io:format("response arp message ethernet  : ~w~n", [Ethernet]),
            io:format("response arp message arp header : ~w~n", [ARPHeader]),

            AppendTable = #arpTable{
                            macAddress=binary_to_list(ARPHeader#arpHeader.sourceMacAddress),
                            ipAddress=binary_to_list(ARPHeader#arpHeader.sourceIPAddress)
                          },
            io:format("arp table : ~w~n", [AppendTable]),
            self() ! {From, responseMacAddress, AppendTable#arpTable.macAddress},
            IsARPTable = lists:any(fun(Elm) -> existARPTable(Elm, AppendTable) end, ArpTable),
            if
                IsARPTable ->
                    ResultArpTable = ArpTable;
                true ->
                    ResultArpTable = lists:append([ArpTable, [AppendTable]])
            end,
            io:format(" result arp table : ~w~n", [ResultArpTable]),
            main(FD, ResultArpTable, Interfaces);

        {From, responseMacAddress, MacAddress} ->
            io:format("responseMacAddress ~n"),
            io:format(" mac address  : ~w~n", [MacAddress]),
            Dest = lists:filter(fun(Elm) -> searchMacARPTable(Elm, MacAddress) end, ArpTable),
            if
                length(Dest) == 1 ->
                    From ! {responseMacAddress, Dest},
                    true;
                true ->
                    io:format(" ----------- not ~w~n ", [Dest]),
                    false
            end,
            main(FD, ArpTable, Interfaces);

        Other ->
            io:format("arp main not supported : ~p~n",[Other]),
            main(FD, ArpTable, Interfaces)
    end.

existARPTable(ArpTable, AppendTable) ->
    if
        ArpTable#arpTable.macAddress == AppendTable#arpTable.macAddress ->
            true;
        true ->
            false
    end.

searchIPARPTable(Elm, RequestIp) ->
    io:format(" search ip address arp table : ~w~n", [Elm#arpTable.ipAddress]),
    io:format(" search ip address request address : ~w~n", [RequestIp]),
    if
        Elm#arpTable.ipAddress =:= RequestIp ->
            true;
        true ->
            false
    end.

searchMacARPTable(Elm, RequestMac) ->
    io:format(" search mac address arp table : ~w~n", [Elm#arpTable.macAddress]),
    io:format(" search mac address request address : ~w~n", [RequestMac]),
    if
        Elm#arpTable.macAddress =:= RequestMac ->
            io:format("search mac address table true ~n"),
            true;
        true ->
            io:format("search mac address table false ~n"),
            false
    end.

broadcastARP(FD, IPAddress, Interfaces) ->
    lists:foreach(fun(Elm) -> broadcastARPRequest(FD, IPAddress, Elm) end, Interfaces).

broadcastARPRequest(_, IPAddress, Interface) ->
    io:format("interface : ~w~n", [Interface]),
    io:format("IPAddress : ~w~n", [IPAddress]),
    {IfName, Eopt} = Interface,
    [{flags, _}, {hwaddr, Hwaddr}, {addr, Addr}, {netmask, NetMask}, {broadaddr, _}] = Eopt,
    NetMaskAddress = lists:zip3(tuple_to_list(Addr), tuple_to_list(NetMask), IPAddress),
    io:format("list :  ~w~n", [NetMaskAddress]),
    Func = fun(Elm) -> main:matchNetMaskAddress(Elm) end,
    IsNetMask = lists:all(Func, NetMaskAddress),
    if
        IsNetMask ->
            matchSendBroadcastAddress(Hwaddr, IfName, IPAddress, Addr),
            true;
        true ->
            false
    end.

matchSendBroadcastAddress(Hwaddr, IfName, IPAddress, Addr) ->
    io:format("match send broad cast address ~n"),
    Ethernet = ethernet:to_binary(#ethernetHeader{sourceMacAddress=Hwaddr, destMacAddress=[16#ff, 16#ff, 16#ff, 16#ff, 16#ff, 16#ff], type=?TYPE_ARP}),
    ARPHeader = arp:to_binary(#arpHeader{
        hardwareType=?TYPE_ETHERNET, protocol=16#0800, addressLen=16#06, protocolLen=16#04,
        operationCode=16#0001,
        sourceMacAddress=Hwaddr, sourceIPAddress=tuple_to_list(Addr),
        destMacAddress=[16#00, 16#00, 16#00, 16#00, 16#00, 16#00], destIPAddress=IPAddress
    }),
    {ok, FD} = procket:open(0, [
            {protocol, ?ETH_P_IP},
            {type, raw},
            {family, packet},
            {interface, IfName}
    ]),
    ok = packet:bind(FD, packet:ifindex(FD,IfName)),
    erlang:open_port({fd, FD, FD}, [binary, stream]),
    Buf = <<Ethernet/bitstring, ARPHeader/bitstring>>,
    io:format(" ---- send buf : ~w~n", [Buf]),
    case procket:sendto(FD, Buf) of
        ok ->
            io:format("send : ok~n");
        {ok, Size} ->
            io:format("send size to : ~w~n", [Size]);
        {Case, Other} ->
            io:format("send to : ~w : ~w~n", [Case, Other])
    end.


parseARP(Buf) ->
    <<HardwareType:16, Protocol:16,
        AddressLen:8, ProtocolLen:8, OperationCode:16,
        SourceMacAddress:48, SourceIPAddress:32,
        DestMacAddress:48, DestIPAddress:32, Data/bitstring>> = Buf,

    ARPHeader = #arpHeader{
        hardwareType=HardwareType, protocol=Protocol,
        addressLen=AddressLen, protocolLen=ProtocolLen, operationCode=OperationCode, 
        sourceMacAddress=binary:encode_unsigned(SourceMacAddress), sourceIPAddress=binary:encode_unsigned(SourceIPAddress),
        destMacAddress=binary:encode_unsigned(DestMacAddress), destIPAddress=binary:encode_unsigned(DestIPAddress)
    },
    {ARPHeader, Data}. 

to_binary(Record) ->
    HardwareType = binary:encode_unsigned(Record#arpHeader.hardwareType),
    Protocol = binary:encode_unsigned(Record#arpHeader.protocol),
    AddressLen = binary:encode_unsigned(Record#arpHeader.addressLen),
    ProtocolLen = binary:encode_unsigned(Record#arpHeader.protocolLen),
    OperationCode = binary:encode_unsigned(Record#arpHeader.operationCode),
    SourceMacAddress = list_to_binary(Record#arpHeader.sourceMacAddress),
    SourceIPAddress = list_to_binary(Record#arpHeader.sourceIPAddress),
    DestMacAddress = list_to_binary(Record#arpHeader.destMacAddress),
    DestIPAddress = list_to_binary(Record#arpHeader.destIPAddress),

    <<
        00,
        HardwareType/bitstring,
        Protocol/bitstring,
        AddressLen/bitstring,
        ProtocolLen/bitstring,
        00,
        OperationCode/bitstring,
        SourceMacAddress/bitstring,
        SourceIPAddress/bitstring,
        DestMacAddress/bitstring,
        DestIPAddress/bitstring
    >>.
