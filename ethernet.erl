-module(ethernet).
-export([parse/1, to_list/1, to_binary/1]).

-include("ethernet.hrl").

% parse ethernet frame
parse(Buf) ->
    <<DestMacAddress:48, SourceMacAddress:48, Type:16, Data/bitstring>> = Buf,

    Ethernet = #ethernetHeader{
        sourceMacAddress=binary_to_list(binary:encode_unsigned(SourceMacAddress)),
        destMacAddress=binary_to_list(binary:encode_unsigned(DestMacAddress)),
        type=Type
    },

    {Ethernet, Data}.

% record convert to binary
to_binary(Record) ->
    DestMacAddress = list_to_binary(Record#ethernetHeader.destMacAddress),
    SourceMacAddress = list_to_binary(Record#ethernetHeader.sourceMacAddress),
    Type = binary:encode_unsigned(Record#ethernetHeader.type),
    <<
        DestMacAddress/bitstring,
        SourceMacAddress/bitstring,
        Type/bitstring
    >>.

% record convert to list
to_list(Record) ->
    lists:append([
        Record#ethernetHeader.sourceMacAddress,
        Record#ethernetHeader.destMacAddress,
        [Record#ethernetHeader.type]
    ]).
