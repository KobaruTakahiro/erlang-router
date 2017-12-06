-define(TYPE_IPv4, 16#0800).
-define(TYPE_ARP, 16#0806).
-define(TYPE_AoE, 16#88A2).

-record(ethernetHeader, {
    sourceMacAddress,
    destMacAddress,
    type
}).
