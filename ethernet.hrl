-define(TYPE_IPv4, 16#0800).
-define(TYPE_ARP, 16#0806).

-record(ethernetHeader, {
    sourceMacAddress,
    destMacAddress,
    type
}).
