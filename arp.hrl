% 
% arp header
%

-define(TYPE_ETHERNET, 16#0001).
-define(TYPE_AMATEUR_RADIO_AX_25, 16#0003).
-define(TYPE_TOKEN_LINK, 16#0004).
-define(TYPE_IEEE802_X, 16#0006).
-define(TYPE_FRAME_RELAY, 16#000F).
-define(TYPE_ATM, 16#0010).

-define(ARP_TYPE_STATIC, static).
-define(ARP_TYPE_DYNAMIC, dynamic).

-record(arpHeader, {
    hardwareType,
    protocol,
    addressLen,
    protocolLen,
    operationCode,
    sourceMacAddress,
    sourceIPAddress,
    destMacAddress,
    destIPAddress
}).

-record(arpTable, {
    sourceIpAddress,
    macAddress,
    ipAddress,
    type
}).
