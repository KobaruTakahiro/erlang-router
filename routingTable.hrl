-define(DYRECT, 0).
-define(STATIC, 1).
-define(DEFAULT_ROUTE, 255).

-record(routingTable, {
    destination,      % destination ip address
    routeMask,        % route net mask
    nextHop,          % next hop ip address
    interface,        % interface
    metric,           % destination metric
    routeType,        % route type static or dynamic
    sourceOfRoute,    % routing protocol
    routeAge,         % route age count
    routeInformation, % other route information
    mtu               % MTU
}).
