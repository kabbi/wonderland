Rudp: module
{
    PATH:   con "/dis/lib/rudp.dis";

    # Type definitions
    TChan: type chan of (array of byte, int, int);
    RChan: type chan of array of byte;

    # Log management
    setlogfd: fn(fd: ref Sys->FD);

    # Start rudp by wrapping around connfd
    # uses tchan for input (data, timeout, retry count),
    # and rchan for output (just received raw data)
    new: fn(connfd: ref Sys->FD, tchan: TChan): RChan;

    # Call this after load
    init: fn();

    stats: fn(): string;
};
