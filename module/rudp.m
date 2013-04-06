Rudp: module
{
    # data, timeout, retry count
    new: fn(connfd: ref Sys->FD, tchan: chan of (array of byte, int, int));
    init: fn();
};
