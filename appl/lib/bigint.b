implement Bigint;

include "sys.m";
    sys: Sys;
include "keyring.m";
    keyring: Keyring;
include "encoding.m";
    base16: Encoding;
include "security.m";
    random: Random;

include "bigint.m";

init()
{
    sys = load Sys Sys->PATH;
    keyring = load Keyring Keyring->PATH;
    if (keyring == nil)
    {
        sys->fprint(sys->fildes(2), "cannot load keyring: %r\n");
        raise "fail:bad module";
    }
    base16 = load Encoding Encoding->BASE16PATH;
    if (base16 == nil)
    {
        sys->fprint(sys->fildes(2), "cannot load base16: %r\n");
        raise "fail:bad module";
    }
    random = load Random Random->PATH;
    if (random == nil)
    {
        sys->fprint(sys->fildes(2), "cannot load random: %r\n");
        raise "fail:bad module";
    }
}


bigint.text(k: self bigint): string
{
    return sys->sprint("key(%s)", base16->enc(k.data));
}
bigint.generate(): bigint
{
    data := array [BB] of byte;
    # TODO: replace NotQuiteRandom with ReallyRandom
    randdata := random->randombuf(random->NotQuiteRandom, RANDOMNESS);
    keyring->sha1(randdata, len randdata, data, nil);
    return bigint(data);
}
bigint.lt(k: self bigint, o: bigint): int
{
    for (i := 0; i < len k.data; i++)
        if (k.data[i] != o.data[i])
            return k.data[i] < o.data[i];
    return 0;
}
bigint.gt(k: self bigint, o: bigint): int
{
    for (i := 0; i < len k.data; i++)
        if (k.data[i] != o.data[i])
            return k.data[i] > o.data[i];
    return 0;
}
bigint.inc(b: self bigint): bigint
{
    k := bigint(array[BB] of { * => byte 0 });
    k.data[:] = b.data[:];
    carry := 1;
    for (i := len k.data - 1; i >= 0 && carry != 0; i--)
    {
        k.data[i]++;
        carry = (k.data[i] == byte 0);
    }
    return k;
}
bigint.dec(b: self bigint): bigint
{
    k := bigint(array[BB] of { * => byte 0 });
    k.data[:] = b.data[:];
    carry := 1;
    for (i := len k.data - 1; i >= 0 && carry != 0; i--)
    {
        k.data[i]--;
        carry = (k.data[i] == byte 16rFF);
    }
    return k;
}
bigint.halve(b: self bigint): bigint
{
    k := bigint(array[BB] of { * => byte 0 });
    k.data[:] = b.data[:];
    carry := byte 0;
    t: int;
    for (i := 0; i < len k.data; i++)
    {
        t = int k.data[i] & 1;
        k.data[i] = byte (k.data[i] >> 1) | carry;
        carry = byte ((byte t) << 7);
    }
    return k;
}
bigint.subtract(s: self bigint, b: bigint): bigint
{
    a := bigint(array[BB] of { * => byte 0 });
    a.data[:] = s.data[:];
    carry := byte 0;
    t: byte;
    for (i := len a.data - 1; i >= 0; i--)
    {
        t = byte (a.data[i] < (b.data[i] + carry));
        a.data[i] -= b.data[i] + carry;
        carry = t;
    }
    #TODO Throw exception in case we are out of bounds (carry != 0)
    return a;
}
