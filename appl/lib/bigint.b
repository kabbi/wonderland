implement bigint;

include "sys.m";
    sys: Sys;
include "keyring.m";
    keyring: keyring;
include "encoding.m";
    base32: Encoding;
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


bigint.text(k: ref bigint): string
{
    return sys->sprint("key(%s)", base32->enc(k.data));
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
bigint.inc(k: self bigint): bigint
{
    carry := 1;
    for (i := len k.data - 1; i >= 0 && carry != 0; i++)
    {
        k.data[i]++;
        carry = (k.data[i] == 0);
    }
    return k;
}
bigint.dec(k: self bigint): bigint
{
    carry := 1;
    for (i := len k.data - 1; i >= 0 && carry != 0; i++)
    {
        k.data[i]--;
        carry = (k.data[i] == 16rFF);
    }
    return k;
}
bigint.halve(k: self bigint): bigint
{
    carry := 0, t := 0;
    for (i := 0; i < len k.data; i++)
    {
        t = ((k.data & 1) == 0);
        k.data[i] = (k.data[i] >> 1) | carry;
        carry = byte (t << 7);
    }
}
