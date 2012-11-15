implement Bigkey;

include "sys.m";
    sys: Sys;
include "keyring.m";
    keyring: Keyring;
include "encoding.m";
    base16: Encoding;
include "security.m";
    random: Random;

include "bigkey.m";

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


Key.text(k: self Key): string
{
    return sys->sprint("key(%s)", base16->enc(k.data));
}
Key.generate(): Key
{
    # TODO: replace NotQuiteRandom with ReallyRandom
    # TODO: maybe really use sha1 here? to maintain good hash-like distribution
    data := random->randombuf(random->NotQuiteRandom, BB);
    return Key(data);
}
Key.lt(k: self Key, o: Key): int
{
    for (i := 0; i < len k.data; i++)
        if (k.data[i] != o.data[i])
            return k.data[i] < o.data[i];
    return 0;
}
Key.gt(k: self Key, o: Key): int
{
    for (i := 0; i < len k.data; i++)
        if (k.data[i] != o.data[i])
            return k.data[i] > o.data[i];
    return 0;
}
Key.eq(k: self Key, o: Key): int
{
    return !k.lt(o) && !k.gt(o);
}
Key.inc(b: self Key): Key
{
    k := Key(array[BB] of { * => byte 0 });
    k.data[:] = b.data[:];
    carry := 1;
    for (i := len k.data - 1; i >= 0 && carry != 0; i--)
    {
        k.data[i]++;
        carry = (k.data[i] == byte 0);
    }
    return k;
}
Key.dec(b: self Key): Key
{
    k := Key(array[BB] of { * => byte 0 });
    k.data[:] = b.data[:];
    carry := 1;
    for (i := len k.data - 1; i >= 0 && carry != 0; i--)
    {
        k.data[i]--;
        carry = (k.data[i] == byte 16rFF);
    }
    return k;
}
Key.halve(b: self Key): Key
{
    k := Key(array[BB] of { * => byte 0 });
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
Key.subtract(s: self Key, b: Key): Key
{
    a := Key(array[BB] of { * => byte 0 });
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
