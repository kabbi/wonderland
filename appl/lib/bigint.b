implement bigint;

include "sys.m";
    sys: Sys;
include "keyring.m";
    keyring: Keyring;
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
    base32 = load Encoding Encoding->BASE32PATH;
    if (base32 == nil)
    {
        sys->fprint(sys->fildes(2), "cannot load base64: %r\n");
        raise "fail:bad module";
    }
    random = load Random Random->PATH;
    if (random == nil)
    {
        sys->fprint(sys->fildes(2), "cannot load random: %r\n");
        raise "fail:bad module";
    }
}

Key.text(k: self ref Key): string
{
    return sys->sprint("Key(%s)", base32->enc(k.data));
}
Key.generate(): Key
{
    data := array [BB] of byte;
    # TODO: replace NotQuiteRandom with ReallyRandom
    randdata := random->randombuf(random->NotQuiteRandom, RANDOMNESS);
    keyring->sha1(randdata, len randdata, data, nil);
    return Key(data);
}
Key.lt(k: self ref Key, o: ref Key): int
{
    for (i := 0; i < len k.data; i++)
        if (k.data[i] != o.data[i])
            return k.data[i] < o.data[i];
    return 0;
}
Key.gt(k: self ref Key, o: ref Key): int
{
    for (i := 0; i < len k.data; i++)
        if (k.data[i] != o.data[i])
            return k.data[i] > o.data[i];
    return 0;
}
