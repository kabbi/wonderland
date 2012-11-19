Bigkey: module
{
    PATH: con "/dis/lib/bigkey.dis";
    RANDOMNESS: con 1000;
    B:      con 32;
    BB:     con B/8; # B in bytes
    
    Key: adt {
        data: array of byte;
        
        text: fn(nil: self Key): string;
        parse: fn(str: string): ref Key;
        generate: fn(): Key;

        lt: fn(nil: self Key, other: Key): int;
        gt: fn(nil: self Key, other: Key): int;
        eq: fn(nil: self Key, other: Key): int;
        inc: fn(nil: self Key): Key;
        dec: fn(nil: self Key): Key;
        subtract: fn(nil: self Key, b: Key): Key;
        halve: fn(nil: self Key): Key;
    };

    init: fn();
};
