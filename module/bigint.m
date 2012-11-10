bigint: module
{
    PATH:	con "/dis/lib/bigint.dis";
    
    Key: adt {
		data: array of byte;
        
		text: fn(nil: self ref Key): string;
		generate: fn(): Key;
        lt: fn(nil: self ref Key, other: ref Key): int;
        gt: fn(nil: self ref Key, other: ref Key): int;
        inc: fn(nil: self ref Key): Key;
        dec: fn(nil: self ref Key): Key;
        halve: fn(nil: self ref Key): Key;
	};

    init:	fn();
}
