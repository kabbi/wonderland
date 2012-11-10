bigint: module
{
    PATH: con "/dis/lib/bigint.dis";
    
    bigint: adt {
		data: array of byte;
        
		text: fn(nil: self bigint): string;
		generate: fn(): bigint;

        lt: fn(nil: self bigint, other: bigint): int;
        gt: fn(nil: self bigint, other: bigint): int;
        inc: fn(nil: self bigint): bigint;
        dec: fn(nil: self bigint): bigint;
        halve: fn(nil: self bigint): bigint;
	};

    init: fn();
}
