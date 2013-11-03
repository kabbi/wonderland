Hashtable: module{
	PATH: con "/dis/lib/hashtable.dis";
	fun1, fun2: fn(s:string,n:int):int;

	HashNode: adt[T]{
		key:string;
		val:T;  # insert() can update contents
	};
	HashTable: adt[T]{
	    syncpid: int;
        syncchan: chan of int;
        
        acquire: fn(h:self ref HashTable);
        release: fn(h:self ref HashTable);
        
		a:	array of list of HashNode[T];
		find:	fn(h:self ref HashTable, key:string):T;
		insert:	fn(h:self ref HashTable, key:string, val:T);
		delete:	fn(h:self ref HashTable, key:string);
		all:	fn(h:self ref HashTable): list of HashNode[T];
		destroy:    fn(h:self ref HashTable);
	};
	init: fn();
	new: fn[T](size:int, elem:T):ref HashTable[T];
	snew: fn[T](size:int, elem:T):ref HashTable[T];
};
