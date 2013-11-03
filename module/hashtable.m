Hashtable: module{
	PATH: con "/dis/lib/hashtable.dis";
	fun1, fun2: fn(s:string,n:int):int;

	HashNode: adt[T]{
		key:string;
		val:T;  # insert() can update contents
	};
	HashTable: adt[T]{
		a:	array of list of HashNode[T];
		find:	fn(h:self ref HashTable, key:string):T;
		insert:	fn(h:self ref HashTable, key:string, val:T);
		delete:	fn(h:self ref HashTable, key:string);
		all:	fn(h:self ref HashTable): list of HashNode[T];
	};
	new: fn[T](size:int, elem:T):ref HashTable[T];

	# Synchronous interface for Hashtable. Using one chan for
	# all the commands. When sending request, first int is one
	# of the commands below, when reading answer - total number
	# of returned elements. HFind and HAll always post something
	# on the chan.
	HInsert, HDelete, HFind, HAll, HDestroy: con iota;
	snew: fn[T](size:int, elem:T): chan of (int, string, T);
};

