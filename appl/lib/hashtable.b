# ehg@research.bell-labs.com 14Dec1996
implement Hashtable;

include "hashtable.m";

# from Aho Hopcroft Ullman
fun1(s:string, n:int):int
{
	h := 0;
	m := len s;
	for(i:=0; i<m; i++){
		h = 65599*h+s[i];
	}
	return (h & 16r7fffffff) % n;
}

# from Limbo compiler
fun2(s:string, n:int):int
{
	h := 0;
	m := len s;
	for(i := 0; i < m; i++){
		c := s[i];
		d := c;
		c ^= c << 6;
		h += (c << 11) ^ (c >> 1);
		h ^= (d << 14) + (d << 7) + (d << 4) + d;
	}
	return (h & 16r7fffffff) % n;
}

new[T](size: int, elem: T):ref HashTable[T]
{
	return ref HashTable[T](array[size] of list of HashNode[T]);
}

HashTable[T].find(h: self ref HashTable, key: string): T
{
	j := fun1(key,len h.a);
	for(q := h.a[j]; q!=nil; q = tl q){
		if((hd q).key==key)
			return (hd q).val;
	}
	return nil;
}

HashTable[T].insert(h: self ref HashTable, key: string, val: T)
{
	j := fun1(key,len h.a);
	for(q := h.a[j]; q!=nil; q = tl q){
		if((hd q).key==key){
			p := (hd q).val;
			p = val;
			return;
		}
	}
	h.a[j] = HashNode(key,val) :: h.a[j];
}

HashTable[T].delete(h:self ref HashTable, key:string)
{
	j := fun1(key,len h.a);
	dl:list of HashNode[T]; dl = nil;
	for(q := h.a[j]; q!=nil; q = tl q){
		if((hd q).key!=key)
			dl = (hd q) :: dl;
	}
	h.a[j] = dl;
}

HashTable[T].all(h:self ref HashTable): list of HashNode
{
	dl:list of HashNode[T]; dl = nil;
	for(j:=0; j<len h.a; j++)
		for(q:=h.a[j]; q!=nil; q = tl q)
			dl = (hd q) :: dl;
	return dl;
}
