# ehg@research.bell-labs.com 14Dec1996
implement Hashtable;

include "sys.m";
    sys: Sys;
include "hashtable.m";

init()
{
    sys = load Sys Sys->PATH;
}

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
	return ref HashTable[T](0, nil, array[size] of list of HashNode[T]);
}

snew[T](size: int, elem: T):ref HashTable[T]
{
    syncchan := chan of int;
    spawn synchronizer(syncchan);
    pid := <-syncchan;
    return ref HashTable[T](pid, syncchan, array[size] of list of HashNode[T]);
}

HashTable[T].find(h: self ref HashTable, key: string): T
{
    h.acquire();
	j := fun1(key,len h.a);
	for(q := h.a[j]; q!=nil; q = tl q){
		if((hd q).key==key) {
		    h.release();
			return (hd q).val;
		}
	}
	h.release();
	return nil;
}

HashTable[T].insert(h: self ref HashTable, key: string, val: T)
{
    h.acquire();
	j := fun1(key,len h.a);
	for(q := h.a[j]; q!=nil; q = tl q){
		if((hd q).key==key){
			p := (hd q).val;
			p = val;
			h.release();
			return;
		}
	}
	h.a[j] = HashNode(key,val) :: h.a[j];
	h.release();
}

HashTable[T].delete(h:self ref HashTable, key:string)
{
    h.acquire();
	j := fun1(key,len h.a);
	dl:list of HashNode[T]; dl = nil;
	for(q := h.a[j]; q!=nil; q = tl q){
		if((hd q).key!=key)
			dl = (hd q) :: dl;
	}
	h.a[j] = dl;
	h.release();
}

HashTable[T].all(h:self ref HashTable): list of HashNode
{
    h.acquire();
	dl:list of HashNode[T]; dl = nil;
	for(j:=0; j<len h.a; j++)
		for(q:=h.a[j]; q!=nil; q = tl q)
			dl = (hd q) :: dl;
	h.release();
	return dl;
}

HashTable[T].acquire(h:self ref HashTable)
{
    if (h.syncchan != nil)
        <-h.syncchan;
}
HashTable[T].release(h:self ref HashTable)
{
    if (h.syncchan != nil)
        h.syncchan <-= 1;
}

HashTable[T].destroy(h:self ref HashTable)
{
    if (h.syncchan != nil)
        return;
    fd := sys->open("#p/" + (string h.syncpid) + "/ctl", sys->OWRITE);
    if(fd != nil)
        sys->fprint(fd, "kill");
}

synchronizer(syncchan: chan of int)
{
    syncchan <-= sys->pctl(0, nil);
    
    while (1) {
        syncchan <-= 1;
        <-syncchan;
    }
}
