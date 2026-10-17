def native(v):
    return v.to_py() if hasattr(v,'to_py') else v
class Store:
    def __init__(self,binding): self.binding=binding
    def stmt(self,sql,args):
        s=self.binding.prepare(sql)
        return s.bind(*args) if args else s
    async def first(self,sql,*args): return native(await self.stmt(sql,args).first())
    async def all(self,sql,*args):
        r=native(await self.stmt(sql,args).all())
        return native(r['results'] if isinstance(r,dict) else r.results)
    async def batch(self,items): return await self.binding.batch([self.stmt(sql,args) for sql,args in items])
