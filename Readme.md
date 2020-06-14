# Hexrays Toolbox

Hexrays Toolbox is a script for the Hexrays Decompiler which
can be used to find code patterns within decompiled code.

Loading hr_toolbox.py with IDA (alt-f7) will make
available the "find_expr()" and "find_item()" functions
to the IDAPython CLI and the script interpreter (shift-f2).

The functions find_expr() and find_item() accept two arguments:
```
    find_item(ea, insn)
    find_expr(ea, expr)

    ea:   address of a valid function within
          the current database
    expr: lambda function

          insn/expr are lambda functions that are passed two arguments.
             1. cfunc: cfunc_t
             2. i/e:   cinsn_t/cexpr_t

          Find the cfunc_t, citem_t, cinsn_t and cexpr_t structures
          within hexrays.hpp for help and further details.
```
Please also check out the [HRDevHelper](https://github.com/patois/HRDevHelper) plugin which may assist in writing respective queries.

A simple example which finds and returns all function calls within
a current function: ```find_expr(here(), lambda cf, e: e.op is cot_call)```

## Examples:

### 1) get list of all numbers used in current function

```
query = lambda cfunc, e: e.op is cot_num
numbers = [e.numval() for e in find_expr(here(), query)]
```
### 2) get list of expressions that compare anything to zero ("x == 0")
```
         cot_eq
         /   \
      x /     \ y
(anything)  cot_num --- n.numval() == 0
```
```
query = lambda cfunc, e: e.op is cot_eq and e.y.op is cot_num and e.y.numval() is 0
l = [e for e in find_expr(here(), query)]
```
### 3) get list of function calls
```
        cot_call
         / 
      x /
 cot_obj
```
```
query = lambda cfunc, e: e.op is cot_call and e.x.op is cot_obj
l = ["%x: %s" % (e.x.obj_ea, get_name(e.x.obj_ea)) for e in find_expr(here(), query)]
```
### 4) print list of memcpy calls where "dst" argument is on stack
```
        cot_call --- arg1 is cot_var
         /           arg1 is on stack
      x /
 cot_obj --- name(obj_ea) == 'memcpy'
```
```
hits = []
query = lambda cfunc, e: (e.op is cot_call and
           e.x.op is cot_obj and
           get_name(e.x.obj_ea) == 'memcpy' and
           len(e.a) == 3 and
           e.a[0].op is cot_var and
           cfunc.lvars[e.a[0].v.idx].is_stk_var())
for ea in Functions():
    hits += ["%x:" % e.ea for e in find_expr(ea, query)]
print(hits)
```
### 5) get list of allocated and freed heaps:
```
var = malloc(num):

        cot_asg
         /  \
      x /    \ y
 cot_var    cot_call
              /
           x /
          cot_obj --- name(obj_ea) == 'malloc'

free(var):

        cot_call --- arg1 is cot_var
         /
      x /
 cot_obj --- name(obj_ea) == 'free'
```
```
ea = here()
query = lambda cfunc, e: (e.op is cot_asg
    and e.x.op is cot_var and
    e.y.op is cot_call and
    e.y.x.op is cot_obj and
    get_name(e.y.x.obj_ea) == 'malloc')
vars_allocated = [e.x.v.idx for e in find_expr(ea, query)]

query = lambda cfunc, e: (e.op is cot_call and
    e.x.op is cot_obj and
    get_name(e.x.obj_ea) == 'free' and
    len(e.a) == 1 and
    e.a[0].op is cot_var)
vars_freed = [e.a[0].v.idx for e in find_expr(ea, query)]

print("allocated:\t", sorted(vars_allocated))
print("freed:\t", sorted(vars_freed))
```
### 6) get list of calls to sprintf(str, fmt, ...) where fmt contains "%s"
```
        cot_call --- arg2 ('fmt') contains '%s'
         /
      x /
 cot_obj --- name(obj_ea) == 'sprintf'
```
```
hits = []
query = lambda cfunc, e: (e.op is cot_call and
    e.x.op is cot_obj and
    get_name(e.x.obj_ea) == 'sprintf' and
    len(e.a) >= 2 and
    e.a[1].op is cot_obj and
    is_strlit(get_flags(e.a[1].obj_ea)) and
    b'%s' in get_strlit_contents(e.a[1].obj_ea, -1, 0, STRCONV_ESCAPE))
for ea in Functions():
    hits += ["%x:" % e.ea for e in find_expr(ea, query)]
print(hits)
```
### 7) get names of functions imported with GetProcAddress
```
        cot_call --- arg2 is cot_obj
         /
      x /
 cot_obj --- name(obj_ea) == 'GetProcAddress'
```
```
from idaapi import *

hits = []
query = lambda cfunc, e: (e.op is cot_call and
    e.x.op is cot_obj and
    get_name(e.x.obj_ea) == 'GetProcAddress' and
    len(e.a) == 2 and
    e.a[1].op is cot_obj and
    is_strlit(get_flags(e.a[1].obj_ea)))

"""this can be optimized by gettings callers (xrefs)
to GetProcAddress and scanning only those"""
for ea in Functions():
    hits += [(e.ea, get_strlit_contents(e.a[1].obj_ea,
        -1,
        0,
        STRCONV_ESCAPE)) for e in find_expr(ea, query)]
for ea, name in hits:
    print("%x: %s" % (ea, name.decode("utf-8")))
```
![find_expr png](./rsrc/gpa.png?raw=true)
