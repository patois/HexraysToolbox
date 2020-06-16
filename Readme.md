# Hexrays Toolbox

Hexrays Toolbox is a script for the Hexrays Decompiler which
can be used to find code patterns within decompiled code.

![toolbox animated gif](./rsrc/toolbox.gif?raw=true)

Loading hr_toolbox.py with IDA (alt-f7) will make
available the "find_expr()" and "find_item()" functions
to the IDAPython CLI and the script interpreter (shift-f2).

The functions find_expr() and find_item() accept two arguments:
```
    find_item(ea, q)
    find_expr(ea, q)

    ea:         address of a valid function within
                the current database
    q:          lambda function
                custom lambda function with the following arguments:
                1. cfunc: cfunc_t
                2. i/e:   cinsn_t/cexpr_t

    Example:
    find_expr(here(), lambda cf, e: e.op is cot_call)
    
    -> finds and returns all function calls within a current function

    Please find the cfunc_t, citem_t, cinsn_t and cexpr_t structures
    within hexrays.hpp for help and further details.
```
Please also check out the [HRDevHelper](https://github.com/patois/HRDevHelper) plugin which may assist in writing respective queries.

## Examples:

### 1) get list of expressions that compare anything to zero ("x == 0")
```
         cot_eq
         /   \
      x /     \ y
(anything)  cot_num --- n.numval() == 0
```
```
from idaapi import *
from hr_toolbox import find_expr
query = lambda cfunc, e: e.op is cot_eq and e.y.op is cot_num and e.y.numval() == 0
r = [e for e in find_expr(here(), query)]
for e in r:
    print(e)
```
### 2) get list of function calls
```
        cot_call
         / 
      x /
 cot_obj
```
```
from idaapi import *
from hr_toolbox import find_expr
query = lambda cfunc, e: e.op is cot_call and e.x.op is cot_obj
r = [e for e in find_expr(here(), query)]
for e in r:
    print(e)
```
### 3) print list of memcpy calls where "dst" argument is on stack
```
        cot_call --- arg1 is cot_var
         /           arg1 is on stack
      x /
 cot_obj --- name(obj_ea) == 'memcpy'
```
```
from idaapi import *
from hr_toolbox import find_expr
r = []
query = lambda cfunc, e: (e.op is cot_call and
           e.x.op is cot_obj and
           get_name(e.x.obj_ea) == 'memcpy' and
           len(e.a) == 3 and
           e.a[0].op is cot_var and
           cfunc.lvars[e.a[0].v.idx].is_stk_var())
for ea in Functions():
    r += [e for e in find_expr(ea, query)]
for e in r:
    print(e)
```
### 4) get list of calls to sprintf(str, fmt, ...) where fmt contains "%s"
```
        cot_call --- arg2 ('fmt') contains '%s'
         /
      x /
 cot_obj --- name(obj_ea) == 'sprintf'
```
```
from idaapi import *
from hr_toolbox import find_expr
r = []
query = lambda cfunc, e: (e.op is cot_call and
    e.x.op is cot_obj and
    get_name(e.x.obj_ea) == 'sprintf' and
    len(e.a) >= 2 and
    e.a[1].op is cot_obj and
    is_strlit(get_flags(e.a[1].obj_ea)) and
    b'%s' in get_strlit_contents(e.a[1].obj_ea, -1, 0, STRCONV_ESCAPE))
for ea in Functions():
    r += [e for e in find_expr(ea, query)]
for e in r:
    print(e)
```
### 5) get list of signed operators, display result in chooser
```
from idaapi import *
from hr_toolbox import ic_t
query = lambda cfunc, e: (e.op in
            [hr.cot_asgsshr, hr. cot_asgsdiv,
            hr.cot_asgsmod, hr.cot_sge,
            hr.cot_sle, hr.cot_sgt,
            hr.cot_slt, hr.cot_sshr,
            hr.cot_sdiv, hr.cot_smod])
ic_t(query)
```