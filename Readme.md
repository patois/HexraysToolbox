# HexRays Toolbox

HexRays Toolbox (hxtb) is a powerful set of IDAPython scripts that can be used to find and locate code patterns in binaries, independent from their underlying processor architecture.

## Use Cases

- scan binary files for vulnerabilities and variants
- locate code patterns from previously reverse engineered executables in newly decompiled code
- malware variant analysis
- find code similarities across several binaries (i.e. for proving "code theft", license violations, ...)
- find code patterns from binaries compiled for architecture A in binaries compiled for architecture B
- probably a lot more...

The query illustrated by the animation below is an example for how a vulnerability that affected WhatsApp for Android (CVE-2019-3568, libwhatsapp.so) can be located using HexRays Toolbox. This is done by formulating a desired code pattern that is to be located using an IDAPython lambda function. Find the example script ![here](./examples/).

![toolbox animated gif](./rsrc/toolbox.gif?raw=true)

## Requirements

A valid IDA license and a valid HexRays decompiler license per target architecture is required. 

## Usage

There are several ways of using Hexrays Toolbox, each with a varying degree of flexibility.

- run queries on behalf of [hxtb_shell](#hxtb-shell), an interactive GUI
- custom IDAPython [scripting](#Scripting)
- ```interactive.py```, a script that adds [convenience functions](./interactive/interactive.py) to be used with the IDA command line interface
- ```automation.py```, a script that processes and runs hxtb queries on a given set of files in [batch mode](./automation/batch.py)

### hxtb-shell
Executing the included ```hxtb_shell.py``` script from within IDA opens a GUI window that can be used to develop, load and run hxtb queries. The screenshot below shows what a query loaded with hxtb-shell may look like.

![hxtb shell](./rsrc/hxtbshell.png?raw=true)

hxtb-shell also accepts Python expressions that are created by the [HRDevHelper](https://github.com/patois/HRDevHelper) plugin's context viewer. They can be copied from it and directly pasted into the hxtb-shell GUI.

![HRDevHelper context viewer](https://github.com/patois/HRDevHelper/blob/master/rsrc/hrdevctx.png?raw=true)

___

Further example queries that can be loaded with hxtb-shell can be found in the ```hxtbshell_queries``` sub-folder included with HexRays Toolbox.

### Scripting

Loading ```hxtb.py``` with IDA (Alt-F7) makes functions such as ```find_expr()``` and ```find_item()``` available to both the IDAPython CLI and the script interpreter (Shift-F2). Among others, these functions can be used to run queries on the currently loaded IDA database. Please check out some of the examples shown [below](#Examples).

```
    find_item(ea, q)
    find_expr(ea, q)

    Positional arguments:
        ea:         address of a valid function within
                    the current database
        q:          lambda function
                    custom lambda function with the following arguments:
                    1. cfunc: cfunc_t
                    2. i/e:   cinsn_t/cexpr_t
    Returns:
        list of query_result_t objects

    Example:
        find_expr(here(), lambda cf, e: e.op is cot_call)
    
        -> finds and returns all function calls within a current function.
        The returned data is a list of query_result_t objects (see hxtb.py).

        The returned list can be passed to an instance of the ic_t class,
        which causes the data to be displayed by a chooser as follows:

        from idaapi import *
        import hxtb
        hxtb.ic_t(find_expr(here(), lambda cf,e:e.op is cot_call))


    Please find the cfunc_t, citem_t, cinsn_t and cexpr_t structures
    within hexrays.hpp for further help and details.
```

## Examples

### List expressions that compare anything to zero ("x == 0")
```
         cot_eq
         /   \
      x /     \ y
(anything)  cot_num --- n.numval() == 0
```
``` python
from idaapi import *
from hxtb import find_expr
query = lambda cfunc, e: e.op is cot_eq and e.y.op is cot_num and e.y.numval() == 0
r = find_expr(here(), query)
for e in r:
    print(e)
```
### List (direct) function calls
```
        cot_call
         / 
      x /
 cot_obj
```
``` python
from idaapi import *
from hxtb import find_expr
query = lambda cfunc, e: e.op is cot_call and e.x.op is cot_obj
r = find_expr(here(), query)
for e in r:
    print(e)
```
![list of calls ](./rsrc/calls.png?raw=true)
### List memcpy calls where "dst" argument is on stack
```
        cot_call --- arg1 is cot_var
         /           arg1 is on stack
      x /
 cot_obj --- name(obj_ea) == 'memcpy'
```
``` python
from idaapi import *
from hxtb import find_expr
r = []
query = lambda cfunc, e: (e.op is cot_call and
           e.x.op is cot_obj and
           get_name(e.x.obj_ea) == 'memcpy' and
           len(e.a) == 3 and
           e.a[0].op is cot_var and
           cfunc.lvars[e.a[0].v.idx].is_stk_var())
for ea in Functions():
    r += find_expr(ea, query)
for e in r:
    print(e)
```
### List calls to sprintf(str, fmt, ...) where fmt contains "%s"
```
        cot_call --- arg2 ('fmt') contains '%s'
         /
      x /
 cot_obj --- name(obj_ea) == 'sprintf'
```
``` python
from idaapi import *
from hxtb import find_expr
r = []
query = lambda cfunc, e: (e.op is cot_call and
    e.x.op is cot_obj and
    get_name(e.x.obj_ea) == 'sprintf' and
    len(e.a) >= 2 and
    e.a[1].op is cot_obj and
    is_strlit(get_flags(get_item_head(e.a[1].obj_ea))) and
    b'%s' in get_strlit_contents(e.a[1].obj_ea, -1, 0, STRCONV_ESCAPE))
for ea in Functions():
    r += find_expr(ea, query)
for e in r:
    print(e)
```
### Show all instructions using signed operators in a list view
``` python
from idaapi import *
from hxtb import ic_t
query = lambda cfunc, e: (e.op in
            [cot_asgsshr, cot_asgsdiv,
            cot_asgsmod, cot_sge,
            cot_sle, cot_sgt,
            cot_slt, cot_sshr,
            cot_sdiv, cot_smod])
ic_t(query)
```
![list of signed operators](./rsrc/signed_ops.png?raw=true)
### Show all "if" statements in a list view
``` python
from idaapi import *
from hxtb import ic_t
ic_t(lambda cf, i: i.op is cit_if)
```
![list of if statements](./rsrc/if_stmt.png?raw=true)
### Find all loop statements within current db, display result in a list view
``` python
from idaapi import *
from hxtb import ic_t, query_db
ic_t(query_db(lambda cf,i: is_loop(i.op)))
```
![list of loops](./rsrc/loops.png?raw=true)
### Show potential memory copy operations in a list view
``` python
from hxtb import ic_t, query_db, find_child_expr
from ida_hexrays import *


find_copy_query = lambda cfunc, i: (i.op is cot_asg and
                                i.x.op is cot_ptr and
                                i.y.op is cot_ptr)

find_loop_query = lambda cfunc, i: (is_loop(i.op) and
                            find_child_expr(cfunc, i, find_copy_query))


ic_t(query_db(find_loop_query))
```
![list of copy loops](./rsrc/copy_loop.png?raw=true)
