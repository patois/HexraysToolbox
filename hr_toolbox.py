import ida_hexrays as hr
import ida_bytes, idautils, ida_kernwin, ida_lines

__author__ = "Dennis Elser @ https://github.com/patois"

"""
Hexrays Toolbox - IDAPython plugin for finding code patterns using Hexrays
==========================================================================

This IDAPython script allows code patterns to be found within binaries whose
processor architecture is supported by the Hexrays decompiler
(https://www.hex-rays.com/).

HRDevHelper (https://github.com/patois/HRDevHelper) is a separate IDAPython
plugin for IDA Pro that visualizes the AST of decompiled code. Its use is
encouraged in combination with Hexrays Toolbox, in order to simplify the
development of queries.

Use Cases:
----------
- scan binary files for known and unknown vulnerabilities
- locate code patterns from previously reverse engineered executables
  within newly decompiled code
- malware variant analysis
- find code similarities across several binaries
- find code patterns from one architecture within executable code of another
  architecture
- many more, limited (almost) only by the queries you'll come up with ;)

Example scenarios:
------------------
Load and run one of the accompanied scripts, such as 'example_queries.py'
with IDA (Shift-F2).

Todo:
-----
- data flow analysis
- this should be optimized for speed and rewritten in C/C++ :)
"""

# ----------------------------------------------------------------------------
def find_item(ea, item, findall=True, parents=False):
    """find item within AST of decompiled function

    arguments:
    ea:         address belonging to a function
    item:       lambda/function: f(cfunc_t, citem_t) returning a bool
    findall:    False -> find cexpr_t only (faster but doesn't find cinsn_t items)
                True  -> find citem_t elements, which includes cexpr_t and cinsn_t
    parents:    False -> discard cexpr_t parent nodes
                True  -> maintain citem_t parent nodes

    returns list of citem_t items
    """

    class citem_finder_t(hr.ctree_visitor_t):
        def __init__(self, cfunc, i, parents):
            hr.ctree_visitor_t.__init__(self,
                hr.CV_PARENTS if parents else hr.CV_FAST)

            self.findall = findall
            self.cfunc = cfunc
            self.item = i
            self.found = list()
            return

        def process(self, i):
            """process cinsn_t and cexpr_t elements alike"""

            cfunc = self.cfunc
            if self.item(cfunc, i):
                self.found.append(i)
                if not self.findall:
                    return 1
            return 0

        def visit_insn(self, i):
            return self.process(i)

        def visit_expr(self, e):
            return self.process(e)

    try:
        cfunc = hr.decompile(ea)
    except:
        print("%x: unable to decompile." % ea)
        return list()

    if cfunc:
        itfinder = citem_finder_t(cfunc, item, parents)
        itfinder.apply_to(cfunc.body, None)
        return itfinder.found
    return list()

# ----------------------------------------------------------------------------
def find_expr(ea, expr, findall=True, parents=False):
    """find expression within AST of decompiled function
    
    arguments:
    ea:         address belonging to a function
    expr:       lambda/function: f(cfunc_t, citem_t) returning a bool
    findall:    False -> find cexpr_t only (faster but doesn't find cinsn_t items)
                True  -> find citem_t elements, which includes cexpr_t and cinsn_t
    parents:    False -> discard cexpr_t parent nodes
                True  -> maintain citem_t parent nodes

    returns list of cexpr_t items
    """

    class expr_finder_t(hr.ctree_visitor_t):
        def __init__(self, cfunc, expr, parents):
            hr.ctree_visitor_t.__init__(self,
                hr.CV_PARENTS if parents else hr.CV_FAST)

            self.findall = findall
            self.cfunc = cfunc
            self.expr = expr
            self.found = list()
            return

        def visit_expr(self, e):
            """process cexpr_t elements"""

            cfunc = self.cfunc
            if self.expr(cfunc, e):
                self.found.append(e)
                if not self.findall:
                    return 1
            return 0

    try:
        cfunc = hr.decompile(ea)
    except:
        print("%x: unable to decompile." % ea)
        return list()

    if cfunc:
        expfinder = expr_finder_t(cfunc, expr, parents)
        expfinder.apply_to_exprs(cfunc.body, None)
        return expfinder.found
    return list()

# ----------------------------------------------------------------------------
def exec_query(q, ea_list, full):
    """run query on list of addresses

    convenience wrapper function around find_item()

    arguments:
    q:          lambda/function: f(cfunc_t, citem_t) returning a bool
    ea_list:    iterable of addresses/functions to process
    full:       False -> find cexpr_t only (faster but doesn't find cinsn_t items)
                True  -> find citem_t elements, which includes cexpr_t and cinsn_t

    returns list of cexpr_t/citem_t
    """

    find_elem = find_item if full else find_expr
    result = list()
    for ea in ea_list:
        result += [e for e in find_elem(ea, q)]
    return result

# ----------------------------------------------------------------------------
def query_db(q,
        full=False,
        fmt=lambda x:"%x: %s" % (x.ea,
            ida_lines.tag_remove(x.print1(None)))):
    """run query on idb, print results
    
    arguments:
    q:          lambda/function: f(cfunc_t, citem_t) returning a bool
    full:       False -> find cexpr_t only (faster but doesn't find cinsn_t items)
                True  -> find citem_t elements, which includes cexpr_t and cinsn_t
    fmt:        lambda/callback-function to be called for formatting output
    """

    return query(q, ea_list=idautils.Functions(), full=full, fmt=fmt)

# ----------------------------------------------------------------------------
def query(q,
        ea_list=None,
        full=False,
        fmt=lambda x:"%x: %s" % (x.ea,
            ida_lines.tag_remove(x.print1(None)))):
    """run query on list of addresses, print results

    arguments:
    q:          lambda/function: f(cfunc_t, citem_t) returning a bool
    ea_list:    iterable of addresses/functions to process
    full:       False -> find cexpr_t only (faster but doesn't find cinsn_t items)
                True  -> find citem_t elements, which includes cexpr_t and cinsn_t
    fmt:        lambda/callback-function to be called for formatting output
    """

    if not ea_list:
        ea_list = [ida_kernwin.get_screen_ea()]

    r = exec_query(q, ea_list=ea_list, full=full)
    print("<query> done! %d unique hits." % len(r))
    try:
        for e in r:
            print(fmt(e))
    except:
        print("<query> error!")
    return

# ----------------------------------------------------------------------------
def display(f,
        fmt=lambda x:"%x: %s" % (x.ea,
            ida_lines.tag_remove(x.print1(None)))):
    """execute function f and print results according to fmt.

    arguments:
    f:      function that is expected to return a list of citem_t/cexpr_t objects
    fmt:    lambda/callback-function to be called for formatting output
    """

    try:
        for e in f():
            print(fmt(e))
    except Exception as exc:
        print("<display> error!:", exc)
    return

# ----------------------------------------------------------------------------
def display_argstr(f, idx):
    """execute function f and print results.

    arguments:
    f:      function that is expected to return a list of citem_t/cexpr_t objects
    idx:    index into the argument list of a cexpr_t 
    """

    try:
        display(f, fmt=lambda x:"%x: %s" % (x.ea,
            ida_bytes.get_strlit_contents(x.a[idx].obj_ea, -1, 0,
                ida_bytes.STRCONV_ESCAPE).decode("utf-8")))
    except Exception as exc:
        print("<display_argstr> error!:", exc)
    return
