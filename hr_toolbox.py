import ida_hexrays as hr
import ida_bytes
import idautils
import ida_kernwin
import ida_lines
import ida_funcs
from ida_idaapi import __EA64__

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
- explicit support for cinsn_t?
"""

# ----------------------------------------------------------------------------
class tb_result_t():
    def __init__(self, i):
        self.ea = i.ea
        self.v = ida_lines.tag_remove(i.print1(None))

    def __str__(self):
        return "%x: %s" % (self.ea, self.v)

# ----------------------------------------------------------------------------
def find_item(ea, q, parents=False):
    """find item within AST of decompiled function

    arguments:
    ea:         address belonging to a function
    q:          lambda/function: f(cfunc_t, citem_t) returning a bool
    parents:    False -> discard cexpr_t parent nodes
                True  -> maintain citem_t parent nodes

    returns list of tb_result_t objects
    """

    class citem_finder_t(hr.ctree_visitor_t):
        def __init__(self, cfunc, q, parents):
            hr.ctree_visitor_t.__init__(self,
                hr.CV_PARENTS if parents else hr.CV_FAST)

            self.cfunc = cfunc
            self.query = q
            self.found = list()
            return

        def process(self, i):
            """process cinsn_t and cexpr_t elements alike"""

            if self.query(self.cfunc, i):
                self.found.append(tb_result_t(i))
            return 0

        def visit_insn(self, i):
            return self.process(i)

        def visit_expr(self, e):
            return self.process(e)

    try:
        f = ida_funcs.get_func(ea)
        if f:
            cfunc = hr.decompile(f)
    except:
        print("%x: unable to decompile." % ea)
        return list()

    if cfunc:
        itfinder = citem_finder_t(cfunc, q, parents)
        itfinder.apply_to(cfunc.body, None)
        return itfinder.found
    return list()

# ----------------------------------------------------------------------------
def find_expr(ea, q, parents=False):
    """find expression within AST of decompiled function
    
    arguments:
    ea:         address belonging to a function
    q:          lambda/function: f(cfunc_t, citem_t) returning a bool
    parents:    False -> discard cexpr_t parent nodes
                True  -> maintain citem_t parent nodes

    returns list of tb_result_t objects
    """

    class expr_finder_t(hr.ctree_visitor_t):
        def __init__(self, cfunc, q, parents):
            hr.ctree_visitor_t.__init__(self,
                hr.CV_PARENTS if parents else hr.CV_FAST)

            self.cfunc = cfunc
            self.query = q
            self.found = list()
            return

        def visit_expr(self, e):
            """process cexpr_t elements"""

            if self.query(self.cfunc, e):
                self.found.append(tb_result_t(e))
            return 0

    try:
        f = ida_funcs.get_func(ea)
        if f:
            cfunc = hr.decompile(f)
    except:
        print("%x: unable to decompile." % ea)
        return list()

    if cfunc:
        expfinder = expr_finder_t(cfunc, q, parents)
        expfinder.apply_to_exprs(cfunc.body, None)
        return expfinder.found
    return list()

# ----------------------------------------------------------------------------
def exec_query(q, ea_list, query_full):
    """run query on list of addresses

    convenience wrapper function around find_item()

    arguments:
    q:          lambda/function: f(cfunc_t, citem_t) returning a bool
    ea_list:    iterable of addresses/functions to process
    query_full: False -> find cexpr_t only (faster but doesn't find cinsn_t items)
                True  -> find citem_t elements, which includes cexpr_t and cinsn_t

    returns list of tb_result_t objects
    """

    find_elem = find_item if query_full else find_expr
    result = list()
    for ea in ea_list:
        result += [e for e in find_elem(ea, q)]
    return result

# ----------------------------------------------------------------------------
def query_db(q, query_full=True, do_print=False):
    """run query on idb, print results
    
    arguments:
    q:          lambda/function: f(cfunc_t, citem_t) returning a bool
    query_full: False -> find cexpr_t only (default - faster but doesn't find cinsn_t items)
                True  -> find citem_t elements, which includes cexpr_t and cinsn_t

    returns list of tb_result_t objects
    """

    return query(q, ea_list=idautils.Functions(), query_full=query_full, do_print=do_print)

# ----------------------------------------------------------------------------
def query(q, ea_list=None, query_full=True, do_print=False):
    """run query on list of addresses, print results

    arguments:
    q:          lambda/function: f(cfunc_t, citem_t) returning a bool
    ea_list:    iterable of addresses/functions to process
    query_full: False -> find cexpr_t only (default - faster but doesn't find cinsn_t items)
                True  -> find citem_t elements, which includes cexpr_t and cinsn_t

    returns list of tb_result_t objects
    """

    if not ea_list:
        ea_list = [ida_kernwin.get_screen_ea()]
    r = list()
    try:
        r = exec_query(q, ea_list, query_full)
        if do_print:
            print("<query> done! %d unique hits." % len(r))
            for e in r:
                print("%x: %s" % (e.ea, e.v))
    except Exception as exc:
        print("<query> error:", exc)
    return r

# ----------------------------------------------------------------------------
class ic_t(ida_kernwin.Choose):
    """Chooser for citem_t types

    arguments:
    q:          lambda/function: f(cfunc_t, citem_t) returning a bool
                or list of tb_result_t objects
    ea_list:    iterable of addresses/functions to process
    query_full: False -> find cexpr_t only (default - faster but doesn't find cinsn_t items)
                True  -> find citem_t elements, which includes cexpr_t and cinsn_t
    """

    def __init__(self, q, ea_list=None, query_full=True,
            flags=ida_kernwin.CH_RESTORE | ida_kernwin.CH_QFLT,
            width=None, height=None, embedded=False, modal=False):
        ida_kernwin.Choose.__init__(
            self,
            "Hexrays Toolbox",
            [ ["Address", 10 | ida_kernwin.CHCOL_EA],
              ["Output", 80 | ida_kernwin.CHCOL_PLAIN]],
            flags = flags,
            width = width,
            height = height,
            embedded = embedded)

        if ea_list is None:
            ea_list =[ida_kernwin.get_screen_ea()]
        if callable(q):
            self.items = exec_query(q, ea_list, query_full)
        elif isinstance(q, list):
            self.items = q
        else:
            self.items = list()

        self.Show()

    def OnClose(self):
        self.items = []

    def OnSelectLine(self, n):
        ida_kernwin.jumpto(self.items[n].ea)

    def OnGetLine(self, n):
        return self._make_choser_entry(n)

    def OnGetSize(self):
        return len(self.items)

    """
    def append(self, data):
        self.items.append(data)
        self.Refresh()
        return
    """
    def set_data(self, data):
        self.items = data
        self.Refresh()

    def _make_choser_entry(self, n):
        return ["%016x" % (self.items[n].ea) if __EA64__ else "%08x" % (self.items[n].ea), self.items[n].v]
