import ida_hexrays as hx
import ida_bytes
import idautils
import ida_kernwin
import ida_lines
import ida_funcs
import idc
from ida_idaapi import __EA64__, BADADDR

__author__ = "Dennis Elser @ https://github.com/patois"
SCRIPT_NAME = "[hxtb]"

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
class query_result_t():
    def __init__(self, entry_ea=BADADDR, i=None):
        self.entry = entry_ea
        if isinstance(i, (hx.cexpr_t, hx.cinsn_t)):
            self.ea = i.ea
            self.v = ida_lines.tag_remove(i.print1(None))
        elif isinstance(i, tuple):
            self.ea, self.v = i
        else:
            self.ea = BADADDR
            self.v = "<undefined>"

    def __str__(self):
        return "[%x] %x: \"%s\"" % (self.entry, self.ea, self.v)

# ----------------------------------------------------------------------------
def find_item(ea, q, parents=False, flags=0):
    """find item within AST of decompiled function

    arguments:
    ea:         address belonging to a function
    q:          lambda/function: f(cfunc_t, citem_t) returning a bool
    parents:    False -> discard cexpr_t parent nodes
                True  -> maintain citem_t parent nodes

    returns list of query_result_t objects
    """

    f = ida_funcs.get_func(ea)
    if f:
        cfunc = None
        hf = hx.hexrays_failure_t()
        try:
            cfunc = hx.decompile(f, hf, flags)
        except Exception as e:
            print("%s %x: unable to decompile: '%s'" % (SCRIPT_NAME, ea, hf))
            print("\t (%s)" % e)
            return list()

        if cfunc:
            return find_child_item(cfunc, cfunc.body, q, parents)
    return list()

# ----------------------------------------------------------------------------
def find_child_item(cfunc, i, q, parents=False):
    """find child item in cfunc_t starting at citem_t i
    
    arguments:
    cfunc:      cfunc_t
    i:          citem_t
    q:          lambda/function: f(cfunc_t, citem_t) returning a bool

    returns list of query_result_t objects
    """

    class citem_finder_t(hx.ctree_visitor_t):
        def __init__(self, cfunc, q, parents):
            hx.ctree_visitor_t.__init__(self,
                hx.CV_PARENTS if parents else hx.CV_FAST)

            self.cfunc = cfunc
            self.query = q
            self.found = list()
            return

        def process(self, i):
            """process cinsn_t and cexpr_t elements alike"""

            if self.query(self.cfunc, i):
                self.found.append(query_result_t(self.cfunc.entry_ea, i))
            return 0

        def visit_insn(self, i):
            return self.process(i)

        def visit_expr(self, e):
            return self.process(e)

    if cfunc:
        itfinder = citem_finder_t(cfunc, q, parents)
        itfinder.apply_to(i, None)
        return itfinder.found
    return list()

# ----------------------------------------------------------------------------
def find_expr(ea, q, parents=False, flags=0):
    """find expression within AST of decompiled function
    
    arguments:
    ea:         address belonging to a function
    q:          lambda/function: f(cfunc_t, citem_t) returning a bool
    parents:    False -> discard cexpr_t parent nodes
                True  -> maintain citem_t parent nodes

    returns list of query_result_t objects
    """

    f = ida_funcs.get_func(ea)
    if f:
        cfunc = None
        hf = hx.hexrays_failure_t()
        try:
            cfunc = hx.decompile(f, hf, flags)
        except Exception as e:
            print("%s %x: unable to decompile: '%s'" % (SCRIPT_NAME, ea, hf))
            print("\t (%s)" % e)
            return list()

        if cfunc:
            return find_child_expr(cfunc, cfunc.body, q, parents)
    return list()

# ----------------------------------------------------------------------------
def find_child_expr(cfunc, e, q, parents=False):
    """find child expression in cfunc_t starting at cexpr_t e
    
    arguments:
    cfunc:      cfunc_t
    e:          cexpr_t
    q:          lambda/function: f(cfunc_t, citem_t) returning a bool

    returns list of query_result_t objects
    """

    class expr_finder_t(hx.ctree_visitor_t):
        def __init__(self, cfunc, q, parents):
            hx.ctree_visitor_t.__init__(self,
                hx.CV_PARENTS if parents else hx.CV_FAST)

            self.cfunc = cfunc
            self.query = q
            self.found = list()
            return

        def visit_expr(self, e):
            """process cexpr_t elements"""

            if self.query(self.cfunc, e):
                self.found.append(query_result_t(self.cfunc.entry_ea, e))
            return 0

    if cfunc:
        expfinder = expr_finder_t(cfunc, q, parents)
        expfinder.apply_to_exprs(e, None)
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

    returns list of query_result_t objects
    """

    find_elem = find_item if query_full else find_expr
    result = list()
    for ea in ea_list:
        result += find_elem(ea, q)
    return result

# ----------------------------------------------------------------------------
def query_db(q, query_full=True, do_print=False):
    """run query on idb
    
    arguments:
    q:          lambda/function: f(cfunc_t, citem_t) returning a bool
    query_full: False -> find cexpr_t only (default - faster but doesn't find cinsn_t items)
                True  -> find citem_t elements, which includes cexpr_t and cinsn_t

    returns list of query_result_t objects
    """

    return query(q, ea_list=idautils.Functions(), query_full=query_full, do_print=do_print)

# ----------------------------------------------------------------------------
def query(q, ea_list=None, query_full=True, do_print=False):
    """run query on list of addresses

    arguments:
    q:          lambda/function: f(cfunc_t, citem_t) returning a bool
    ea_list:    iterable of addresses/functions to process
    query_full: False -> find cexpr_t only (default - faster but doesn't find cinsn_t items)
                True  -> find citem_t elements, which includes cexpr_t and cinsn_t

    returns list of query_result_t objects
    """

    if not ea_list:
        ea_list = [ida_kernwin.get_screen_ea()]
    r = list()
    try:
        r = exec_query(q, ea_list, query_full)
        if do_print:
            print("<query> done! %d unique hits." % len(r))
            for e in r:
                print(e)
    except Exception as exc:
        print("<query> error:", exc)
    return r

# ----------------------------------------------------------------------------
class ic_t(ida_kernwin.Choose):
    """Chooser for citem_t types

    arguments:
    q:          lambda/function: f(cfunc_t, citem_t) returning a bool
                or list of query_result_t objects
    ea_list:    iterable of addresses/functions to process
    query_full: False -> find cexpr_t only (default - faster but doesn't find cinsn_t items)
                True  -> find citem_t elements, which includes cexpr_t and cinsn_t
    """
    window_title = "Hexrays Toolbox"

    def __init__(self,
            q=None,
            ea_list=None,
            query_full=True,
            flags=ida_kernwin.CH_RESTORE | ida_kernwin.CH_QFLT,
            title=None,
            width=None,
            height=None,
            embedded=False,
            modal=False):
        
        _title = ""
        i = 0
        idx = ""
        pfx = ""
        exists = True
        while exists:
            idx = chr(ord('A')+i%26)
            _title = "%s-%s%s" % (ic_t.window_title, pfx, idx)
            if title:
                _title += ": %s" % title
            exists = (ida_kernwin.find_widget(_title) != None)
            i += 1
            pfx += "" if i % 26 else "A"

        ida_kernwin.Choose.__init__(
            self,
            _title,
            [ ["Function", 20 | ida_kernwin.CHCOL_FNAME],
              ["Address", 10 | ida_kernwin.CHCOL_EA],
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
        item_ea = self.items[n].ea
        func_ea = self.items[n].entry
        ea = func_ea if item_ea == BADADDR else item_ea
        ida_kernwin.jumpto(ea)

    def OnGetLine(self, n):
        return self._make_choser_entry(n)

    def OnGetSize(self):
        return len(self.items)

    def append(self, data):
        if not isinstance(data, query_result_t):
            return False
        self.items.append(data)
        self.Refresh()
        return True

    def set_data(self, data):
        self.items = data
        self.Refresh()

    def get_data(self):
        return self.items

    def _make_choser_entry(self, n):
        return ["%s" % idc.get_func_off_str(self.items[n].entry),
                "%016x" % self.items[n].ea if __EA64__ else "%08x" % self.items[n].ea,
                self.items[n].v]
