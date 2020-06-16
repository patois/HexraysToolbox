import ida_hexrays as hr
import ida_bytes
import idautils
import ida_kernwin
import ida_lines
import ida_funcs


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
def find_item(ea, q, findall=True, parents=False):
    """find item within AST of decompiled function

    arguments:
    ea:         address belonging to a function
    q:          lambda/function: f(cfunc_t, citem_t) returning a bool
    findall:    False -> find cexpr_t only (faster but doesn't find cinsn_t items)
                True  -> find citem_t elements, which includes cexpr_t and cinsn_t
    parents:    False -> discard cexpr_t parent nodes
                True  -> maintain citem_t parent nodes

    returns list of tb_result_t objects
    """

    class citem_finder_t(hr.ctree_visitor_t):
        def __init__(self, cfunc, q, findall, parents):
            hr.ctree_visitor_t.__init__(self,
                hr.CV_PARENTS if parents else hr.CV_FAST)

            self.findall = findall
            self.cfunc = cfunc
            self.query = q
            self.found = list()
            return

        def process(self, i):
            """process cinsn_t and cexpr_t elements alike"""

            if self.query(self.cfunc, i):
                self.found.append(tb_result_t(i))
                if not self.findall:
                    return 1
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
        itfinder = citem_finder_t(cfunc, q, findall, parents)
        itfinder.apply_to(cfunc.body, None)
        return itfinder.found
    return list()

# ----------------------------------------------------------------------------
def find_expr(ea, q, findall=True, parents=False):
    """find expression within AST of decompiled function
    
    arguments:
    ea:         address belonging to a function
    q:          lambda/function: f(cfunc_t, citem_t) returning a bool
    findall:    False -> find cexpr_t only (faster but doesn't find cinsn_t items)
                True  -> find citem_t elements, which includes cexpr_t and cinsn_t
    parents:    False -> discard cexpr_t parent nodes
                True  -> maintain citem_t parent nodes

    returns list of tb_result_t objects
    """

    class expr_finder_t(hr.ctree_visitor_t):
        def __init__(self, cfunc, q, findall, parents):
            hr.ctree_visitor_t.__init__(self,
                hr.CV_PARENTS if parents else hr.CV_FAST)

            self.findall = findall
            self.cfunc = cfunc
            self.query = q
            self.found = list()
            return

        def visit_expr(self, e):
            """process cexpr_t elements"""

            if self.query(self.cfunc, e):
                self.found.append(tb_result_t(e))
                if not self.findall:
                    return 1
            return 0

    try:
        f = ida_funcs.get_func(ea)
        if f:
            cfunc = hr.decompile(f)
    except:
        print("%x: unable to decompile." % ea)
        return list()

    if cfunc:
        expfinder = expr_finder_t(cfunc, q, findall, parents)
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

    returns list of tb_result_t objects
    """

    find_elem = find_item if full else find_expr
    result = list()
    for ea in ea_list:
        result += [e for e in find_elem(ea, q)]
    return result

# ----------------------------------------------------------------------------
def query_db(q, full=False):
    """run query on idb, print results
    
    arguments:
    q:          lambda/function: f(cfunc_t, citem_t) returning a bool
    full:       False -> find cexpr_t only (faster but doesn't find cinsn_t items)
                True  -> find citem_t elements, which includes cexpr_t and cinsn_t
    """

    return query(q, ea_list=idautils.Functions(), full=full)

# ----------------------------------------------------------------------------
def query(q, ea_list=None, full=False):
    """run query on list of addresses, print results

    arguments:
    q:          lambda/function: f(cfunc_t, citem_t) returning a bool
    ea_list:    iterable of addresses/functions to process
    full:       False -> find cexpr_t only (faster but doesn't find cinsn_t items)
                True  -> find citem_t elements, which includes cexpr_t and cinsn_t
    """

    if not ea_list:
        ea_list = [ida_kernwin.get_screen_ea()]

    r = exec_query(q, ea_list=ea_list, full=full)
    print("<query> done! %d unique hits." % len(r))
    try:
        for e in r:
            print("%x: %s" % (e[0], e[1]))
    except Exception as exc:
        print("<query> error:", exc)
    return

# ----------------------------------------------------------------------------
def display(f):
    """execute function f and print results

    arguments:
    f:      function that is expected to return a list of tb_result_t objects
    """
    try:
        r = f()
        print("<display> done! %d unique hits." % len(r))
        for e in r:
            print("%x: %s" % (e.ea, e.v))
    except Exception as exc:
        print("<display> error:", exc)
    return

# ----------------------------------------------------------------------------
class ic_t(ida_kernwin.Choose):
    """Chooser for citem_t types

    arguments:
    q:          lambda/function: f(cfunc_t, citem_t) returning a bool
    ea_list:    iterable of addresses/functions to process
    full:       False -> find cexpr_t only (faster but doesn't find cinsn_t items)
                True  -> find citem_t elements, which includes cexpr_t and cinsn_t
    """

    def __init__(self, q, ea_list=None, full=False,
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
        self.items = exec_query(q, ea_list, full)
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

    def set_data(self, data):
        self.items = data
        self.Refresh()
    """
    def _make_choser_entry(self, n):
        return ["%x" % self.items[n].ea, self.items[n].v]