import hr_toolbox as tb
from idaapi import *

__author__ = "https://github.com/patois"

# ----------------------------------------------------------------------------
def find_calls():
    """find function calls
    example function to be passed to hr_toolbox.display()

    """

    query = lambda cf, e: (e.op is cot_call and
        e.x.op is cot_obj)

    return tb.db_exec_query(query)

# ----------------------------------------------------------------------------
def find_memcpy():
    """find calls to memcpy() where the 'n' argument is signed
    example function to be passed to hr_toolbox.display()

    """

    query = lambda cf, e: (e.op is cot_call and
        e.x.op is cot_obj and
        'memcpy' in get_name(e.x.obj_ea) and
        len(e.a) == 3 and
        e.a[2].op is cot_var and
        cf.lvars[e.a[2].v.idx].tif.is_signed())

    return tb.db_exec_query(query)

# ----------------------------------------------------------------------------
def find_sprintf():
    """find calls to sprintf() where the format string argument contains '%s'
    example function to be passed to hr_toolbox.display()

    """

    query = lambda cfunc, e: (e.op is cot_call and
        e.x.op is cot_obj and
        'sprintf' in get_name(e.x.obj_ea) and
        len(e.a) >= 2 and
        e.a[1].op is cot_obj and
        is_strlit(get_flags(e.a[1].obj_ea)) and
        b'%s' in get_strlit_contents(e.a[1].obj_ea, -1, 0, STRCONV_ESCAPE))

    return tb.db_exec_query(query)

# ----------------------------------------------------------------------------
def find_gpa():
    """find dynamically imported functions (Windows)
    example function to be passed to hr_toolbox.display()

    """

    query = lambda cfunc, e: (e.op is cot_call and
        e.x.op is cot_obj and
        'GetProcAddress' in get_name(e.x.obj_ea) and
        len(e.a) == 2 and
        e.a[1].op is cot_obj and
        is_strlit(get_flags(e.a[1].obj_ea)))

    gpa = get_name_ea_simple('GetProcAddress')
    ea_list = [f.start_ea for f in [get_func(xref.frm) for xref in XrefsTo(gpa, XREF_FAR)] if f]
    return tb.exec_query(query, list(dict.fromkeys(ea_list)))

# ----------------------------------------------------------------------------
def menu():
    print("""Example commands:

    menu()

    d(find_calls) # print function calls
    d(find_memcpy) # print calls to memcpy() with signed 'n' argument
    d(find_sprintf) # print calls to sprintf() with "%s" in fmt str
    da(find_gpa, 1) # print calls to GetProcAddress + imported func name

    qdb(lambda cf, e: e.op is cot_call) # find function calls
    q(lambda cf, e: e.op is cot_call, [here()], lambda e: "%s" % get_name(e.x.obj_ea)[::-1])
    q(lambda cf, e: e.op is cit_if and e.cif.expr.op is cot_land)

    """)
    return

if __name__ == "__main__":
    from hr_toolbox import display as d
    from hr_toolbox import display_argstr as da
    from hr_toolbox import query as q
    from hr_toolbox import query_db as qdb
    menu()