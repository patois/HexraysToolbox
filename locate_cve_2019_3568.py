from idaapi import *
from hr_toolbox import query

def locate_CVE_2019_3568():
    """Example query:
    One (but not very elegant) way of locating CVE-2019-3568 within libwhatsapp.so. 

    """
    expr = lambda cf, e: (e.op is cit_if and
            e.cif.expr.op is cot_land and
            e.cif.expr.y.op is cot_eq and
            e.cif.expr.y.y.op is cot_num and
            e.cif.expr.y.y.numval() == 51200)

    locations=set(CodeRefsTo(get_name_ea(BADADDR, "__aeabi_memcpy"), False))
    return query(expr, locations, full=True)

if __name__ == "__main__":
    print("Attempting to locate CVE-2019-3568...")
    locate_CVE_2019_3568()