import idautils
import idaapi
import hxtb
import json
import os
from types import FunctionType

# hxtb-shell - A graphical frontend for Hexrays Toolbox
# URL: https://github.com/patois/HexraysToolbox

__author__ = "@pat0is"
SCRIPT_NAME = "hxtb-shell"

def run_query(qf, ea_list, qs):
    subtitle = qs.help
    title = subtitle if len(subtitle) < 80 else "%s..." % subtitle[:77]
    ch = hxtb.ic_t(title="Shell [%s]" % title)
    mode = qs.ast_type==1

    idaapi.show_wait_box("Processing")
    try:
        nfuncs = len(ea_list)
        for j, ea in enumerate(ea_list):
            if idaapi.user_cancelled():
                break
            idaapi.replace_wait_box("Processing function %d/%d" % (j+1, nfuncs))
            r = list()
            try:
                r = hxtb.exec_query(qf, [ea], mode, parents=True, flags=idaapi.DECOMP_NO_WAIT)
                for x in r:
                    ch.append(x)
            except Exception as e:
                print("%s: %s" % (SCRIPT_NAME, e))
    finally:
        idaapi.hide_wait_box()
    return ch

def compile_code(s):
    qo = None
    try:
        if s.query_type == 0:
            global ___hxtbshell_dynfunc_code___
            q = "\t"+"\t".join(s.query.splitlines(True))
            foo_code = compile('def ___hxtbshell_dynfunc___():\n%s' % q, "hxtb-shell dyncode", "exec")
            ___hxtbshell_dynfunc_code___ = FunctionType(foo_code.co_consts[0], globals(), "___hxtbshell_dynfunc___")
            hack = eval("lambda: ___hxtbshell_dynfunc_code___()")
            #instantiate
            qo = hack()
        else:
            qo = eval("lambda f, i: %s" % s.query)
    except Exception as e:
        print(e)
    return qo

def get_func_xrefs(ea):
    ea_list = []
    for xea in idautils.XrefsTo(ea):
        xf = idaapi.get_func(xea.frm)
        if not xf:
            print("[%s] warning: no function boundaries defined at %x" % (SCRIPT_NAME, xea.frm))
        else:
            ea_list.append(xf.start_ea)
    # remove duplicates
    ea_list = list(dict.fromkeys(ea_list))
    return ea_list

class QuerySettings():
    def __init__(self, query="", query_qtype=0, ast_type=0, scope=0, help=""):
        self.commit(query, query_qtype, ast_type, scope, help)

    def commit(self, query, query_qtype, ast_type, scope, help):
        self.version = 1.0
        self.query = query
        self.query_type = query_qtype
        self.ast_type = ast_type
        self.help = help
        self.scope = scope
        return

    def save(self, filepath):
        try:
            with open(filepath, 'w') as fp:
                json.dump(vars(self), fp, ensure_ascii=True)
        except Exception as e:
            return (False, e)
        return (True, "")

    def load(self, filepath):
        try:
            with open(filepath, 'r') as fp:
                content = json.load(fp)
                for k, v in content.items():
                    setattr(self, k, v)
        except Exception as e:
            return (False, e)
        return (True, "")


class QueryForm(idaapi.Form):
    def __init__(self):
        form = r"""STARTITEM {id:mstr_query}
BUTTON YES NONE
BUTTON NO NONE
BUTTON CANCEL NONE
%s
<##New:{btn_new}><##Load:{btn_load}><##Save as...:{btn_save}>

<:{str_help}>
<Query (function or expression)\::{mstr_query}>

<##Above code is a##Function:{rOptionFunction}>
<Lambda expression (f=cfunc_t and i=citem_t):{rOptionExpression}>{rad_qtype}>

<##Process AST elements##cot (faster):{rASTExpr}>
<cit and cot:{rASTStmt}>{rad_ast_type}>

<##Scope##Database:{rScopeIDB}>
<Current function:{rScopeCurFunc}>
<Xrefs to current item:{rScopeXrefItem}>
<Defined by query:{rScopeQuery}>{rad_qscope}>     

<##Run Query:{btn_runq}>
""" % SCRIPT_NAME
        self._qs = QuerySettings()
        s = self._get_settings()

        t = idaapi.textctrl_info_t()
        controls = {"mstr_query": idaapi.Form.MultiLineTextControl(text=s.query,
                        flags=t.TXTF_AUTOINDENT | t.TXTF_ACCEPTTABS | t.TXTF_FIXEDFONT,
                        tabsize=4,
                        width=90,
                        swidth=90),
                    "str_help": idaapi.Form.StringInput(swidth=90, value=s.help),
                    "rad_qscope": idaapi.Form.RadGroupControl(
                        ("rScopeIDB", "rScopeCurFunc", "rScopeXrefItem", "rScopeQuery"), value=s.scope),
                    "rad_qtype": idaapi.Form.RadGroupControl(("rOptionFunction", "rOptionExpression"), value=s.query_type),
                    "rad_ast_type": idaapi.Form.RadGroupControl(("rASTExpr", "rASTStmt"), value=s.ast_type),
                    "btn_load": idaapi.Form.ButtonInput(self.OnButtonPress, code=0),
                    "btn_save": idaapi.Form.ButtonInput(self.OnButtonPress, code=1),
                    "btn_runq": idaapi.Form.ButtonInput(self.OnButtonPress, code=2),
                    "btn_new": idaapi.Form.ButtonInput(self.OnButtonPress, code=3)}
        idaapi.Form.__init__(self, form, controls)

    def _get_settings(self):
        return self._qs

    def _ui_apply_settings(self, settings):
        tc = self.GetControlValue(self.mstr_query)
        tc.text = settings.query
        self.SetControlValue(self.mstr_query, tc)
        self.SetControlValue(self.rad_ast_type, settings.ast_type)
        self.SetControlValue(self.rad_qtype, settings.query_type)
        self.SetControlValue(self.rad_qscope, settings.scope)
        self.SetControlValue(self.str_help, settings.help)
        return 

    def _commit_settings(self):
        settings = self._get_settings()
        settings.commit(
            self.GetControlValue(self.mstr_query).text,
            self.GetControlValue(self.rad_qtype),
            self.GetControlValue(self.rad_ast_type),
            self.GetControlValue(self.rad_qscope),
            self.GetControlValue(self.str_help))
        return

    def _handle_btn_load_tbq_file(self, filepath):
        settings = self._get_settings()
        success, e = settings.load(filepath)
        if success:
            if settings.version < 1.0:
                idaapi.warning("Version not supported")
                return
            self._ui_apply_settings(settings)
        else:
            idaapi.warning("Could not load file.\n\n%s" % e)
            return
        print("[%s] loaded from \"%s\"" % (SCRIPT_NAME, filepath))
        return

    def _handle_btn_save_tbq_file(self, filepath):
        if os.path.exists(filepath):
            if idaapi.ASKBTN_YES != idaapi.ask_yn(idaapi.ASKBTN_NO, "File exists!\n\nOverwerite %s?" % filepath):
                return
        self._commit_settings()
        success, e = self._get_settings().save(filepath)
        if success:
            print("[%s] saved to \"%s\"" % (SCRIPT_NAME, filepath))
        else:
            idaapi.warning("Could not save file.\n\n%s" % e)
        return

    def _handle_btn_run_query(self):
        self._commit_settings()
        settings = self._get_settings()
        qo = compile_code(settings)
        if qo:
            scope = settings.scope
            if scope == 0:
                ea_list = list(idautils.Functions())
            elif scope == 1 or scope == 2:
                screen_ea = idaapi.get_screen_ea()
                ea_list = []
                if scope == 1:
                    ea_list.append(screen_ea)
                else:
                    ea_list = get_func_xrefs(screen_ea)
            elif scope == 3 and settings.query_type == 0:
                ea_list = qo.get_scope()
            else:
                idaapi.warning("%s: invalid scope!" % SCRIPT_NAME)
                return

            # if the query is a function
            if settings.query_type == 0:
                # call init() and check whether it is ok to run this query
                if qo.init():
                    """run query on 'ea_list'
                    on a side note: passing an object's method as an argument to hxtb
                    is probably(?) a bad idea and I surely do not know how it works
                    under the hood but it seems to work for the time being."""
                    if not len(ea_list):
                        idaapi.warning("%s: empty scope!" % SCRIPT_NAME)
                        return
                    run_query(qo.run, ea_list, settings)
                    # call cleanup/exit function
                    qo.exit()
            # otherwise it is a lambda expression
            else:
                run_query(qo, ea_list, settings)
        return

    def _handle_btn_new(self):
        # apply empty settings
        self._ui_apply_settings(QuerySettings())
        return

    def OnButtonPress(self, code=0):
        if code == 0:
            path = idaapi.ask_file(False, "*.tbq", "Load hxtb query from file...")
            if path:
                self._handle_btn_load_tbq_file(path)
        elif code == 1:
            path = idaapi.ask_file(True, "*.tbq", "Save hxtb query to file...")
            if path:
                self._handle_btn_save_tbq_file(path)
        elif code == 2:
            self._handle_btn_run_query()
        elif code == 3:
            self._handle_btn_new()
        else:    
            idaapi.warning("wtf?")

    INSTANCE = None

    @staticmethod
    def open():
        if QueryForm.INSTANCE is None:
            form = QueryForm()
            form.modal = False
            form, _ = form.Compile()
            QueryForm.INSTANCE = form
        return QueryForm.INSTANCE.Open()

if __name__ == "__main__":
    QueryForm().open()