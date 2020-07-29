#!/usr/bin/env python

try:
    from idaapi import *
except:
    import sys, os, argparse, subprocess, logging, threading, time, signal

    sigint_count = 0
    cur_thread_count = 0

    def sig_handler(signum, frame):
        global sigint_count
        global cur_thread_count

        msg = "SIGINT: "
        if not sigint_count:
            logging.warning("%saborting..." % msg)
        else:
            if sigint_count > 2:
                logging.error("DUDE WHY DON'T YOU JUST CHILL!?!?")
            logging.warning("%sI am alive and waiting for %d IDA instances to finish" % (msg, cur_thread_count))

        sigint_count += 1
        return

    def process_files(ida_path, in_path, out_path, script_path, threads, compress):
        global cur_thread_count

        if threads < 1:
            return

        input_files = list()
        for root, dirs, files in os.walk(in_path):
            for f in files:
                input_files.append(os.path.join(root, f))

        total_files = len(input_files)
        cur_file = 0

        logging.info("Starting to process %d files (max %d concurrent threads)" % (total_files, threads))

        lock = threading.Lock()
        thread_exit_evt = threading.Event()       
        signal.signal(signal.SIGINT, sig_handler)

        while not sigint_count and len(input_files):
            with lock:
                n = cur_thread_count
            while n < threads:
                if not len(input_files):
                    break
                f = input_files.pop(0)
                cur_file += 1
                cmdline = "%s -o\"%s\" -A -c %s -S\"%s\" \"%s\"" % (
                            ida_path,
                            os.path.join(out_path, os.path.basename(f))+".idb",
                            "-P+" if compress else "",
                            script_path,
                            f)
                logging.debug("Running %s" % cmdline)
                logging.info("Thread %d/%d: processing file %d/%d - \"%s\"" % (threading.active_count(),
                                                                            threads,
                                                                            cur_file,
                                                                            total_files,
                                                                            f))
                with lock:
                    cur_thread_count += 1
                ida_instance(cmdline, thread_exit_evt, lock).start()
                with lock:
                    n = cur_thread_count

            logging.debug("Threshold reached / no more files in queue. Waiting...")
            while not sigint_count and not thread_exit_evt.wait(1.0):
                pass
            thread_exit_evt.clear()

        with lock:
            n = cur_thread_count

        while n > 0:
            logging.info("Waiting for %d more IDA instances to finish" % (n))
            while not thread_exit_evt.wait(1):
                pass
            thread_exit_evt.clear()
            with lock:
                n = cur_thread_count

        return

    class ida_instance(threading.Thread):
        def __init__(self, cmdline, thread_exit_evt, lock):
            threading.Thread.__init__(self)
            self.cmdline = cmdline
            self.thread_exit_evt = thread_exit_evt
            self.lock = lock
            return

        def run_ida_instance(self):
            global cur_thread_count

            cp = subprocess.run(self.cmdline)
            logging.debug("IDA instance terminated (exit code %d)" % (cp.returncode))
            with self.lock:
                cur_thread_count -= 1
            self.thread_exit_evt.set()
            return cp.returncode

        def run(self):
            self.run_ida_instance()
            return

    def run_batch_mode():
        parser = argparse.ArgumentParser()
        parser.add_argument("idapath",
                            type=str,
                            help="path to IDA executable (ida/ida64/idat/idat64/...)")
        parser.add_argument("inpath",
                            type=str, 
                            help="input path containing files to scan")
        parser.add_argument("outpath",
                            type=str, 
                            help="output path. idb/i64 files and logs will be stored here")
        parser.add_argument("-t", "--threads", type=int,
                            default=3,
                            help="maximum number of concurrent IDA instances (default=3)")
        parser.add_argument("-l", "--loglevel", type=str,
                            default="INFO",
                            help="log level: INFO, DEBUG (default: INFO)")
        parser.add_argument("-c", "--compress", action="store_true",
                            help="compress IDA database")
        args = parser.parse_args()

        numeric_level = getattr(logging, args.loglevel.upper(), None)
        if not isinstance(numeric_level, int):
            raise ValueError('Invalid log level: %s' % loglevel)    

        logging.basicConfig(
            format="[%(asctime)s] [%(levelname)s]\t%(message)s",
            level=numeric_level,
            datefmt="%H:%M:%S")

        script_path = os.path.abspath(sys.argv[0])

        if " " in script_path:
            logging.error("This script must not be run from a path that contains whitespace characters!")
            sys.exit(1)

        process_files(args.idapath, args.inpath, args.outpath, script_path, args.threads, args.compress)
        logging.info("Exiting")
        return

    run_batch_mode()
    sys.exit(0)


# IDAPython specific code starts here
import hr_toolbox as tb
import logging

def get_callers_to(func_name):
    """returns list of functions calling 'func_name'"""

    ea = get_name_ea(BADADDR, func_name)
    if ea == BADADDR:
        # return empty list
        return list()
    
    xrefs = CodeRefsTo(ea, False)
    funcs = [get_func(xref).start_ea for xref in xrefs if get_func(xref)]
    return list(set(funcs))

def run_query_02():
    logging.info("-" * 80)
    logging.info("Query start: 0x3300")

    q = lambda func, item: (item.op is cot_num and 
                            item.numval() == 0x3300)

    matches = tb.query_db(q)

    if len(matches):
        for m in matches:
            logging.info("Match: %s" % m)
    else:
        logging.info("Nothing found")

    logging.info("Query end: 0x3300")
    logging.info("-" * 80)
    return True


def run_query_01():
    """find calls to WinHttpSetOption() where 2nd argument has the
    WINHTTP_OPTION_SECURITY_FLAGS flags set
    """

    logging.info("-" * 80)
    logging.info("Query start: WinHttpSetOption")

    callsites = get_callers_to("WinHttpSetOption")
    if len(callsites):
        q = lambda func, item: (item.op is cot_call and 
                                item.x.op is cot_obj and
                                get_name(item.x.obj_ea) == "WinHttpSetOption" and
                                item.a[1].op is cot_num and
                                item.a[1].numval() & 0x1f == 0x1f)
        matches = tb.query(q, ea_list=callsites)

        if len(matches):
            for m in matches:
                logging.info("Match: %s" % m)
        else:
            logging.info("No calls resolvable")

    else:
        logging.info("No calls resolvable")   
    logging.info("Query end: WinHttpSetOption")
    logging.info("-" * 80)
    return True

def ida_context_main():
    logging.basicConfig(
        filename="%s.log" % os.path.splitext(get_idb_path())[0],
        format="[ %(asctime)s ] [%(levelname)s]\t%(message)s",
        level=logging.DEBUG,
        datefmt="%Y-%m-%d %H:%M:%S")

    logging.info("=" * 80)
    logging.info("Input file: %s" % get_input_file_path())
    logging.info("IDA database: %s" % get_idb_path())

    if init_hexrays_plugin():

        # taken from alysis.idc
        inf_set_af((inf_get_af() | AF_DODATA | AF_FINAL) & BADADDR)
        auto_mark_range(0, BADADDR, AU_FINAL)

        logging.info("Waiting for disassembly to finish")
        auto_wait()
        logging.info("Done")
        logging.info("Running queries now")

        # queries go here
        run_query_01()
        run_query_02()

    else:
        logging.error("Decompiler unavailable")

    logging.info("Scan process completed. Exiting.\n")
    qexit(0)
    return

ida_context_main()
