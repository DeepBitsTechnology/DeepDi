# ---------------------------------------------------------------------
# ida_deepdi.py - IDA Deepdi classes
# ---------------------------------------------------------------------


import ida_kernwin

import ida_netnode
import ida_pro
import ida_ua

import idc
import time
import sys
from deepdi_module import DD
import ctypes
import idaapi

DEBUG = False  # print debug statements

IDA_SDK_VERSION = ida_pro.IDA_SDK_VERSION
BADADDR = idc.BADADDR
BADNODE = ida_netnode.BADNODE
PLUGIN = True
LOADER = not PLUGIN
AUTO_WAIT = True


class Cancelled(Exception):
    pass


class FileError(Exception):
    pass


class MultipleAddressSpacesNotSupported(Exception):
    pass


class IdaDeepDi:
    def __init__(self, arg):
        self.autorun = False if arg == 0 else True
        self.debug = DEBUG
        self.elements = {}
        self.counters = []
        self.tags = []
        self.xmlfile = 0
        self.options = None

    def cleanup(self):
        """
        Frees memory and closes message box and XML file at termination.
        """
        if self.options != None:
            self.options.Free()
        ida_kernwin.hide_wait_box()

    def is_int(self, s):
        try:
            int(s, 16)
            return True
        except:
            return False


class DeepdiImporter(IdaDeepDi):
    """
    DeepDi importer class.
    """

    def __init__(self, as_plugin, key, arg=0):
        """
        Initializes the XmlImporter attributes

        Args:
            as_plugin:
            debug:
        """
        IdaDeepDi.__init__(self, arg)
        self.plugin = as_plugin
        self.timers = dict()
        self.addr_mode = 1
        self.create = True
        self.dataseg = None
        self.deferred = []
        self.key = key

    def start(self):
        displayMenu = self.autorun == False
        self.get_options(displayMenu)
        if self.options.Instructions.checked:
            self.process_instructions()
        if self.options.Functions.checked:
            self.process_functions()
        if self.options.Analysis.checked:
            idc.msg('Waiting for auto analysis.\n')
            ida_kernwin.show_wait_box('Waiting for auto analysis.')
            self.set_timer('waiting')
            idc.auto_wait()
            idc.msg('Auto analysis finished!\n')
            ida_kernwin.hide_wait_box()
            self.display_total_time('waiting')

    def get_options(self, display):

        """
        Displays the options menu and retrieves the option settings.
        """
        fmt = "HELP\n"
        fmt += "XML PROGRAM loader/importer plugin (Python)\n"
        fmt += "IDA SDK: " + str(IDA_SDK_VERSION) + "\n\n"
        fmt += "The XML PROGRAM loader loads elements from a "
        fmt += "XML <PROGRAM> document to create an idb database.\n\n"
        fmt += "ENDHELP\n"
        fmt += "Import from XML PROGRAM document...."
        fmt += "\n <##Options##Instructions:{Instructions}>"
        fmt += "\n <Functions:{Functions}>"
        fmt += "\n <Auto Analysis:{Analysis}>{cGroup1}>"
        fmt += "\n\n"

        Opts = {'cGroup1': ida_kernwin.Form.ChkGroupControl((
            "Instructions",
            "Functions",
            "Analysis"
        ))}

        self.options = ida_kernwin.Form(fmt, Opts)
        self.options.Compile()

        self.options.Instructions.checked = True
        self.options.Functions.checked = True
        self.options.Analysis.checked = True

        if display == True:
            ok = self.options.Execute()
            if (ok == 0):
                raise Cancelled

    def set_timer(self, item):
        # item = 'functions'
        self.timers[item] = time.clock()

    def display_total_time(self, item):
        idc.msg('elapsed time for %s: %.4fs\n' % (item, time.clock() - self.timers[item]))

    def display_progress(self, current, total, msg):
        txt = '{0} {1}/{2}({3:.2f}%) finished.'.format(msg, current, total, current * 100 / float(total))
        ida_kernwin.hide_wait_box()
        ida_kernwin.show_wait_box(txt)

    def process_functions(self):
        item = 'functions'
        self.set_timer(item)
        functions = self.generate_functions()
        self.display_total_time(item)
        self.set_timer(item)
        self.import_functions(functions)
        self.display_total_time(item)

    def generate_functions(self):
        KEY = self.key
        binary_file = idaapi.get_input_file_path()
        functions = []  # eg: [{'entry_point':xxx}]
        idc.msg("DeepDi started...\n")
        ida_kernwin.show_wait_box('Generating functions...')

        try:
            DD.Initialize(KEY)
            batch_size = 1024 * 128
            with DD.Open(binary_file) as file_data:
                for sec in file_data.sections.iter(DD.Section):
                    if not sec.executable:
                        continue
                    # print(sec.name)

                    for sec_addr in range(sec.start, sec.end, batch_size):
                        text_result = file_data.disassemble(sec_addr, sec_addr + batch_size, False)

                        for data in text_result.functions.iter(ctypes.c_int64):
                            # print(data.value)
                            entry_point = '{:x}'.format(data.value)
                            functions.append({'entry_point': entry_point})
        except:
            idc.msg('Function generation failed!')
            idc.msg(sys.exc_info())

        else:
            idc.msg("generated {} functions successfully!\n".format(len(functions)))
        finally:
            ida_kernwin.hide_wait_box()

        return functions

    def import_functions(self, functions):
        idc.msg('\nImporting {} functions: \n'.format(len(functions)))

        i = 0
        total = len(functions)
        for function in functions:
            i += 1
            if i % 5000 == 0:
                self.display_progress(i, total, 'Importing functions')

            addrstr = function['entry_point']
            if ":" in addrstr:
                [segstr, offset_str] = addrstr.split(':')
                offset = int(offset_str, 16)
                if self.is_int(segstr):
                    sgmt = int(segstr, 16)
                    addr = (sgmt << 4) + offset
                else:
                    # multiple address spaces not currently implemented
                    addr = BADADDR
                idc.add_func(addr, BADADDR)
            else:
                idc.add_func(int(addrstr, 16), BADADDR)
        idc.msg('Done.\n')
        ida_kernwin.hide_wait_box()

    def process_instructions(self):
        item = 'instructions'
        address_list = self.generate_instructions()

        self.set_timer(item)
        self.import_instructions(address_list)
        self.display_total_time(item)

    def generate_instructions(self):

        ida_kernwin.show_wait_box('Generating instructions...')
        KEY = self.key
        binary_file = idaapi.get_input_file_path()
        DD.Initialize(KEY)
        batch_size = 1024 * 1024
        try:
            with DD.Open(binary_file) as file_data:

                address_list = []

                for sec in file_data.sections.iter(DD.Section):
                    if not sec.executable:
                        continue
                    # print(sec.name)
                    for sec_addr in range(sec.start, sec.end, batch_size):
                        text_result = file_data.disassemble(sec_addr, sec_addr + batch_size, False)
                        for data in text_result.disassembly.iter(DD.Disassembly):
                            length = data.instruction.length
                            address = data.address
                            # address_list.append('{:x}'.format(address))
                            address_list.append(address)
        except:
            idc.msg('Instructions generation failed!\n')
            idc.msg(sys.exc_info())

        else:
            idc.msg("generated {} instructions successfully!\n".format(len(address_list)))
        finally:
            ida_kernwin.hide_wait_box()

        return address_list

    def import_instructions(self, address_list):
        idc.msg('\nImporting {} instructions: \n'.format(len(address_list)))

        i = 0
        total = len(address_list)
        for address in address_list:
            i += 1
            if i % 100000 == 0:
                self.display_progress(i, total, 'Importing instructions')
            length = ida_ua.create_insn(address)
        i = 0
        total = len(address_list)
        for address in address_list:
            i += 1
            if i % 100000 == 0:
                self.display_progress(i, total, 'Importing instructions')
            length = ida_ua.create_insn(address)

    def generate_sections(self):
        KEY = self.key
        binary_file = idaapi.get_input_file_path()
        sections = []
        idc.msg("DeepDi started...\n")
        ida_kernwin.show_wait_box('Generating sections...')

        try:
            DD.Initialize(KEY)
            with DD.Open(binary_file) as file_data:
                for sec in file_data.sections.iter(DD.Section):
                    #         ('start', ctypes.c_int64),
                    #         ('end', ctypes.c_int64),
                    #         ('name', String),
                    #         ('writable', ctypes.c_bool),
                    #         ('executable', ctypes.c_bool),
                    mysec = {}

                    mysec['start'] = sec.start
                    mysec['end'] = sec.end
                    mysec['offset'] = sec.offset
                    mysec['name'] = str(sec.name)
                    mysec['writable'] = sec.writable
                    mysec['executable'] = sec.executable

                    # mysec['size'] = sec.end - sec.start + 1
                    sections.append(mysec)
        except:
            idc.msg('Sections generation failed!')
            print(sys.exc_info())

        else:
            idc.msg("generated {} sections successfully!\n".format(len(sections)))
        finally:
            ida_kernwin.hide_wait_box()

        return sections
