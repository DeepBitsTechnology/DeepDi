from binaryninja import *
import time
import sys
import os
import traceback
sys.path.append(os.path.dirname(__file__))
from deepdi_module import DD
import ctypes

KEY = b'1234456'
DRBINARY_PREFIX = 'DeepDi-'
DRBINARY_GROUP = 'DeepDi\\'


class New_thread_starter(BackgroundTaskThread):
    def __init__(self, function, *args):
        BackgroundTaskThread.__init__(self, "new background thread", False)
        self.function = function
        self.args = args

    def run(self):
        self.function(*self.args)


class DeepdiImporter():
    """
    DeepDi importer class.
    """

    def __init__(self, bv, key):
        self.bv = bv
        self.timers = dict()
        self.key = key

    def get_options(self, display):

        pass

    def set_timer(self, item):
        # item = 'functions'
        self.timers[item] = time.process_time()

    def display_total_time(self, item):
        log_info('elapsed time for %s: %.4fs' % (item, time.process_time() - self.timers[item]))

    def display_progress(self, current, total, msg):
        pass
        txt = '{0} {1}/{2}({3:.2f}%) finished.'.format(msg, current, total, current * 100 / float(total))

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
        binary_file = self.bv.file.filename.encode()
        functions = []  # eg: [{'entry_point':xxx}]
        log_info("DeepDi started...\n")
        # ida_kernwin.show_wait_box('Generating functions...')

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
                            entry_point = data.value
                            functions.append({'entry_point': entry_point})  # int64/long/int
        except:
            log_error('Function generation failed!')
            traceback.print_exc()

        else:
            log_info("generated {} functions successfully!\n".format(len(functions)))
        finally:
            # ida_kernwin.hide_wait_box()
            pass
        return functions

    def import_functions(self, functions):
        bv = self.bv
        log_info('\nImporting {} functions: \n'.format(len(functions)))

        i = 0
        total = len(functions)
        for function in functions:
            i += 1
            if i % 5000 == 0:
                self.display_progress(i, total, 'Importing functions')

            addr = function['entry_point']

            bv.add_function(addr)

        log_info('Done.\n')

    def process_instructions(self):
        item = 'instructions'
        address_list = self.generate_instructions()

        self.set_timer(item)
        self.import_instructions(address_list)
        self.display_total_time(item)

    def generate_instructions(self):

        log_info('Generating instructions...')
        KEY = self.key
        binary_file = self.bv.file.filename
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
                            address_list.append(address)
        except:
            log_error('Instructions generation failed!\n')
            print(sys.exc_info())

        else:
            log_info("generated {} instructions successfully!\n".format(len(address_list)))
        finally:
            pass

        return address_list

    def import_instructions(self, address_list):
        log_error('This functions is not avaliable yet.')


def start_deepdi(bv, action):
    """
    :param bv: Binary View
    :param action: what to do, 'instructions' or 'functions'
    :return: None
    """
    dd = DeepdiImporter(bv, KEY)
    if action == 'functions':
        dd.process_functions()


# PluginCommand.register(DRBINARY_GROUP + 'Generate instructions', '',
#                        lambda bv: New_thread_starter(start_deepdi, bv, 'instructions').start())

PluginCommand.register(DRBINARY_GROUP + 'Generate functions', '',
                       lambda bv: New_thread_starter(start_deepdi, bv, 'functions').start())
