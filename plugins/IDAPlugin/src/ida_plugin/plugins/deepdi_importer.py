# ---------------------------------------------------------------------
# deepdi_importer.py - IDA DeepDi Importer plugin
# ---------------------------------------------------------------------
"""
This file must be placed in the IDA plugins directory.
The file ida_deepdi.py must be placed in the IDA python directory.
"""

import ida_idaapi
import ida_deepdi
import idc
import sys

KEY = b'123456'

BADADDR = idc.BADADDR


class DeepdilImporterPlugin(ida_idaapi.plugin_t):
    """
    DeepDi Importer plugin class
    """
    flags = 0
    comment = "Import DeepDi functions and code blocks"
    help = "Import DeepDi functions and code blocks"
    wanted_name = "Deepdi Importer"
    wanted_hotkey = "Ctrl-Alt-K"

    def init(self):
        return ida_idaapi.PLUGIN_OK

    def run(self, arg):
        st = idc.set_ida_state(idc.IDA_STATUS_WORK)
        deepdi = ida_deepdi.DeepdiImporter(key=KEY, as_plugin=True)
        try:
            deepdi.start()

        except:
            msg = "***** Exception occurred: DeepDi Importer failed! *****"
            print "\n" + msg + "\n", sys.exc_type, sys.exc_value
            idc.warning(msg)
            import traceback
            traceback.print_exc()

        finally:
            deepdi.cleanup()
            idc.set_ida_state(st)

    def term(self):
        pass


def PLUGIN_ENTRY():
    return DeepdilImporterPlugin()
