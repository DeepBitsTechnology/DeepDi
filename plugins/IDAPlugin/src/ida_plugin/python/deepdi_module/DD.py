import ctypes
import os

dir = os.path.dirname(__file__)
DLL_PATH = str(os.path.join(dir, 'Disassembler.dll'))


class Bxty(ctypes.Union):
    _fields_ = [
        ('_Buf', ctypes.c_char * 16),
        ('_Ptr', ctypes.c_char_p)
    ]


class String(ctypes.Structure):
    '''
    	value_type *_Myptr()
		{	// determine current pointer to buffer for mutable string
		return (this->_BUF_SIZE <= _Myres
			? _Unfancy(_Bx._Ptr)
			: _Bx._Buf);
		}
    '''
    _fields_ = [
        ('_Bx', Bxty),
        # current length of string
        ('_Mysize', ctypes.c_uint64),
        # current storage reserved for string
        ('_Myres', ctypes.c_uint64),
    ]

    def __str__(self):
        if self._Myres >= 16:
            return self._Bx._Ptr.decode('utf-8')
        else:
            # return str(self._Bx._Buf, 'utf-8')
            return str(self._Bx._Buf)
class Section(ctypes.Structure):
    _fields_ = [
        ('start', ctypes.c_int64),
        ('end', ctypes.c_int64),
        ('offset', ctypes.c_int64),
        ('name', String),
        ('writable', ctypes.c_bool),
        ('executable', ctypes.c_bool),
    ]


class Memory(ctypes.Structure):
    _fields_ = [
        ('base', ctypes.c_int32),
        ('index', ctypes.c_int32),
    ]


class OperandData(ctypes.Union):
    _fields_ = [
        ('reg', ctypes.c_int32),
        ('mem', Memory),
    ]


class Operand(ctypes.Structure):
    _fields_ = [
        ('data', OperandData),
        ('type', ctypes.c_int32),
        ('read', ctypes.c_bool),
        ('write', ctypes.c_bool),
    ]


class Instruction(ctypes.Structure):
    _fields_ = [
        ('mnemonic', ctypes.c_int32),
        ('operands', Operand * 10),
        ('length', ctypes.c_int8),
    ]


class Vector(ctypes.Structure):
    _fields_ = [
        ('_Myfirst', ctypes.c_void_p),
        ('_Mylast', ctypes.c_void_p),
        ('_Myend', ctypes.c_void_p),
    ]

    def iter(self, T):
        if self._Myfirst is None:
            return
        for addr in range(self._Myfirst, self._Mylast, ctypes.sizeof(T)):
            yield T.from_address(addr)


class DisassemblyResult(ctypes.Structure):
    _fields_ = [
        ('functions', Vector),
        ('disassembly_text', Vector),
        ('disassembly', Vector),
    ]

    def __del__(self):
        _lib.DisassemblyResultDtor(ctypes.byref(self))


class DisassemblyText(ctypes.Structure):
    _fields_ = [
        ('text', String),
        ('address', ctypes.c_int64),
    ]

    def __str__(self):
        return '<"{}", {:16X}>'.format(self.text, self.address)


class Disassembly(ctypes.Structure):
    _fields_ = [
        ('instruction', Instruction),
        ('address', ctypes.c_int64),
    ]


class FileData(ctypes.Structure):
    _fields_ = [
        ('sections', Vector),
        ('internal_data', ctypes.c_void_p)
    ]

    def __init__(self, *args, **kw):
        # super().__init__(*args, **kw)
        super(ctypes.Structure, self).__init__(*args, **kw)
        self.init = True

    def disassemble(self, start, end, return_string):
        v = DisassemblyResult()
        _lib.FileData_Disassemble(ctypes.byref(self), ctypes.byref(v), start, end, return_string)
        return v

    def __del__(self):
        if self.init:
            _lib.FileDataDtor(ctypes.byref(self))

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        _lib.FileDataDtor(ctypes.byref(self))
        self.init = False


class Library:
    def __init__(self):
        lib = ctypes.cdll.LoadLibrary(DLL_PATH)

        # DisassemblyResult::~DisassemblyResult
        self.DisassemblyResultDtor = lib['??1DisassemblyResult@dd@@QEAA@XZ']
        self.DisassemblyResultDtor.argtypes = [ctypes.POINTER(DisassemblyResult)]
        self.DisassemblyResultDtor.restype = None

        # FileData::~FileData
        self.FileDataDtor = lib['??1FileData@dd@@QEAA@XZ']
        self.FileDataDtor.argtypes = [ctypes.POINTER(FileData)]
        self.FileDataDtor.restype = None

        # FileData::Disassemble
        self.FileData_Disassemble = lib['?Disassemble@FileData@dd@@QEAA?AUDisassemblyResult@2@_J0_N@Z']
        self.FileData_Disassemble.argtypes = [ctypes.POINTER(FileData), ctypes.POINTER(DisassemblyResult),
                                              ctypes.c_int64, ctypes.c_int64, ctypes.c_bool]
        self.FileData_Disassemble.restype = None

        # Initialize
        self.Initialize = lib['?Initialize@dd@@YAXPEBD@Z']
        self.Initialize.argtypes = [ctypes.c_char_p]
        self.Initialize.restype = None

        # Open
        self.Open = lib['?Open@dd@@YA?AUFileData@1@PEBD@Z']
        self.Open.argtypes = [ctypes.POINTER(FileData), ctypes.c_char_p]
        self.Open.restype = None

        # Release
        self.Release = lib['?Release@dd@@YAXXZ']
        self.Release.argtypes = []
        self.Release.restype = None

    def initialize(self, key):
        self.Initialize(key)

    def open(self, path):
        v = FileData()
        self.Open(ctypes.byref(v), path)
        return v

    def release(self):
        self.Release()


_lib = Library()

Initialize = _lib.initialize
Open = _lib.open
Release = _lib.release
