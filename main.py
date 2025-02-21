import os, sys, ctypes, enum, platform, struct, re, psutil
from termcolor import colored

from ctypes.wintypes import HANDLE, BOOL, DWORD, HWND, HINSTANCE, HKEY, LPVOID, LPWSTR, PBOOL
from ctypes import c_ulong, c_char_p, c_int, c_void_p, windll

from minidump.utils.privileges import enable_debug_privilege

x_remove = re.compile(r'\\x')

lib_funcs = ['QWidget', 'background', 'QScrollArea', 'QScrollBar', 'QObject*', 'QGroupBox', 'QProgressBar', 'background-color', 'font-weight', 'border-radius', 'padding', 'QToolButton', 'qlineargradient', 'Segoe UI']

if platform.system() != 'Windows':
	raise Exception('This script will ovbiously only work on Windows')

IS_PYTHON_64 = False if (8 * struct.calcsize("P")) == 32 else True

key_pattern =  '80 00 00 00 00 ?? 00 00 00 ?? 00 00 80 ?? ?? 00 00 18 00 00 00 00 00 00 00'

class MINIDUMP_TYPE(enum.IntFlag):
	MiniDumpNormal						  = 0x00000000
	MiniDumpWithDataSegs					= 0x00000001
	MiniDumpWithFullMemory				  = 0x00000002
	MiniDumpWithHandleData				  = 0x00000004
	MiniDumpFilterMemory					= 0x00000008
	MiniDumpScanMemory					  = 0x00000010
	MiniDumpWithUnloadedModules			 = 0x00000020
	MiniDumpWithIndirectlyReferencedMemory  = 0x00000040
	MiniDumpFilterModulePaths			   = 0x00000080
	MiniDumpWithProcessThreadData		   = 0x00000100
	MiniDumpWithPrivateReadWriteMemory	  = 0x00000200
	MiniDumpWithoutOptionalData			 = 0x00000400
	MiniDumpWithFullMemoryInfo			  = 0x00000800
	MiniDumpWithThreadInfo				  = 0x00001000
	MiniDumpWithCodeSegs					= 0x00002000
	MiniDumpWithoutAuxiliaryState		   = 0x00004000
	MiniDumpWithFullAuxiliaryState		  = 0x00008000
	MiniDumpWithPrivateWriteCopyMemory	  = 0x00010000
	MiniDumpIgnoreInaccessibleMemory		= 0x00020000
	MiniDumpWithTokenInformation			= 0x00040000
	MiniDumpWithModuleHeaders			   = 0x00080000
	MiniDumpFilterTriage					= 0x00100000
	MiniDumpValidTypeFlags				  = 0x001fffff

class WindowsBuild(enum.Enum):
	WIN_XP  = 2600
	WIN_2K3 = 3790
	WIN_VISTA = 6000
	WIN_7 = 7600
	WIN_8 = 9200
	WIN_BLUE = 9600
	WIN_10_1507 = 10240
	WIN_10_1511 = 10586
	WIN_10_1607 = 14393
	WIN_10_1707 = 15063

class WindowsMinBuild(enum.Enum):
	WIN_XP = 2500
	WIN_2K3 = 3000
	WIN_VISTA = 5000
	WIN_7 = 7000
	WIN_8 = 8000
	WIN_BLUE = 9400
	WIN_10 = 9800

def getWindowsBuild():
    class OSVersionInfo(ctypes.Structure):
        _fields_ = [
            ("dwOSVersionInfoSize" , ctypes.c_int),
            ("dwMajorVersion"      , ctypes.c_int),
            ("dwMinorVersion"      , ctypes.c_int),
            ("dwBuildNumber"       , ctypes.c_int),
            ("dwPlatformId"        , ctypes.c_int),
            ("szCSDVersion"        , ctypes.c_char*128)];
    GetVersionEx = getattr( ctypes.windll.kernel32 , "GetVersionExA")
    version  = OSVersionInfo()
    version.dwOSVersionInfoSize = ctypes.sizeof(OSVersionInfo)
    GetVersionEx( ctypes.byref(version) )
    return version.dwBuildNumber

DELETE = 0x00010000
READ_CONTROL = 0x00020000
WRITE_DAC = 0x00040000
WRITE_OWNER = 0x00080000

SYNCHRONIZE = 0x00100000

STANDARD_RIGHTS_REQUIRED = DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER
STANDARD_RIGHTS_ALL = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE

if getWindowsBuild() >= WindowsMinBuild.WIN_VISTA.value:
	PROCESS_ALL_ACCESS = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFFF
else:
	PROCESS_ALL_ACCESS = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFF

FILE_SHARE_READ = 1
FILE_SHARE_WRITE = 2
FILE_SHARE_DELETE = 4
FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
FILE_FLAG_BACKUP_SEMANTICS = 0x2000000

FILE_CREATE_NEW = 1
FILE_CREATE_ALWAYS = 2
FILE_OPEN_EXISTING = 3
FILE_OPEN_ALWAYS = 4
FILE_TRUNCATE_EXISTING = 5

FILE_GENERIC_READ = 0x80000000
FILE_GENERIC_WRITE = 0x40000000
FILE_GENERIC_EXECUTE = 0x20000000
FILE_GENERIC_ALL = 0x10000000


FILE_ATTRIBUTE_READONLY = 0x1
FILE_ATTRIBUTE_HIDDEN = 0x2
FILE_ATTRIBUTE_DIRECTORY = 0x10
FILE_ATTRIBUTE_NORMAL = 0x80
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
GENERIC_READ = 0x80000000
FILE_READ_ATTRIBUTES = 0x80

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

MAX_PATH = 260


"""
class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = (
        ('length', ctypes.wintypes.DWORD),
        ('p_security_descriptor', ctypes.wintypes.LPVOID),
        ('inherit_handle', ctypes.wintypes.BOOLEAN),
        )
LPSECURITY_ATTRIBUTES = ctypes.POINTER(SECURITY_ATTRIBUTES)
"""
Psapi = windll.psapi
GetProcessImageFileName = Psapi.GetProcessImageFileNameA
GetProcessImageFileName.restype = ctypes.wintypes.DWORD
QueryFullProcessImageName = ctypes.windll.kernel32.QueryFullProcessImageNameA
QueryFullProcessImageName.restype = ctypes.wintypes.DWORD
EnumProcesses = Psapi.EnumProcesses
EnumProcesses.restype = ctypes.wintypes.DWORD

LPSECURITY_ATTRIBUTES = LPVOID 
CreateFile = ctypes.windll.kernel32.CreateFileW
CreateFile.argtypes = (
	LPWSTR,
	DWORD,
	DWORD,
    LPSECURITY_ATTRIBUTES,
	DWORD,
	DWORD,
	HANDLE,
    )
CreateFile.restype = ctypes.wintypes.HANDLE

PHANDLE = ctypes.POINTER(HANDLE)
PDWORD = ctypes.POINTER(DWORD)

GetCurrentProcess = ctypes.windll.kernel32.GetCurrentProcess
GetCurrentProcess.argtypes = ()
GetCurrentProcess.restype = HANDLE

IsWow64Process  = ctypes.windll.kernel32.IsWow64Process
IsWow64Process.argtypes = (HANDLE, PBOOL)
IsWow64Process.restype = BOOL

CloseHandle = ctypes.windll.kernel32.CloseHandle
CloseHandle.argtypes = (HANDLE, )
CloseHandle.restype = BOOL

OpenProcess = ctypes.windll.kernel32.OpenProcess
OpenProcess.argtypes = (DWORD, BOOL, DWORD )
OpenProcess.restype = HANDLE

MiniDumpWriteDump = ctypes.windll.DbgHelp.MiniDumpWriteDump
MiniDumpWriteDump.argtypes = (HANDLE , DWORD , HANDLE, DWORD, DWORD, DWORD, DWORD)
MiniDumpWriteDump.restype = BOOL

def is64bitProc(process_handle):
	is64 = BOOL()
	res = IsWow64Process(process_handle, ctypes.byref(is64))
	if res == 0:
		print('Failed to get process version info!')
	return not bool(is64.value)

def enum_pids():

	max_array = c_ulong * 4096 # define long array to capture all the processes
	pProcessIds = max_array() # array to store the list of processes
	pBytesReturned = c_ulong() # the number of bytes returned in the array
	#EnumProcess
	res = EnumProcesses(
		ctypes.byref(pProcessIds),
		ctypes.sizeof(pProcessIds),
		ctypes.byref(pBytesReturned)
	)
	if res == 0:
		return []

	# get the number of returned processes
	nReturned = int(pBytesReturned.value/ctypes.sizeof(c_ulong()))
	return [i for i in pProcessIds[:nReturned]]

def enum_process_names():
	pid_to_name = {}

	for pid in enum_pids():
		pid_to_name[pid] = 'Not found'
		process_handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
		if process_handle is None:
			print('[Enum Processes]Failed to open process PID: %d Reason: %s ' % (pid))
			continue

		image_name = (ctypes.c_char*MAX_PATH)()
		max_path = DWORD(4096)
		#res = GetProcessImageFileName(process_handle, image_name, MAX_PATH)
		res = QueryFullProcessImageName(process_handle, 0 ,image_name, ctypes.byref(max_path))
		if res == 0:
			print('[Enum Proceses]Failed GetProcessImageFileName on PID: %d Reason: %s ' % (pid))
			continue

		pid_to_name[pid] = image_name.value.decode()
	return pid_to_name

def create_dump(pid, output_filename, mindumptype, debug=False):
	if debug:
		print('Enabling SeDebugPrivilege')
		assigned = enable_debug_privilege()
		msg = ['failure', 'success'][assigned]
		print('SeDebugPrivilege assignment %s' % msg)

	print('Opening process PID: %d' % pid)
	process_handle = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
	if process_handle is None:
		print('Failed to open process PID: %d' % pid)
		return
	print('Process handle: 0x%04x' % process_handle)
	is64 = is64bitProc(process_handle)
	if is64 != IS_PYTHON_64:
		print('process architecture mismatch! This could case error! Python arch: %s Target process arch: %s' % ('x86' if not IS_PYTHON_64 else 'x64', 'x86' if not is64 else 'x64'))

	print('Creating file handle for output file')
	file_handle = CreateFile(output_filename, FILE_GENERIC_READ | FILE_GENERIC_WRITE, 0, None,  FILE_CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, None)
	if file_handle == -1:
		print('Failed to create file')
		return
	print('Dumping process to file')
	res = MiniDumpWriteDump(process_handle, pid, file_handle, mindumptype, 0,0,0)
	if not bool(res):
		print('Failed to dump process to file')
	print('Dump file created succsessfully')
	CloseHandle(file_handle)
	CloseHandle(process_handle)

	return output_filename

def help():
	print(colored(r"""
 __    __   ______          _______   __    __  __       __  _______   ________  _______  
|  \  |  \ /      \        |       \ |  \  |  \|  \     /  \|       \ |        \|       \ 
| $$  | $$|  $$$$$$\       | $$$$$$$\| $$  | $$| $$\   /  $$| $$$$$$$\| $$$$$$$$| $$$$$$$\\
 \$$\/  $$| $$___\$$______ | $$  | $$| $$  | $$| $$$\ /  $$$| $$__/ $$| $$__    | $$__| $$
  >$$  $$  \$$    \|      \| $$  | $$| $$  | $$| $$$$\  $$$$| $$    $$| $$  \   | $$    $$
 /  $$$$\  _\$$$$$$\\\$$$$$$| $$  | $$| $$  | $$| $$\$$ $$ $$| $$$$$$$ | $$$$$   | $$$$$$$\\
|  $$ \$$\|  \__| $$       | $$__/ $$| $$__/ $$| $$ \$$$| $$| $$      | $$_____ | $$  | $$
| $$  | $$ \$$    $$       | $$    $$ \$$    $$| $$  \$ | $$| $$      | $$     \| $$  | $$
 \$$   \$$  \$$$$$$         \$$$$$$$   \$$$$$$  \$$      \$$ \$$       \$$$$$$$$ \$$   \$$
	
										by Qeratos""", 'green'))
	print("""------------------------------------------------------------------------------------------
| HELP:
------------------------------------------------------------------------------------------
-h 
	for print HELP
-proc <procname.exe> 
	for dumping opened XS process by process name
-file <filepath>
	for parsing already dumped process
-pid <pid>
	for dumping opened XS process by pid 
""")
	exit()
	
def dump_proc(pid, outfile='dumped'):
	mindumptype = MINIDUMP_TYPE.MiniDumpNormal | MINIDUMP_TYPE.MiniDumpWithFullMemory
	return create_dump(pid, f"{outfile}_{str(pid)}.dmp", mindumptype)

def get_key(data, offset, length):
    return data[offset:offset + length]

def is_ascii(str):
    for char in str:
        ascii_code = ord(char)
        if not (0x20 <= ascii_code <= 0x7E):
            return False  
    return True

def find_pattern(file_path):
    pattern_list = key_pattern.split(' ')
    byte_sequence = []

    for byte in pattern_list:
        if byte == '??':
            byte_sequence.append(None)
        else:
            byte_sequence.append(int(byte, 16))

    with open(file_path, 'rb') as f:
        data = f.read()

    pattern_len = len(byte_sequence)
    matches = []

    with open(f'{file_path[:-4]}_res.txt', 'wt') as res:
        for i in range(len(data) - pattern_len + 1):
            match = True
            real_bytes = []
            
            for j in range(pattern_len):
                if byte_sequence[j] is not None:
                    if data[i + j] != byte_sequence[j]:
                        match = False
                        break
                else:
                    real_bytes.append(data[i + j])
            
            if match:
                result_string = []
                byte_idx = 0
                for j in range(pattern_len):
                    if byte_sequence[j] is not None:
                        result_string.append(f"{byte_sequence[j]:02X}")
                    else:
                        result_string.append(f"{real_bytes[byte_idx]:02X}")
                        byte_idx += 1

                key = get_key(data, i + int(len(key_pattern)/3), int(result_string[5], 16)*2).replace(b'\x00', b'')
                try:
                    key = key.decode('utf-8', errors='ignore')
                    if key:
                        if not re.findall(x_remove, key) and key not in lib_funcs and len(key) > 6 and len(key) < 25 and is_ascii(key):
                            print(f"KEY = {key}")
                            # res.write(f"""Найдено совпадение: {int(result_string[5], 16)} на смещении {hex(i)} ключ: {hex(i + int(len(pattern)/3))} длинна шаблона: {int(len(pattern)/3)}\nKEY: {key}\n""")
                            res.write(f"KEY: {key}\n")
                except:
                    pass
                # print(f"Найдено совпадение: {int(result_string[5], 16)} на смещении {hex(i)} ключ: {hex(i + int(len(pattern)/3))} длинна шаблона: {int(len(pattern)/3)}")
                # print(f"KEY: {get_key(data, i + int(len(pattern)/3), int(result_string[5], 16)*2)}\n")
                matches.append((i, ' '.join(result_string)))

    return matches

def get_pid(name):
	processes = psutil.process_iter(['pid', 'name'])
	for proc in processes:
		try:
			if proc.info['name'] == name:
				print(f"PID: {proc.info['pid']}, Process Name: {proc.info['name']}")
				return proc.info['pid']
		except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):

			pass

def main(args):
	if len(args) < 2 or args[1] == '-h':
		help()
	elif args[1] == '-proc':
		if args[2]:
			pname = args[2]
			print(f'proccess: {pname}')

			pid = get_pid(pname)
			if pid:
				res_file = dump_proc(pid=pid)
				if res_file:
					result = find_pattern(res_file)
			else:
				print(f"Process not finded!")
			
		else:
			help()

	elif args[1] == '-file':
		if args[2]:
			fname = args[2]
			print(f'file: {fname}')
			result = find_pattern(fname)
		else:
			help()

	elif args[1] == '-pid':
		if args[2]:
			pid = args[2]
			print(f'pid: {pid}')

			res_file = dump_proc(pid=int(pid))
			if res_file:
				result = find_pattern(res_file)
		else:
			help()
	else:
		help()


main(sys.argv)