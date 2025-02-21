# XC-DUMPER
## POC that we can dump passwords from unlocked KeepassXC [from process memory]

## INFO:
1) Supports only Windows
2) Supports minidump dump format

## INSTALL:
```Python
python.exe -m pip install -r requirements.txt
```

## ARGS:
```
-h 
	for print HELP
-proc <procname.exe> 
	for dumping opened XS process by process name
-file <filepath>
	for parsing already dumped process
-pid <pid>
	for dumping opened XS process by pid 
```

## USAGE:
```Python
#Using process name
python.exe main.py -proc KeepassXC.exe

#Using dump file
python.exe main.py -file dumped_proc.dmp

#Using process pid
python.exe main.py -pid 9012
```