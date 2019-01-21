# PostgreSQLService-windows
A PostgreSQL service for Windows

## Build Instructions

### Requirements:
- Visual Studio 2017

Open PostgreSQLService.sln and build it.

## Install Instructions

### Requirements:
- PostgreSQL should be in the PATH

1. There will be two .exe files in the Release folder, copy these to be **next to** the `data` directory.
2. Open and administrative prompt and `cd` to the director containing the binaries.
3. Run `PostgreSQLServiceInstaller.exe /I:<directory>` where `<directory>` is the directory containing the `data` directory.

The program should exit in a matter of seconds. If it takes longer, press [ENTER], an error will be written to PostgreSQLServiceInstaller.log.
