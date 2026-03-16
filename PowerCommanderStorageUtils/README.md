# PowerCommanderStorageUtils

SQLite vault storage helper for PowerCommander when `-UseOfflineStorage` is used. Build this project and place its output (and dependencies) in **PowerCommander/PowerCommanderStorageUtils/** so that DLLs are loaded only from that subfolder.

## Build and deploy

1. **Build** (from repo root):
   ```bash
   dotnet build PowerCommanderStorageUtils/PowerCommanderStorageUtils.csproj
   ```

2. **macOS / Linux:** Publish so the native SQLite library is included:
   ```bash
   export RID=osx-arm64   # or osx-x64, linux-x64, etc.
   dotnet publish PowerCommanderStorageUtils/PowerCommanderStorageUtils.csproj -c Debug -r $RID -o PowerCommanderStorageUtils/bin/publish-$RID
   ```

3. **Copy into PowerCommander:** Create the subfolder and copy DLLs there:
   ```bash
   mkdir -p PowerCommander/PowerCommanderStorageUtils
   cp PowerCommanderStorageUtils/bin/publish-<rid>/*.dll PowerCommander/PowerCommanderStorageUtils/
   cp PowerCommanderStorageUtils/bin/publish-<rid>/libe_sqlite3.dylib PowerCommander/PowerCommanderStorageUtils/   # macOS
   # Windows: copy e_sqlite3.dll instead
   ```

   Required files in `PowerCommander/PowerCommanderStorageUtils/`:
   - PowerCommanderStorageUtils.dll
   - Microsoft.Data.Sqlite.dll
   - SQLitePCLRaw.batteries_v2.dll
   - SQLitePCLRaw.core.dll
   - SQLitePCLRaw.provider.e_sqlite3.dll
   - libe_sqlite3.dylib (macOS) or e_sqlite3.dll (Windows)

If these files are not found in `PowerCommanderStorageUtils/`, an error is thrown **only when you use** `Connect-Keeper -UseOfflineStorage`.
