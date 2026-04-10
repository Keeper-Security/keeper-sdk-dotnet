# PowerCommanderStorageUtils

SQLite vault storage helper for PowerCommander when `-UseOfflineStorage` is used. Build this project and copy its output (and dependencies) into the `StorageUtils` folder under the **PowerCommander module directory** so the offline-storage helper can load from a dedicated location.

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

3. **Copy into PowerCommander** (`StorageUtils` subfolder):
   ```bash
   cp PowerCommanderStorageUtils/bin/publish-<rid>/*.dll "PowerCommander/StorageUtils/"
   cp PowerCommanderStorageUtils/bin/publish-<rid>/libe_sqlite3.dylib "PowerCommander/StorageUtils/"   # macOS
   # Windows: copy e_sqlite3.dll into "PowerCommander/StorageUtils/" instead
   ```

   Required files in `PowerCommander/StorageUtils/`:
   - PowerCommanderStorageUtils.dll
   - Microsoft.Data.Sqlite.dll
   - SQLitePCLRaw.batteries_v2.dll
   - SQLitePCLRaw.core.dll
   - SQLitePCLRaw.provider.e_sqlite3.dll
   - libe_sqlite3.dylib (macOS), e_sqlite3.dll (Windows), or libe_sqlite3.so (Linux)

If `PowerCommanderStorageUtils.dll` or its SQLite dependencies are not found in `PowerCommander/StorageUtils/`, an error is thrown **only when you use** `Connect-Keeper -UseOfflineStorage`.
