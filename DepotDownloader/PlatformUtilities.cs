// This file is subject to the terms and conditions defined
// in file 'LICENSE', which is part of this source code package.

using System.IO;
using System.Runtime.InteropServices;

namespace DepotDownloader;

static class PlatformUtilities
{
    private const UnixFileMode ModeExecute = UnixFileMode.UserExecute | UnixFileMode.GroupExecute | 
                                             UnixFileMode.OtherExecute;
    
    public static void SetExecutable(string path, bool value)
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return;
        }
        
        UnixFileMode mode = File.GetUnixFileMode(path);
        bool hasExecuteMask = (mode & ModeExecute) == ModeExecute;
        if (hasExecuteMask != value)
        {
            File.SetUnixFileMode(path, value
                ? mode | ModeExecute
                : mode & ~ModeExecute);
        }
    }
}