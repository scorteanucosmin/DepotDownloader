// This file is subject to the terms and conditions defined
// in file 'LICENSE', which is part of this source code package.

using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using ProtoBuf;

namespace DepotDownloader;

[ProtoContract]
class DepotConfigStore
{
    [ProtoMember(1)]
    public Dictionary<uint, ulong> InstalledManifestIDs { get; private set; }

    string FileName;

    DepotConfigStore()
    {
        InstalledManifestIDs = [];
    }

    static bool Loaded
    {
        get { return Instance != null; }
    }

    public static DepotConfigStore Instance;

    public static void LoadFromFile(string filename)
    {
        if (Loaded)
        {
            return;
        }

        if (File.Exists(filename))
        {
            using FileStream fs = File.Open(filename, FileMode.Open);
            using DeflateStream ds = new(fs, CompressionMode.Decompress);
            Instance = Serializer.Deserialize<DepotConfigStore>(ds);
        }
        else
        {
            Instance = new DepotConfigStore();
        }

        Instance.FileName = filename;
    }

    public static void Save()
    {
        if (!Loaded)
            throw new Exception("Saved config before loading");

        using FileStream fs = File.Open(Instance.FileName, FileMode.Create);
        using DeflateStream ds = new(fs, CompressionMode.Compress);
        Serializer.Serialize(ds, Instance);
    }
}