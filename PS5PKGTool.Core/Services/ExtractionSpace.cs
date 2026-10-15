using System.Runtime.InteropServices;
using ProsperoPkgTool.Containers;

namespace PS5PKGTool.Core.Services;

/// <summary>Disk space an extraction needs compared with what the destination volume has free.</summary>
/// <param name="RequiredBytes">Bytes the extracted files take on disk (file sizes rounded up to whole clusters).</param>
/// <param name="DataBytes">Sum of the file sizes; the extraction cannot succeed with less free space than this.</param>
/// <param name="FileCount">Number of files that will be written.</param>
/// <param name="AvailableBytes">Free bytes on the destination volume for the current user, or -1 when unknown.</param>
/// <param name="Volume">The destination volume (drive root or share) the free space was read from.</param>
public sealed record ExtractionSpaceEstimate(long RequiredBytes, long DataBytes, int FileCount, long AvailableBytes, string Volume)
{
    public bool IsKnownToFit => AvailableBytes >= 0 && RequiredBytes <= AvailableBytes;
    public bool IsKnownNotToFit => AvailableBytes >= 0 && RequiredBytes > AvailableBytes;
    public long Shortfall => Math.Max(0, RequiredBytes - Math.Max(0, AvailableBytes));
}

public static class ExtractionSpace
{
    // NTFS / exFAT default cluster size; every non-empty file occupies at least one cluster.
    private const long ClusterSize = 4096;

    /// <summary>
    /// Estimate the space extracting <paramref name="packagePath"/> into <paramref name="destination"/>
    /// needs, using the engine's lazy reader (inner-PFS metadata only, no file data is decoded), so it
    /// is quick even for multi-GB packages. Returns null when the package cannot be read this way
    /// (not a finalized debug package, wrong passcode...); the extraction itself reports those errors.
    /// </summary>
    public static ExtractionSpaceEstimate? EstimatePackage(string packagePath, string destination,
        string? passcode = null)
    {
        long required = 0;
        long data = 0;
        int files = 0;
        try
        {
            using ProsperoFileBackedPackage package = ProsperoPackageContent.ReadFileBacked(
                Path.GetFullPath(packagePath), string.IsNullOrEmpty(passcode) ? null : passcode);
            foreach (ProsperoInnerPfsReader.Entry entry in package.Entries)
            {
                if (entry.IsDirectory) continue;
                required += OnDisk(entry.Size);
                data += entry.Size;
                files++;
            }
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException
                                       or NotSupportedException or ArgumentException
                                       or System.Security.Cryptography.CryptographicException)
        {
            return null;
        }

        (long available, string volume) = FreeSpace(destination);
        return new ExtractionSpaceEstimate(required, data, files, available, volume);
    }

    /// <summary>
    /// Throw before anything is written when <paramref name="dataBytes"/> (the plain sum of the file
    /// sizes, a lower bound of what the extraction writes) cannot fit on the volume holding
    /// <paramref name="destination"/>, so a full disk fails at once instead of part-way through.
    /// </summary>
    public static void ThrowIfNotEnoughSpace(long dataBytes, string destination)
    {
        (long available, string volume) = FreeSpace(destination);
        if (available >= 0 && dataBytes > available)
            throw new IOException(
                $"Not enough free disk space on {volume}: the extracted files need {Format(dataBytes)}, " +
                $"but only {Format(available)} is free. Free up {Format(dataBytes - available)} or choose another folder.");
    }

    /// <summary>Bytes a file of <paramref name="size"/> bytes occupies, rounded up to whole clusters.</summary>
    public static long OnDisk(long size) => (size + ClusterSize - 1) / ClusterSize * ClusterSize;

    /// <summary>
    /// Free bytes available to the current user on the volume that holds <paramref name="path"/> (which
    /// need not exist yet: the nearest existing parent is used), or -1 when it cannot be read.
    /// </summary>
    public static (long AvailableBytes, string Volume) FreeSpace(string path)
    {
        string? directory = Path.GetFullPath(path);
        while (directory is not null && !Directory.Exists(directory))
            directory = Path.GetDirectoryName(directory);
        if (directory is null) return (-1, Path.GetPathRoot(Path.GetFullPath(path)) ?? path);
        string volume = Path.GetPathRoot(directory) ?? directory;

        try
        {
            // GetDiskFreeSpaceEx honours quotas and works for UNC shares and mounted folders.
            if (OperatingSystem.IsWindows() &&
                GetDiskFreeSpaceEx(directory, out ulong available, out _, out _))
                return ((long)Math.Min(available, long.MaxValue), volume);
            return (new DriveInfo(volume).AvailableFreeSpace, volume);
        }
        catch (Exception ex) when (ex is IOException or ArgumentException or UnauthorizedAccessException)
        {
            return (-1, volume);
        }
    }

    /// <summary>Human-readable size (binary units), e.g. "2.27 GB".</summary>
    public static string Format(long bytes)
    {
        string[] units = ["B", "KB", "MB", "GB", "TB"];
        double value = Math.Max(0, bytes);
        int unit = 0;
        while (value >= 1024 && unit < units.Length - 1) { value /= 1024; unit++; }
        return $"{value:0.##} {units[unit]}";
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetDiskFreeSpaceEx(string directoryName, out ulong freeBytesAvailable,
        out ulong totalNumberOfBytes, out ulong totalNumberOfFreeBytes);
}
