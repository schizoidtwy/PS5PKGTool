using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.ExceptionServices;
using PS5PKGTool.Core.Builders;
using PS5PKGTool.Core.Models;
using PS5PKGTool.Core.Parsers;

namespace PS5PKGTool.Core.Services;

public readonly record struct SonyPackageExtractProgress(long CompletedBytes, long TotalBytes, string CurrentPath);
public sealed class SonyPackageExtractResult
{
    public required string Destination { get; init; }
    public required int FileCount { get; init; }
    public required long ExtractedBytes { get; init; }
}

public static class SonyPackageExtraction
{
    public static async Task<SonyPackageExtractResult> ExtractAsync(string packagePath, string destination,
        string passcode = SonyDebugPackageCredentials.DefaultPasscode,
        IProgress<SonyPackageExtractProgress>? progress = null, CancellationToken cancellationToken = default)
    {
        string output = Path.GetFullPath(destination);
        if (Directory.Exists(output)) throw new IOException("The extraction destination already exists: " + output);
        string fullPackage = Path.GetFullPath(packagePath);
        SonyPkgSummary package = new SonyPkgReader().Read(fullPackage, passcode);
        var game = new Ps5GameInfo
        {
            SourceKind = Ps5SourceKind.SonyPackage,
            RootPath = fullPackage,
            Package = package,
        };
        string staging = output + ".extracting." + Guid.NewGuid().ToString("N");
        long completed = 0;
        long total;
        int fileCount;
        try
        {
            Directory.CreateDirectory(staging);

            // Use the exact file set the file browser and the convert pipeline use: the inner PFS
            // merged with the readable CNT metadata (param.json, artwork, trophies, activities...),
            // with the PFS's own flat-path/AFID index tables excluded. Extract, Convert and the
            // browser therefore agree, every readable file is written, and the internal tables never
            // appear in the output.
            using IReadOnlyGameFileSystem files = GameFileSystem.Open(game, cancellationToken);
            GameFileRecord[] wanted = files.Files
                .Where(file => file.RelativePath.Length > 0)
                .ToArray();
            if (wanted.Length == 0)
                throw new InvalidDataException(
                    "The package does not expose any readable files (it may be retail or require a passcode).");

            total = wanted.Sum(file => file.Size);
            fileCount = wanted.Length;
            ExtractionSpace.ThrowIfNotEnoughSpace(total, staging);

            // Read in source order when the file system supports batch reads: each compressed block is
            // then decoded once and the package is scanned front to back, by several workers that each
            // own a reader. The order files are written in does not change the extracted tree.
            Func<IGameFileBatchReader> openReader;
            int workers;
            if (files is IBatchReadableGameFileSystem batchable)
            {
                wanted = batchable.OrderForSequentialRead(wanted);
                openReader = batchable.OpenBatchReader;
                workers = Math.Clamp(Environment.ProcessorCount, 2, MaxWorkers);
            }
            else
            {
                openReader = () => new DirectReader(files);
                workers = 1;
            }

            completed = await CopyFilesAsync(wanted, staging, openReader, workers, total, progress, cancellationToken)
                .ConfigureAwait(false);

            Directory.Move(staging, output);
            return new SonyPackageExtractResult { Destination = output, FileCount = fileCount, ExtractedBytes = completed };
        }
        catch
        {
            try { if (Directory.Exists(staging)) Directory.Delete(staging, true); } catch (IOException) { }
            throw;
        }
    }

    // Decoding (outer AES-XTS + Kraken) is CPU-bound and single-threaded per mount, so extraction
    // scales with workers that each own a mount; past ~8 the disk is usually the limit.
    private const int MaxWorkers = 8;
    private const long UnitBytes = 32 * 1024 * 1024;
    private const int BufferSize = 4 * 1024 * 1024;
    private static readonly long ProgressInterval = Stopwatch.Frequency / 10;

    /// <summary>
    /// A slice of work in source order: whole files <c>First .. First + Count - 1</c>, or, when
    /// <see cref="RangeLength"/> is not negative, one range of a single large file so that a big file
    /// is decoded by several workers at once.
    /// </summary>
    private readonly record struct WorkUnit(int First, int Count, long RangeStart = 0, long RangeLength = -1);

    /// <summary>
    /// Copies <paramref name="wanted"/> (already in source order) into <paramref name="root"/>.
    /// Workers take ~32 MiB units in order, so together they still sweep the package front to back,
    /// and each reads and writes its own units, which overlaps decoding with disk writes.
    /// </summary>
    private static async Task<long> CopyFilesAsync(GameFileRecord[] wanted, string root,
        Func<IGameFileBatchReader> openReader, int workers, long total,
        IProgress<SonyPackageExtractProgress>? progress, CancellationToken cancellationToken)
    {
        string[] relatives = wanted.Select(file => GameFileSystem.NormalizePath(file.RelativePath)).ToArray();
        string[] targets = relatives.Select(relative => ResolveContainedPath(root, relative)).ToArray();
        WorkUnit[] units = PlanUnits(wanted);
        workers = Math.Max(1, Math.Min(workers, units.Length));

        var createdDirectories = new ConcurrentDictionary<string, byte>(StringComparer.OrdinalIgnoreCase);
        long completed = 0;
        long lastReport = 0;
        int nextUnit = -1;

        using var failure = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        CancellationToken token = failure.Token;

        void ReportProgress(int fileIndex, bool force)
        {
            if (progress is null) return;
            long now = Stopwatch.GetTimestamp();
            long last = Interlocked.Read(ref lastReport);
            if (!force && (now - last < ProgressInterval || Interlocked.CompareExchange(ref lastReport, now, last) != last))
                return;
            progress.Report(new SonyPackageExtractProgress(Interlocked.Read(ref completed), total, relatives[fileIndex]));
        }

        void CopyRange(IGameFileBatchReader reader, int fileIndex, long start, long length, byte[] buffer)
        {
            string target = targets[fileIndex];
            string directory = Path.GetDirectoryName(target)!;
            // Create before recording it, so another worker never sees a directory that is not there yet.
            if (!createdDirectories.ContainsKey(directory))
            {
                Directory.CreateDirectory(directory);
                createdDirectories.TryAdd(directory, 0);
            }

            long size = wanted[fileIndex].Size;
            // Ranges of one large file are written by several workers through their own handles. The
            // staging folder is new, so OpenOrCreate never meets a file this run did not make.
            using var output = new FileStream(target, FileMode.OpenOrCreate, FileAccess.Write, FileShare.ReadWrite,
                bufferSize: 0, FileOptions.None);
            // Reserving the final size up front lets NTFS allocate the file once instead of growing it.
            if (size > 0 && output.Length != size) output.SetLength(size);
            if (length == 0) return;

            using Stream input = reader.OpenRead(relatives[fileIndex]);
            input.Position = start;
            output.Position = start;
            long done = 0;
            while (done < length)
            {
                token.ThrowIfCancellationRequested();
                int take = (int)Math.Min(buffer.Length, length - done);
                int count = 0;
                while (count < take)
                {
                    int read = input.Read(buffer, count, take - count);
                    if (read <= 0)
                        throw new EndOfStreamException($"Package file '{relatives[fileIndex]}' ended unexpectedly.");
                    count += read;
                }
                output.Write(buffer, 0, count);
                done += count;
                Interlocked.Add(ref completed, count);
                ReportProgress(fileIndex, force: false);
            }
        }

        Task[] tasks = Enumerable.Range(0, workers).Select(_ => Task.Run(() =>
        {
            try
            {
                using IGameFileBatchReader reader = openReader();
                byte[] buffer = new byte[BufferSize];
                while (true)
                {
                    token.ThrowIfCancellationRequested();
                    int index = Interlocked.Increment(ref nextUnit);
                    if (index >= units.Length) return;
                    WorkUnit unit = units[index];
                    for (int fileIndex = unit.First; fileIndex < unit.First + unit.Count; fileIndex++)
                    {
                        bool whole = unit.RangeLength < 0;
                        CopyRange(reader, fileIndex, whole ? 0 : unit.RangeStart,
                            whole ? wanted[fileIndex].Size : unit.RangeLength, buffer);
                    }
                }
            }
            catch
            {
                failure.Cancel();
                throw;
            }
        }, token)).ToArray();

        try
        {
            await Task.WhenAll(tasks).ConfigureAwait(false);
        }
        catch
        {
            // Surface the root cause rather than the cancellations it triggered in the other workers.
            Exception? cause = tasks
                .SelectMany(task => task.Exception?.InnerExceptions ?? [])
                .FirstOrDefault(ex => ex is not OperationCanceledException);
            if (cause is not null) ExceptionDispatchInfo.Throw(cause);
            cancellationToken.ThrowIfCancellationRequested();
            throw;
        }

        ReportProgress(wanted.Length - 1, force: true);
        return completed;
    }

    /// <summary>Groups consecutive small files into ~<see cref="UnitBytes"/> units and splits files
    /// larger than that into ranges, keeping source order.</summary>
    private static WorkUnit[] PlanUnits(GameFileRecord[] wanted)
    {
        var units = new List<WorkUnit>();
        int groupStart = 0;
        long groupBytes = 0;
        for (int index = 0; index < wanted.Length; index++)
        {
            long size = wanted[index].Size;
            if (size > UnitBytes)
            {
                if (index > groupStart) units.Add(new WorkUnit(groupStart, index - groupStart));
                for (long start = 0; start < size; start += UnitBytes)
                    units.Add(new WorkUnit(index, 1, start, Math.Min(UnitBytes, size - start)));
                groupStart = index + 1;
                groupBytes = 0;
                continue;
            }

            groupBytes += size;
            if (groupBytes >= UnitBytes)
            {
                units.Add(new WorkUnit(groupStart, index + 1 - groupStart));
                groupStart = index + 1;
                groupBytes = 0;
            }
        }
        if (groupStart < wanted.Length) units.Add(new WorkUnit(groupStart, wanted.Length - groupStart));
        return units.ToArray();
    }

    /// <summary>Fallback for file systems without batch reads: plain per-file opens, one worker.</summary>
    private sealed class DirectReader(IReadOnlyGameFileSystem files) : IGameFileBatchReader
    {
        public Stream OpenRead(string relativePath) => files.OpenRead(relativePath);
        public void Dispose() { }
    }

    private static string ResolveContainedPath(string root, string relative)
    {
        if (string.IsNullOrWhiteSpace(relative) || Path.IsPathRooted(relative)) throw new InvalidDataException("Package path is unsafe.");
        string rootFull = Path.GetFullPath(root) + Path.DirectorySeparatorChar;
        string target = Path.GetFullPath(Path.Combine(root, relative.Replace('/', Path.DirectorySeparatorChar)));
        if (!target.StartsWith(rootFull, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("Package path escapes the extraction root.");
        return target;
    }
}
