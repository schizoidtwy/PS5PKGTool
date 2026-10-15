using System.Diagnostics;
using System.Runtime.ExceptionServices;
using System.Threading.Channels;
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

            // Read in source order through one shared reader when the file system supports it: each
            // compressed block is then decoded once and the package is scanned front to back. The
            // order files are written in does not change the extracted tree.
            IGameFileBatchReader? batch = null;
            if (files is IBatchReadableGameFileSystem batchable)
            {
                wanted = batchable.OrderForSequentialRead(wanted);
                batch = batchable.OpenBatchReader();
            }

            using (batch)
            {
                Func<string, Stream> openRead = batch is null ? files.OpenRead : batch.OpenRead;
                completed = await CopyFilesAsync(wanted, staging, openRead, total, progress, cancellationToken)
                    .ConfigureAwait(false);
            }

            Directory.Move(staging, output);
            return new SonyPackageExtractResult { Destination = output, FileCount = fileCount, ExtractedBytes = completed };
        }
        catch
        {
            try { if (Directory.Exists(staging)) Directory.Delete(staging, true); } catch (IOException) { }
            throw;
        }
    }

    private const int ChunkSize = 4 * 1024 * 1024;
    private const int ChunkCount = 8;
    private static readonly long ProgressInterval = Stopwatch.Frequency / 10;

    /// <summary>One piece of a file in flight between the reader and the writer. An empty file is sent
    /// as a single chunk with no buffer so the writer still creates it.</summary>
    private readonly record struct Chunk(int FileIndex, byte[]? Buffer, int Count);

    /// <summary>
    /// Copies <paramref name="wanted"/> into <paramref name="root"/> with reading (decrypt +
    /// decompress) and writing overlapped on two threads. A fixed set of buffers is recycled between
    /// them, which bounds memory and makes the reader wait when the disk falls behind.
    /// </summary>
    private static async Task<long> CopyFilesAsync(GameFileRecord[] wanted, string root, Func<string, Stream> openRead,
        long total, IProgress<SonyPackageExtractProgress>? progress, CancellationToken cancellationToken)
    {
        string[] relatives = wanted.Select(file => GameFileSystem.NormalizePath(file.RelativePath)).ToArray();
        string[] targets = relatives.Select(relative => ResolveContainedPath(root, relative)).ToArray();

        var free = Channel.CreateUnbounded<byte[]>();
        for (int index = 0; index < ChunkCount; index++) free.Writer.TryWrite(new byte[ChunkSize]);
        var filled = Channel.CreateBounded<Chunk>(new BoundedChannelOptions(ChunkCount)
        {
            SingleReader = true,
            SingleWriter = true,
        });

        using var failure = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        CancellationToken token = failure.Token;

        Task reader = Task.Run(async () =>
        {
            try
            {
                for (int fileIndex = 0; fileIndex < wanted.Length; fileIndex++)
                {
                    token.ThrowIfCancellationRequested();
                    long size = wanted[fileIndex].Size;
                    if (size == 0)
                    {
                        await filled.Writer.WriteAsync(new Chunk(fileIndex, null, 0), token).ConfigureAwait(false);
                        continue;
                    }

                    using Stream input = openRead(relatives[fileIndex]);
                    long position = 0;
                    while (position < size)
                    {
                        byte[] buffer = await free.Reader.ReadAsync(token).ConfigureAwait(false);
                        int take = (int)Math.Min(buffer.Length, size - position);
                        int count = 0;
                        while (count < take)
                        {
                            int read = input.Read(buffer, count, take - count);
                            if (read <= 0)
                                throw new EndOfStreamException($"Package file '{relatives[fileIndex]}' ended unexpectedly.");
                            count += read;
                        }
                        position += count;
                        await filled.Writer.WriteAsync(new Chunk(fileIndex, buffer, count), token).ConfigureAwait(false);
                    }
                }
                filled.Writer.Complete();
            }
            catch (Exception ex)
            {
                filled.Writer.TryComplete(ex);
                failure.Cancel();
                throw;
            }
        }, token);

        Task<long> writer = Task.Run(async () =>
        {
            var createdDirectories = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            FileStream? output = null;
            int currentFile = -1;
            long completed = 0;
            long lastReport = 0;
            try
            {
                await foreach (Chunk chunk in filled.Reader.ReadAllAsync(token).ConfigureAwait(false))
                {
                    if (chunk.FileIndex != currentFile)
                    {
                        output?.Dispose();
                        output = null;
                        currentFile = chunk.FileIndex;
                        string target = targets[currentFile];
                        string directory = Path.GetDirectoryName(target)!;
                        if (createdDirectories.Add(directory)) Directory.CreateDirectory(directory);
                        output = new FileStream(target, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                            bufferSize: 0, FileOptions.None);
                        // Reserving the final size up front lets NTFS allocate one contiguous run
                        // instead of growing the file a chunk at a time.
                        if (wanted[currentFile].Size > 0) output.SetLength(wanted[currentFile].Size);
                    }

                    if (chunk.Buffer is not null)
                    {
                        output!.Write(chunk.Buffer, 0, chunk.Count);
                        completed += chunk.Count;
                        free.Writer.TryWrite(chunk.Buffer);
                    }

                    long now = Stopwatch.GetTimestamp();
                    if (progress is not null && now - lastReport >= ProgressInterval)
                    {
                        lastReport = now;
                        progress.Report(new SonyPackageExtractProgress(completed, total, relatives[currentFile]));
                    }
                }
                output?.Dispose();
                output = null;
                if (progress is not null && currentFile >= 0)
                    progress.Report(new SonyPackageExtractProgress(completed, total, relatives[currentFile]));
                return completed;
            }
            catch
            {
                failure.Cancel();
                throw;
            }
            finally
            {
                output?.Dispose();
            }
        }, token);

        try
        {
            await Task.WhenAll(reader, writer).ConfigureAwait(false);
        }
        catch
        {
            // Surface the root cause rather than the cancellation it triggered on the other side.
            Exception? cause = new[] { reader.Exception, writer.Exception }
                .SelectMany(aggregate => aggregate?.InnerExceptions ?? [])
                .FirstOrDefault(ex => ex is not OperationCanceledException);
            if (cause is not null) ExceptionDispatchInfo.Throw(cause);
            cancellationToken.ThrowIfCancellationRequested();
            throw;
        }
        return writer.Result;
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
