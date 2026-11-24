using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace ProxyCollector.Services;

/// <summary>
/// Spools each source's extracted lines to a per-run temporary file. The collector
/// replays feeds in configured source order, preserving first-contributor attribution
/// without retaining all fetched source bodies and lines in memory.
/// </summary>
public sealed class SourceSpoolStore : IDisposable
{
    private readonly string _directory;
    private bool _disposed;

    public SourceSpoolStore()
    {
        _directory = Path.Combine(Path.GetTempPath(), "fastnodes-source-spool-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_directory);
    }

    public async Task WriteSourceAsync(int sourceIndex, IReadOnlyList<string> lines, CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        if (sourceIndex < 0) throw new ArgumentOutOfRangeException(nameof(sourceIndex));
        ArgumentNullException.ThrowIfNull(lines);

        string path = GetPath(sourceIndex);
        string temporary = path + ".tmp";
        await File.WriteAllLinesAsync(temporary, lines, new UTF8Encoding(false), cancellationToken);
        File.Move(temporary, path, overwrite: true);
    }

    public async Task AppendSourceAsync(int sourceIndex, IReadOnlyList<string> lines, CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        if (sourceIndex < 0) throw new ArgumentOutOfRangeException(nameof(sourceIndex));
        ArgumentNullException.ThrowIfNull(lines);
        if (lines.Count == 0) return;

        string path = GetPath(sourceIndex);
        if (!File.Exists(path))
            throw new InvalidOperationException("Create the root source spool before appending provider lines.");

        await File.AppendAllLinesAsync(path, lines, new UTF8Encoding(false), cancellationToken);
    }

    public bool HasSource(int sourceIndex)
    {
        ThrowIfDisposed();
        return File.Exists(GetPath(sourceIndex));
    }

    public IEnumerable<string> ReadSourceLines(int sourceIndex)
    {
        ThrowIfDisposed();
        string path = GetPath(sourceIndex);
        return File.Exists(path) ? File.ReadLines(path, Encoding.UTF8) : Enumerable.Empty<string>();
    }

    private string GetPath(int sourceIndex)
        => Path.Combine(_directory, sourceIndex.ToString("D6", System.Globalization.CultureInfo.InvariantCulture) + ".txt");

    private void ThrowIfDisposed()
    {
        if (_disposed) throw new ObjectDisposedException(nameof(SourceSpoolStore));
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        try
        {
            if (Directory.Exists(_directory))
                Directory.Delete(_directory, recursive: true);
        }
        catch
        {
            // Temporary-file cleanup must not mask collection results or original failures.
        }
    }
}
