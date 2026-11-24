using System;
using System.Threading;
using System.Threading.Tasks;

namespace ProxyCollector.Services;

/// <summary>
/// Weighted memory reservations for source downloads. The reservation includes
/// response buffering, UTF-16 decoding and extracted-line materialization.
/// </summary>
public sealed class SourceFetchBudget
{
    private const long UnitBytes = 1024L * 1024L;
    private const long WorkingSetMultiplier = 4;

    private readonly WeightedCapacity _sourceCapacity;
    private readonly WeightedCapacity _providerCapacity;

    public SourceFetchBudget(long sourceBudgetBytes, long providerBudgetBytes)
    {
        _sourceCapacity = new WeightedCapacity(sourceBudgetBytes);
        _providerCapacity = new WeightedCapacity(providerBudgetBytes);
    }

    /// <summary>
    /// Use the declared length only when it describes the bytes that will be buffered.
    /// Content-Length on a compressed response measures the compressed wire body, not
    /// its decompressed working set, so those responses reserve the full configured cap.
    /// </summary>
    public static int GetReservationBytes(long? contentLength, bool isCompressed, int maximumResponseBytes)
    {
        if (maximumResponseBytes <= 0) throw new ArgumentOutOfRangeException(nameof(maximumResponseBytes));
        if (isCompressed || !contentLength.HasValue) return maximumResponseBytes;
        return checked((int)Math.Clamp(contentLength.Value, 1L, maximumResponseBytes));
    }

    public ValueTask<IDisposable> AcquireSourceAsync(int maxResponseBytes, CancellationToken cancellationToken)
        => _sourceCapacity.AcquireAsync(GetReservationUnits(maxResponseBytes), cancellationToken);

    public ValueTask<IDisposable> AcquireProviderAsync(int maxResponseBytes, CancellationToken cancellationToken)
        => _providerCapacity.AcquireAsync(GetReservationUnits(maxResponseBytes), cancellationToken);

    private static int GetReservationUnits(int responseBytes)
    {
        if (responseBytes <= 0) throw new ArgumentOutOfRangeException(nameof(responseBytes));
        long workingBytes = checked((long)responseBytes * WorkingSetMultiplier);
        return checked((int)Math.Max(1, (workingBytes + UnitBytes - 1) / UnitBytes));
    }

    private sealed class WeightedCapacity
    {
        private readonly SemaphoreSlim _gate = new(1, 1);
        private readonly long _capacityUnits;
        private long _availableUnits;
        private TaskCompletionSource _changed = NewSignal();

        public WeightedCapacity(long budgetBytes)
        {
            if (budgetBytes < UnitBytes)
                throw new ArgumentOutOfRangeException(nameof(budgetBytes), "A fetch budget must be at least 1 MiB.");
            _capacityUnits = budgetBytes / UnitBytes;
            _availableUnits = _capacityUnits;
        }

        public async ValueTask<IDisposable> AcquireAsync(int units, CancellationToken cancellationToken)
        {
            if (units > _capacityUnits)
                throw new ArgumentOutOfRangeException(nameof(units),
                    $"The request needs {units} MiB, above this pool's {_capacityUnits} MiB limit.");

            while (true)
            {
                await _gate.WaitAsync(cancellationToken);
                Task changed;
                try
                {
                    if (_availableUnits >= units)
                    {
                        _availableUnits -= units;
                        return new CapacityLease(this, units);
                    }
                    changed = _changed.Task;
                }
                finally
                {
                    _gate.Release();
                }

                await changed.WaitAsync(cancellationToken);
            }
        }

        private void Release(int units)
        {
            _gate.Wait();
            try
            {
                _availableUnits += units;
                if (_availableUnits > _capacityUnits)
                    throw new InvalidOperationException("Fetch-memory budget released more capacity than it reserved.");

                TaskCompletionSource previous = _changed;
                _changed = NewSignal();
                previous.TrySetResult();
            }
            finally
            {
                _gate.Release();
            }
        }

        private static TaskCompletionSource NewSignal()
            => new(TaskCreationOptions.RunContinuationsAsynchronously);

        private sealed class CapacityLease : IDisposable
        {
            private WeightedCapacity? _owner;
            private readonly int _units;

            public CapacityLease(WeightedCapacity owner, int units)
            {
                _owner = owner;
                _units = units;
            }

            public void Dispose()
                => Interlocked.Exchange(ref _owner, null)?.Release(_units);
        }
    }
}
