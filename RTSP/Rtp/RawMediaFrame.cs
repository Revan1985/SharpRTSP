﻿using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;

namespace Rtsp.Rtp
{
    public class RawMediaFrame : IDisposable
    {
        private bool disposedValue;
        private readonly IEnumerable<ReadOnlyMemory<byte>> _data;
        private readonly IEnumerable<IMemoryOwner<byte>> _owners;

        public IEnumerable<ReadOnlyMemory<byte>> Data
        {
            get
            {
                if (disposedValue) throw new ObjectDisposedException(nameof(RawMediaFrame));
                return _data;
            }
        }

        public required DateTime ClockTimestamp { get; init; }
        public required uint RtpTimestamp { get; init; }

        public RawMediaFrame(IEnumerable<ReadOnlyMemory<byte>> data, IEnumerable<IMemoryOwner<byte>> owners)
        {
            _data = data;
            _owners = owners;
        }

        public bool Any() => Data.Any();

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    foreach (var owner in _owners)
                    {
                        owner.Dispose();
                    }
                }
                disposedValue = true;
            }
        }

        public void Dispose()
        {
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }

        public static RawMediaFrame Empty => new([], []) { RtpTimestamp = 0, ClockTimestamp = DateTime.MinValue };
    }
}