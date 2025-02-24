﻿namespace RtspMultiplexer;

using Rtsp;

/// <summary>
/// Class to store source information of the request.
/// </summary>
internal class OriginContext
{
    public int OriginCSeq { get; internal set; }
    public RtspListener OriginSourcePort { get; internal set; }
}
