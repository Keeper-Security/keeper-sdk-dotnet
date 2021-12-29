﻿using System;

namespace KeeperSecurity.Utils
{
    /// <exclude/>
    public static class DateTimeOffsetExtensions
    {
#if NET452
        internal static long Epoch = new DateTimeOffset(1970, 1, 1, 0, 0, 0, TimeSpan.Zero).UtcTicks;
             
        public static long ToUnixTimeMilliseconds(this DateTimeOffset date)
        {
            return (date.UtcTicks - Epoch) / TimeSpan.TicksPerMillisecond;
        }

        public static DateTimeOffset FromUnixTimeMilliseconds(long milliseconds)
        {
            return new DateTimeOffset(milliseconds * TimeSpan.TicksPerMillisecond + Epoch, TimeSpan.Zero);
        }
#else
        public static DateTimeOffset FromUnixTimeMilliseconds(long milliseconds)
        {
            return DateTimeOffset.FromUnixTimeMilliseconds(milliseconds);
        }
#endif
    }
}