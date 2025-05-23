﻿// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

using System;
using System.IO;
using System.Net;
using Microsoft.Extensions.Logging;
using Tsavorite.core;

namespace Garnet.server
{
    /// <summary>
    /// Options when creating Garnet server
    /// </summary>
    public class ServerOptions
    {
        public const byte DEFAULT_RESP_VERSION = 2;

        /// <summary>
        /// Endpoints to bind server to.
        /// </summary>
        public EndPoint[] EndPoints { get; set; } = [new IPEndPoint(IPAddress.Loopback, 6379)];

        /// <summary>
        /// Cluster announce Endpoint
        /// </summary>
        public EndPoint ClusterAnnounceEndpoint { get; set; }

        /// <summary>
        /// Total log memory used in bytes (rounds down to power of 2).
        /// </summary>
        public string MemorySize = "16g";

        /// <summary>
        /// Size of each page in bytes (rounds down to power of 2).
        /// </summary>
        public string PageSize = "32m";

        /// <summary>
        /// Size of each log segment in bytes on disk (rounds down to power of 2).
        /// </summary>
        public string SegmentSize = "1g";

        /// <summary>
        /// Size of hash index in bytes (rounds down to power of 2).
        /// </summary>
        public string IndexSize = "128m";

        /// <summary>
        /// Max size of hash index in bytes (rounds down to power of 2). If unspecified, index size doesn't grow (default behavior).
        /// </summary>
        public string IndexMaxSize = string.Empty;

        /// <summary>
        /// Percentage of log memory that is kept mutable.
        /// </summary>
        public int MutablePercent = 90;

        /// <summary>
        /// Enable tiering of records (hybrid log) to storage, to support a larger-than-memory store. Use LogDir to specify storage directory.
        /// </summary>
        public bool EnableStorageTier = false;

        /// <summary>
        /// When records are read from the main store's in-memory immutable region or storage device, copy them to the tail of the log.
        /// </summary>
        public bool CopyReadsToTail = false;

        /// <summary>
        /// When records are read from the object store's in-memory immutable region or storage device, copy them to the tail of the log.
        /// </summary>
        public bool ObjectStoreCopyReadsToTail = false;

        /// <summary>
        /// Storage directory for tiered records (hybrid log), if storage tiering (UseStorage) is enabled. Uses current directory if unspecified.
        /// </summary>
        public string LogDir = null;

        /// <summary>
        /// Storage directory for checkpoints. Uses LogDir if unspecified.
        /// </summary>
        public string CheckpointDir = null;

        /// <summary>
        /// Recover from latest checkpoint.
        /// </summary>
        public bool Recover = false;

        /// <summary>
        /// Disable pub/sub feature on server.
        /// </summary>
        public bool DisablePubSub = false;

        /// <summary>
        /// Page size of log used for pub/sub (rounds down to power of 2).
        /// </summary>
        public string PubSubPageSize = "4k";

        /// <summary>
        /// Server bootup should fail if errors happen during bootup of AOF and checkpointing.
        /// </summary>
        public bool FailOnRecoveryError = false;

        /// <summary>
        /// Skip RDB restore checksum validation
        /// </summary>
        public bool SkipRDBRestoreChecksumValidation = false;

        /// <summary>
        /// Logger
        /// </summary>
        public ILogger logger;

        /// <summary>
        /// Constructor
        /// </summary>
        public ServerOptions(ILogger logger = null)
        {
            this.logger = logger;
        }

        /// <summary>
        /// Get memory size
        /// </summary>
        /// <returns></returns>
        public int MemorySizeBits()
        {
            long size = ParseSize(MemorySize);
            long adjustedSize = PreviousPowerOf2(size);
            if (size != adjustedSize)
                logger?.LogInformation("Warning: using lower log memory size than specified (power of 2)");
            return (int)Math.Log(adjustedSize, 2);
        }

        /// <summary>
        /// Get page size
        /// </summary>
        /// <returns></returns>
        public int PageSizeBits()
        {
            long size = ParseSize(PageSize);
            long adjustedSize = PreviousPowerOf2(size);
            if (size != adjustedSize)
                logger?.LogInformation("Warning: using lower page size than specified (power of 2)");
            return (int)Math.Log(adjustedSize, 2);
        }

        /// <summary>
        /// Get pub/sub page size
        /// </summary>
        /// <returns></returns>
        public long PubSubPageSizeBytes()
        {
            long size = ParseSize(PubSubPageSize);
            long adjustedSize = PreviousPowerOf2(size);
            if (size != adjustedSize)
                logger?.LogInformation("Warning: using lower pub/sub page size than specified (power of 2)");
            return adjustedSize;
        }

        /// <summary>
        /// Get segment size
        /// </summary>
        /// <returns></returns>
        public int SegmentSizeBits()
        {
            long size = ParseSize(SegmentSize);
            long adjustedSize = PreviousPowerOf2(size);
            if (size != adjustedSize)
                logger?.LogInformation("Warning: using lower disk segment size than specified (power of 2)");
            return (int)Math.Log(adjustedSize, 2);
        }

        /// <summary>
        /// Get index size
        /// </summary>
        /// <returns></returns>
        public int IndexSizeCachelines(string name, string indexSize)
        {
            long size = ParseSize(indexSize);
            long adjustedSize = PreviousPowerOf2(size);
            if (adjustedSize < 64 || adjustedSize > (1L << 37)) throw new Exception($"Invalid {name}");
            if (size != adjustedSize)
                logger?.LogInformation("Warning: using lower {name} than specified (power of 2)", name);
            return (int)(adjustedSize / 64);
        }

        /// <summary>
        /// Get KVSettings
        /// </summary>
        public void GetSettings<TKey, TValue>()
        {
            var indexCacheLines = IndexSizeCachelines("hash index size", IndexSize);
            var kvSettings = new KVSettings<TKey, TValue>()
            {
                IndexSize = indexCacheLines * 64L,
                PreallocateLog = false,
                PageSize = 1L << PageSizeBits()
            };
            logger?.LogInformation("[Store] Using page size of {PageSize}", PrettySize(kvSettings.PageSize));

            kvSettings.MemorySize = 1L << MemorySizeBits();
            logger?.LogInformation("[Store] Using log memory size of {MemorySize}", PrettySize(kvSettings.MemorySize));

            logger?.LogInformation("[Store] There are {LogPages} log pages in memory", PrettySize(kvSettings.MemorySize / kvSettings.PageSize));

            kvSettings.SegmentSize = 1L << SegmentSizeBits();
            logger?.LogInformation("[Store] Using disk segment size of {SegmentSize}", PrettySize(kvSettings.SegmentSize));

            logger?.LogInformation("[Store] Using hash index size of {IndexSize} ({CacheLines} cache lines)", PrettySize(kvSettings.IndexSize), PrettySize(indexCacheLines));

            if (EnableStorageTier)
            {
                if (LogDir is null or "")
                    LogDir = Directory.GetCurrentDirectory();
                kvSettings.LogDevice = Devices.CreateLogDevice(LogDir + "/Store/hlog", logger: logger);
            }
            else
            {
                if (LogDir != null)
                    throw new Exception("LogDir specified without enabling tiered storage (UseStorage)");
                kvSettings.LogDevice = new NullDevice();
            }

            if (CheckpointDir == null) CheckpointDir = LogDir;

            if (CheckpointDir is null or "")
                CheckpointDir = Directory.GetCurrentDirectory();

            kvSettings.CheckpointDir = CheckpointDir + "/Store/checkpoints";
            kvSettings.RemoveOutdatedCheckpoints = true;
        }

        /// <summary>
        /// Parse size from string specification
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        public static long ParseSize(string value)
        {
            char[] suffix = ['k', 'm', 'g', 't', 'p'];
            long result = 0;
            foreach (char c in value)
            {
                if (char.IsDigit(c))
                {
                    result = result * 10 + (byte)c - '0';
                }
                else
                {
                    for (int i = 0; i < suffix.Length; i++)
                    {
                        if (char.ToLower(c) == suffix[i])
                        {
                            result *= (long)Math.Pow(1024, i + 1);
                            return result;
                        }
                    }
                }
            }
            return result;
        }

        /// <summary>
        /// Pretty print value
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        protected static string PrettySize(long value)
        {
            char[] suffix = ['k', 'm', 'g', 't', 'p'];
            double v = value;
            int exp = 0;
            while (v - Math.Floor(v) > 0)
            {
                if (exp >= 18)
                    break;
                exp += 3;
                v *= 1024;
                v = Math.Round(v, 12);
            }

            while (Math.Floor(v).ToString().Length > 3)
            {
                if (exp <= -18)
                    break;
                exp -= 3;
                v /= 1024;
                v = Math.Round(v, 12);
            }
            if (exp > 0)
                return v.ToString() + suffix[exp / 3 - 1];
            else if (exp < 0)
                return v.ToString() + suffix[-exp / 3 - 1];
            return v.ToString();
        }

        /// <summary>
        /// Previous power of 2
        /// </summary>
        /// <param name="v"></param>
        /// <returns></returns>
        protected static long PreviousPowerOf2(long v)
        {
            v |= v >> 1;
            v |= v >> 2;
            v |= v >> 4;
            v |= v >> 8;
            v |= v >> 16;
            v |= v >> 32;
            return v - (v >> 1);
        }
    }
}