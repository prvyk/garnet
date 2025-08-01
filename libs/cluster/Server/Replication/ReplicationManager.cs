﻿// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Garnet.common;
using Garnet.server;
using Microsoft.Extensions.Logging;
using Tsavorite.core;

namespace Garnet.cluster
{
    internal sealed partial class ReplicationManager : IDisposable
    {
        readonly ClusterProvider clusterProvider;
        readonly StoreWrapper storeWrapper;
        readonly AofProcessor aofProcessor;
        readonly CheckpointStore checkpointStore;
        readonly ReplicationSyncManager replicationSyncManager;

        readonly CancellationTokenSource ctsRepManager = new();
        readonly TimeSpan replicaAttachTimeout;

        readonly int pageSizeBits;

        readonly ILogger logger;
        bool _disposed;

        private long primary_sync_last_time;

        internal long LastPrimarySyncSeconds => IsRecovering ? (DateTime.UtcNow.Ticks - primary_sync_last_time) / TimeSpan.TicksPerSecond : 0;

        internal void UpdateLastPrimarySyncTime() => this.primary_sync_last_time = DateTime.UtcNow.Ticks;

        private SingleWriterMultiReaderLock recoverLock;
        private SingleWriterMultiReaderLock recoveryStateChangeLock;

        public bool IsRecovering => currentRecoveryStatus != RecoveryStatus.NoRecovery;

        public bool CannotStreamAOF => IsRecovering && currentRecoveryStatus != RecoveryStatus.CheckpointRecoveredAtReplica;

        private long replicationOffset;

        public long ReplicationOffset
        {
            get
            {
                // Primary tracks replicationOffset indirectly through AOF tailAddress
                // Replica will adjust replication offset as it receives data from primary (TODO: since AOFs are synced this might obsolete)
                var role = clusterProvider.clusterManager.CurrentConfig.LocalNodeRole;
                return role == NodeRole.PRIMARY ?
                    (clusterProvider.serverOptions.EnableAOF && storeWrapper.appendOnlyFile.TailAddress > kFirstValidAofAddress ? storeWrapper.appendOnlyFile.TailAddress : kFirstValidAofAddress) :
                    replicationOffset;
            }

            set { replicationOffset = value; }
        }

        /// <summary>
        /// Replication offset corresponding to the checkpoint start marker. We will truncate only to this point after taking a checkpoint (the checkpoint
        /// is taken only when we encounter a checkpoint end marker).
        /// </summary>
        public long ReplicationCheckpointStartOffset;

        /// <summary>
        /// Replication offset until which AOF address is valid for old primary if failover has occurred
        /// </summary>
        public long ReplicationOffset2
        {
            get { return currentReplicationConfig.replicationOffset2; }
        }

        public string PrimaryReplId => currentReplicationConfig.primary_replid;
        public string PrimaryReplId2 => currentReplicationConfig.primary_replid2;

        /// <summary>
        /// Recovery status
        /// </summary>
        public RecoveryStatus currentRecoveryStatus;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public GarnetClusterCheckpointManager GetCkptManager(StoreType storeType)
        {
            return storeType switch
            {
                StoreType.Main => (GarnetClusterCheckpointManager)storeWrapper.store.CheckpointManager,
                StoreType.Object => (GarnetClusterCheckpointManager)storeWrapper.objectStore?.CheckpointManager,
                _ => throw new Exception($"GetCkptManager: unexpected state {storeType}")
            };
        }

        public long GetRecoveredSafeAofAddress()
        {
            var storeAofAddress = clusterProvider.replicationManager.GetCkptManager(StoreType.Main).RecoveredSafeAofAddress;
            var objectStoreAofAddress = clusterProvider.serverOptions.DisableObjects ? long.MaxValue : clusterProvider.replicationManager.GetCkptManager(StoreType.Object).RecoveredSafeAofAddress;
            return Math.Min(storeAofAddress, objectStoreAofAddress);
        }

        public long GetCurrentSafeAofAddress()
        {
            var storeAofAddress = clusterProvider.replicationManager.GetCkptManager(StoreType.Main).CurrentSafeAofAddress;
            var objectStoreAofAddress = clusterProvider.serverOptions.DisableObjects ? long.MaxValue : clusterProvider.replicationManager.GetCkptManager(StoreType.Object).CurrentSafeAofAddress;
            return Math.Min(storeAofAddress, objectStoreAofAddress);
        }

        public ReplicationManager(ClusterProvider clusterProvider, ILogger logger = null)
        {
            var opts = clusterProvider.serverOptions;
            this.logger = logger;
            this.clusterProvider = clusterProvider;
            this.storeWrapper = clusterProvider.storeWrapper;
            this.pageSizeBits = storeWrapper.appendOnlyFile == null ? 0 : storeWrapper.appendOnlyFile.UnsafeGetLogPageSizeBits();

            networkBufferSettings.Log(logger, nameof(ReplicationManager));
            this.networkPool = networkBufferSettings.CreateBufferPool(logger: logger);
            ValidateNetworkBufferSettings();

            aofProcessor = new AofProcessor(storeWrapper, recordToAof: false, clusterProvider: clusterProvider, logger: logger);
            replicaSyncSessionTaskStore = new ReplicaSyncSessionTaskStore(storeWrapper, clusterProvider, logger);
            replicationSyncManager = new ReplicationSyncManager(clusterProvider, logger);

            ReplicationOffset = 0;

            // Set the appendOnlyFile field for all stores
            clusterProvider.GetReplicationLogCheckpointManager(StoreType.Main).checkpointVersionShiftStart = CheckpointVersionShiftStart;
            clusterProvider.GetReplicationLogCheckpointManager(StoreType.Main).checkpointVersionShiftEnd = CheckpointVersionShiftEnd;
            if (storeWrapper.objectStore != null)
            {
                clusterProvider.GetReplicationLogCheckpointManager(StoreType.Object).checkpointVersionShiftStart = CheckpointVersionShiftStart;
                clusterProvider.GetReplicationLogCheckpointManager(StoreType.Object).checkpointVersionShiftEnd = CheckpointVersionShiftEnd;
            }

            // If this node starts as replica, it cannot serve requests until it is connected to primary
            if (clusterProvider.clusterManager.CurrentConfig.LocalNodeRole == NodeRole.REPLICA && clusterProvider.serverOptions.Recover && !BeginRecovery(RecoveryStatus.InitializeRecover))
                throw new Exception(Encoding.ASCII.GetString(CmdStrings.RESP_ERR_GENERIC_CANNOT_ACQUIRE_RECOVERY_LOCK));

            checkpointStore = new CheckpointStore(storeWrapper, clusterProvider, true, logger);
            aofTaskStore = new(clusterProvider, 1, logger);

            var clusterFolder = "/cluster";
            var clusterDataPath = opts.CheckpointDir + clusterFolder;
            var deviceFactory = opts.GetInitializedDeviceFactory(clusterDataPath);
            replicationConfigDevice = deviceFactory.Get(new FileDescriptor(directoryName: "", fileName: "replication.conf"));
            replicationConfigDevicePool = new(1, (int)replicationConfigDevice.SectorSize);

            var canRecoverReplicationHistory = replicationConfigDevice.GetFileSize(0) > 0;
            if (clusterProvider.serverOptions.Recover && canRecoverReplicationHistory)
            {
                logger?.LogTrace("Recovering in-memory checkpoint registry");
                // If recover option is enabled and replication history information is available
                // recover replication history and initialize in-memory checkpoint registry.
                RecoverReplicationHistory();
            }
            else
            {
                logger?.LogTrace("Initializing new in-memory checkpoint registry");
                // If recover option is not enabled or replication history is not available
                // initialize new empty replication history.
                InitializeReplicationHistory();
            }

            // After initializing replication history propagate replicationId to ReplicationLogCheckpointManager
            SetPrimaryReplicationId();
            replicaReplayTaskCts = CancellationTokenSource.CreateLinkedTokenSource(ctsRepManager.Token);
            replicaAttachTimeout = TimeSpan.FromSeconds(clusterProvider.serverOptions.ReplicaAttachTimeout);
        }

        /// <summary>
        /// Used to free up buffer pool
        /// </summary>
        public void Purge() => networkPool.Purge();

        public string GetBufferPoolStats() => networkPool.GetStats();

        void CheckpointVersionShiftStart(bool isMainStore, long oldVersion, long newVersion, bool isStreaming)
        {
            if (clusterProvider.clusterManager.CurrentConfig.LocalNodeRole == NodeRole.REPLICA)
                return;

            if (isStreaming)
            {
                if (isMainStore)
                    storeWrapper.EnqueueCommit(AofEntryType.MainStoreStreamingCheckpointStartCommit, newVersion);
                else
                    storeWrapper.EnqueueCommit(AofEntryType.ObjectStoreStreamingCheckpointStartCommit, newVersion);
            }
            else
            {
                // We enqueue a single checkpoint start marker, since we have unified checkpointing
                if (isMainStore)
                    storeWrapper.EnqueueCommit(AofEntryType.CheckpointStartCommit, newVersion);
            }
        }

        void CheckpointVersionShiftEnd(bool isMainStore, long oldVersion, long newVersion, bool isStreaming)
        {
            if (clusterProvider.clusterManager.CurrentConfig.LocalNodeRole == NodeRole.REPLICA)
                return;

            if (isStreaming)
            {
                if (isMainStore)
                    storeWrapper.EnqueueCommit(AofEntryType.MainStoreStreamingCheckpointEndCommit, newVersion);
                else
                    storeWrapper.EnqueueCommit(AofEntryType.ObjectStoreStreamingCheckpointEndCommit, newVersion);
            }
            else
            {
                // We enqueue a single checkpoint end marker, since we have unified checkpointing
                if (isMainStore)
                    storeWrapper.EnqueueCommit(AofEntryType.CheckpointEndCommit, newVersion);
            }
        }

        /// <summary>
        /// Acquire recovery and checkpoint locks to prevent checkpoints and parallel recovery tasks
        /// </summary>
        /// <param name="nextRecoveryStatus"></param>
        public bool BeginRecovery(RecoveryStatus nextRecoveryStatus)
        {
            if (currentRecoveryStatus != RecoveryStatus.NoRecovery)
            {
                logger?.LogError("Error background recovering task has not completed [{recoverStatus}]", nextRecoveryStatus);
                return false;
            }

            if (!clusterProvider.storeWrapper.TryPauseCheckpoints())
            {
                logger?.LogError("Error could not acquire checkpoint lock [{recoverStatus}]", nextRecoveryStatus);
                return false;
            }

            if (!recoverLock.TryWriteLock())
            {
                logger?.LogError("Error could not acquire recover lock [{recoverStatus}]", nextRecoveryStatus);
                // If failed to acquire recoverLock re-enable checkpoint taking
                clusterProvider.storeWrapper.ResumeCheckpoints();
                return false;
            }

            currentRecoveryStatus = nextRecoveryStatus;
            logger?.LogTrace("Success recover lock [{recoverStatus}]", nextRecoveryStatus);
            return true;
        }

        /// <summary>
        /// Release recovery and checkpoint locks
        /// </summary>
        /// <param name="nextRecoveryStatus"></param>
        public void EndRecovery(RecoveryStatus nextRecoveryStatus)
        {
            logger?.LogTrace("{method} [{currentRecoveryStatus},{nextRecoveryStatus}]", nameof(EndRecovery), currentRecoveryStatus, nextRecoveryStatus);

            try
            {
                recoveryStateChangeLock.WriteLock();
                switch (currentRecoveryStatus)
                {
                    case RecoveryStatus.NoRecovery:
                        throw new GarnetException($"Invalid state change [{currentRecoveryStatus},{nextRecoveryStatus}]");
                    case RecoveryStatus.InitializeRecover:
                    case RecoveryStatus.ClusterReplicate:
                    case RecoveryStatus.ClusterFailover:
                    case RecoveryStatus.ReplicaOfNoOne:
                        switch (nextRecoveryStatus)
                        {
                            case RecoveryStatus.CheckpointRecoveredAtReplica:
                                Debug.Assert(currentRecoveryStatus is not RecoveryStatus.NoRecovery and not RecoveryStatus.CheckpointRecoveredAtReplica);
                                currentRecoveryStatus = nextRecoveryStatus;
                                break;
                            case RecoveryStatus.NoRecovery:
                                currentRecoveryStatus = nextRecoveryStatus;
                                recoverLock.WriteUnlock();
                                clusterProvider.storeWrapper.ResumeCheckpoints();
                                break;
                            default:
                                throw new GarnetException($"Invalid state change [{currentRecoveryStatus},{nextRecoveryStatus}]");
                        }
                        break;
                    case RecoveryStatus.CheckpointRecoveredAtReplica:
                        switch (nextRecoveryStatus)
                        {
                            case RecoveryStatus.NoRecovery:
                                currentRecoveryStatus = nextRecoveryStatus;
                                recoverLock.WriteUnlock();
                                clusterProvider.storeWrapper.ResumeCheckpoints();
                                break;
                            default:
                                throw new GarnetException($"Invalid state change [{currentRecoveryStatus},{nextRecoveryStatus}]");
                        }
                        break;
                }
            }
            finally
            {
                recoveryStateChangeLock.WriteUnlock();
            }
        }

        public void Dispose()
        {
            _disposed = true;

            replicationConfigDevice?.Dispose();
            replicationConfigDevicePool?.Free();

            replicationSyncManager?.Dispose();

            checkpointStore.WaitForReplicas();
            replicaSyncSessionTaskStore.Dispose();
            replicaReplayTaskCts.Cancel();
            activeReplay.WriteLock();
            replicaReplayTaskCts.Dispose();
            ctsRepManager.Cancel();
            ctsRepManager.Dispose();
            aofTaskStore.Dispose();
            aofProcessor?.Dispose();
            networkPool?.Dispose();
        }

        /// <summary>
        /// Main recover method for replication
        /// </summary>
        public void Recover()
        {
            var nodeRole = clusterProvider.clusterManager.CurrentConfig.LocalNodeRole;

            switch (nodeRole)
            {
                case NodeRole.PRIMARY:
                    PrimaryRecover();
                    break;
                case NodeRole.REPLICA:
                    // We will instead recover as part of TryConnectToPrimary instead
                    // ReplicaRecover();
                    break;
                default:
                    logger?.LogError("Not valid role for node {nodeRole}", nodeRole);
                    throw new Exception($"Not valid role for node {nodeRole}");
            }
        }

        /// <summary>
        /// Primary recover
        /// </summary>
        private void PrimaryRecover()
        {
            storeWrapper.RecoverCheckpoint();
            storeWrapper.RecoverAOF();
            if (clusterProvider.serverOptions.EnableAOF)
            {
                // If recovered checkpoint corresponds to an unavailable AOF address, we initialize AOF to that address
                var recoveredSafeAofAddress = GetRecoveredSafeAofAddress();
                if (storeWrapper.appendOnlyFile.TailAddress < recoveredSafeAofAddress)
                    storeWrapper.appendOnlyFile.Initialize(recoveredSafeAofAddress, recoveredSafeAofAddress);
                logger?.LogInformation("Recovered AOF: begin address = {beginAddress}, tail address = {tailAddress}", storeWrapper.appendOnlyFile.BeginAddress, storeWrapper.appendOnlyFile.TailAddress);
                ReplicationOffset = storeWrapper.ReplayAOF();
            }

            // First recover and then load latest checkpoint info in-memory
            if (!InitializeCheckpointStore())
                logger?.LogWarning("Failed acquiring latest memory checkpoint metadata at {method}", nameof(PrimaryRecover));
        }

        /// <summary>
        /// Wait for local replication offset to sync with input value
        /// </summary>
        /// <param name="primaryReplicationOffset"></param>
        /// <returns></returns>
        public async Task<long> WaitForReplicationOffset(long primaryReplicationOffset)
        {
            while (ReplicationOffset < primaryReplicationOffset)
            {
                if (ctsRepManager.IsCancellationRequested) return -1;
                await Task.Yield();
            }
            return ReplicationOffset;
        }

        /// <summary>
        /// Initiate connection with PRIMARY after restart
        /// </summary>
        public void Start()
        {
            if (clusterProvider.clusterManager == null)
                return;

            var current = clusterProvider.clusterManager.CurrentConfig;

            var localNodeRole = current.LocalNodeRole;
            var replicaOfNodeId = current.LocalNodePrimaryId;
            if (localNodeRole == NodeRole.REPLICA && clusterProvider.serverOptions.Recover && replicaOfNodeId != null)
            {
                var success = clusterProvider.serverOptions.ReplicaDisklessSync ?
                    TryReplicateDisklessSync(null, null, background: false, force: true, tryAddReplica: false, out var errorMessage) :
                    TryReplicateDiskbasedSync(null, null, background: false, force: false, tryAddReplica: false, out errorMessage);
                // At initialization of ReplicationManager, this node has been put into recovery mode
                if (!success)
                    logger?.LogError($"An error occurred at {nameof(ReplicationManager)}.{nameof(Start)} {{error}}", Encoding.ASCII.GetString(errorMessage));
            }
            else if (localNodeRole == NodeRole.PRIMARY && replicaOfNodeId == null)
            {
                var replicaIds = current.GetLocalNodeReplicaIds();
                foreach (var replicaId in replicaIds)
                {
                    // TODO: Initiate AOF sync task correctly when restarting primary
                    if (clusterProvider.replicationManager.TryAddReplicationTask(replicaId, 0, out var aofSyncTaskInfo))
                    {
                        if (!TryConnectToReplica(replicaId, 0, aofSyncTaskInfo, out var errorMessage))
                            logger?.LogError("{errorMessage}", Encoding.ASCII.GetString(errorMessage));
                    }
                }
            }
            else
            {
                logger?.LogWarning("Replication manager starting configuration inconsistent role:{role} replicaOfId:{replicaOfNodeId}", replicaOfNodeId, localNodeRole);
            }
        }
    }
}