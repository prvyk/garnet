// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

using System;
using System.Diagnostics;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Garnet.client;
using Garnet.common;
using Garnet.server;
using Microsoft.Extensions.Logging;
using Tsavorite.core;

namespace Garnet.cluster
{
    internal sealed partial class ReplicaSyncSession(
        StoreWrapper storeWrapper,
        ClusterProvider clusterProvider,
        SyncMetadata replicaSyncMetadata = null,
        TimeSpan replicaSyncTimeout = default,
        CancellationToken token = default,
        string replicaNodeId = null,
        string replicaAssignedPrimaryId = null,
        CheckpointEntry replicaCheckpointEntry = null,
        long replicaAofBeginAddress = 0,
        long replicaAofTailAddress = 0,
        ILogger logger = null) : IDisposable
    {
        readonly StoreWrapper storeWrapper = storeWrapper;
        readonly ClusterProvider clusterProvider = clusterProvider;
        public readonly SyncMetadata replicaSyncMetadata = replicaSyncMetadata;
        readonly TimeSpan replicaSyncTimeout = replicaSyncTimeout;
        readonly CancellationToken token = token;
        readonly CancellationTokenSource cts = new();
        SectorAlignedBufferPool bufferPool = null;
        readonly SemaphoreSlim semaphore = new(0);

        public readonly string replicaNodeId = replicaNodeId;
        public readonly string replicaAssignedPrimaryId = replicaAssignedPrimaryId;
        private readonly long replicaAofBeginAddress = replicaAofBeginAddress;
        private readonly long replicaAofTailAddress = replicaAofTailAddress;

        private readonly CheckpointEntry replicaCheckpointEntry = replicaCheckpointEntry;

        private readonly ILogger logger = logger;

        public string errorMsg = default;

        const int validateMetadataMaxRetryCount = 10;

        public void Dispose()
        {
            AofSyncTask?.garnetClient?.Dispose();
            AofSyncTask = null;
            cts.Cancel();
            cts.Dispose();
            semaphore?.Dispose();
            bufferPool?.Free();
        }

        public bool ValidateMetadata(
            CheckpointEntry localEntry,
            out long index_size,
            out LogFileInfo hlog_size,
            out long obj_index_size,
            out LogFileInfo obj_hlog_size,
            out bool skipLocalMainStoreCheckpoint,
            out bool skipLocalObjectStoreCheckpoint)
        {
            hlog_size = default;
            obj_hlog_size = default;
            index_size = -1L;
            obj_index_size = -1L;

            // Local and remote checkpoints are of same history if both of the following hold
            // 1. There is a checkpoint available at remote node
            // 2. Remote and local checkpoints contain the same PrimaryReplId
            var sameMainStoreCheckpointHistory = !string.IsNullOrEmpty(replicaCheckpointEntry.metadata.storePrimaryReplId) && replicaCheckpointEntry.metadata.storePrimaryReplId.Equals(localEntry.metadata.storePrimaryReplId);
            var sameObjectStoreCheckpointHistory = !string.IsNullOrEmpty(replicaCheckpointEntry.metadata.objectStorePrimaryReplId) && replicaCheckpointEntry.metadata.objectStorePrimaryReplId.Equals(localEntry.metadata.objectStorePrimaryReplId);
            // We will not send the latest local checkpoint if any of the following hold
            // 1. Local node does not have any checkpoints
            // 2. Local checkpoint is of same version and history as the remote checkpoint
            skipLocalMainStoreCheckpoint = localEntry.metadata.storeHlogToken == default || (sameMainStoreCheckpointHistory && localEntry.metadata.storeVersion == replicaCheckpointEntry.metadata.storeVersion);
            skipLocalObjectStoreCheckpoint = clusterProvider.serverOptions.DisableObjects || localEntry.metadata.objectStoreHlogToken == default || (sameObjectStoreCheckpointHistory && localEntry.metadata.objectStoreVersion == replicaCheckpointEntry.metadata.objectStoreVersion);

            // Acquire metadata for main store
            // If failed then this checkpoint is not usable because it is corrupted
            if (!skipLocalMainStoreCheckpoint && !clusterProvider.replicationManager.TryAcquireSettledMetadataForMainStore(localEntry, out hlog_size, out index_size))
                return false;

            // Acquire metadata for object store
            // If failed then this checkpoint is not usable because it is corrupted
            if (!skipLocalObjectStoreCheckpoint && !clusterProvider.replicationManager.TryAcquireSettledMetadataForObjectStore(localEntry, out obj_hlog_size, out obj_index_size))
                return false;

            return true;
        }

        /// <summary>
        /// Start sending the latest checkpoint to replica
        /// </summary>
        public async Task<bool> SendCheckpoint()
        {
            errorMsg = default;
            var storeCkptManager = clusterProvider.GetReplicationLogCheckpointManager(StoreType.Main);
            var objectStoreCkptManager = clusterProvider.GetReplicationLogCheckpointManager(StoreType.Object);
            var current = clusterProvider.clusterManager.CurrentConfig;
            var (address, port) = current.GetWorkerAddressFromNodeId(replicaNodeId);

            if (address == null || port == -1)
            {
                errorMsg = $"PRIMARY-ERR don't know about replicaId: {replicaNodeId}";
                logger?.LogError("{errorMsg}", errorMsg);
                return false;
            }

            GarnetClientSession gcs = new(
                new IPEndPoint(IPAddress.Parse(address), port),
                clusterProvider.replicationManager.GetRSSNetworkBufferSettings,
                clusterProvider.replicationManager.GetNetworkPool,
                tlsOptions: clusterProvider.serverOptions.TlsOptions?.TlsClientOptions,
                authUsername: clusterProvider.ClusterUsername,
                authPassword: clusterProvider.ClusterPassword,
                logger: logger);
            CheckpointEntry localEntry = default;
            AofSyncTaskInfo aofSyncTaskInfo = null;

            try
            {
                logger?.LogInformation("Replica replicaId:{replicaId} requesting checkpoint replicaStoreVersion:{replicaStoreVersion} replicaObjectStoreVersion:{replicaObjectStoreVersion}",
                    replicaNodeId, replicaCheckpointEntry.metadata.storeVersion, replicaCheckpointEntry.metadata.objectStoreVersion);

                logger?.LogInformation("Attempting to acquire checkpoint");
                (localEntry, aofSyncTaskInfo) = await AcquireCheckpointEntry();
                logger?.LogInformation("Checkpoint search completed");

                gcs.Connect((int)replicaSyncTimeout.TotalMilliseconds);

                long index_size = -1;
                long obj_index_size = -1;
                var hlog_size = default(LogFileInfo);
                var obj_hlog_size = default(LogFileInfo);
                var skipLocalMainStoreCheckpoint = false;
                var skipLocalObjectStoreCheckpoint = false;
                var retryCount = validateMetadataMaxRetryCount;
                while (!ValidateMetadata(localEntry, out index_size, out hlog_size, out obj_index_size, out obj_hlog_size, out skipLocalMainStoreCheckpoint, out skipLocalObjectStoreCheckpoint))
                {
                    logger?.LogError("Failed to validate metadata. Retrying....");
                    await Task.Yield();
                    if (retryCount-- <= 0)
                        throw new GarnetException("Failed to validate metadata!");
                }

                #region sendStoresSnapshotData
                if (!skipLocalMainStoreCheckpoint)
                {
                    logger?.LogInformation("Sending main store checkpoint {version} {storeHlogToken} {storeIndexToken} to replica", localEntry.metadata.storeVersion, localEntry.metadata.storeHlogToken, localEntry.metadata.storeIndexToken);

                    // 1. send hlog file segments
                    if (clusterProvider.serverOptions.EnableStorageTier && hlog_size.hybridLogFileEndAddress > 64)
                        await SendFileSegments(gcs, localEntry.metadata.storeHlogToken, CheckpointFileType.STORE_HLOG, hlog_size.hybridLogFileStartAddress, hlog_size.hybridLogFileEndAddress);

                    // 2.Send index file segments
                    //var index_size = storeWrapper.store.GetIndexFileSize(localEntry.storeIndexToken);
                    await SendFileSegments(gcs, localEntry.metadata.storeIndexToken, CheckpointFileType.STORE_INDEX, 0, index_size);

                    // 3. Send snapshot file segments
                    await SendFileSegments(gcs, localEntry.metadata.storeHlogToken, CheckpointFileType.STORE_SNAPSHOT, 0, hlog_size.snapshotFileEndAddress);

                    // 4. Send delta log segments
                    var dlog_size = hlog_size.deltaLogTailAddress;
                    await SendFileSegments(gcs, localEntry.metadata.storeHlogToken, CheckpointFileType.STORE_DLOG, 0, dlog_size);

                    // 5.Send index metadata
                    await SendCheckpointMetadata(gcs, storeCkptManager, CheckpointFileType.STORE_INDEX, localEntry.metadata.storeIndexToken);

                    // 6. Send snapshot metadata
                    await SendCheckpointMetadata(gcs, storeCkptManager, CheckpointFileType.STORE_SNAPSHOT, localEntry.metadata.storeHlogToken);
                }

                if (!skipLocalObjectStoreCheckpoint)
                {
                    logger?.LogInformation("Sending object store checkpoint {version} {objectStoreHlogToken} {objectStoreIndexToken} to replica", localEntry.metadata.objectStoreVersion, localEntry.metadata.objectStoreHlogToken, localEntry.metadata.objectStoreIndexToken);

                    // 1. send hlog file segments
                    if (clusterProvider.serverOptions.EnableStorageTier && obj_hlog_size.hybridLogFileEndAddress > 24)
                    {
                        //send object hlog file segments
                        await SendFileSegments(gcs, localEntry.metadata.objectStoreHlogToken, CheckpointFileType.OBJ_STORE_HLOG, obj_hlog_size.hybridLogFileStartAddress, obj_hlog_size.hybridLogFileEndAddress);

                        var hlogSegmentCount = ((obj_hlog_size.hybridLogFileEndAddress - obj_hlog_size.hybridLogFileStartAddress) >> clusterProvider.serverOptions.ObjectStoreSegmentSizeBits()) + 1;
                        await SendObjectFiles(gcs, localEntry.metadata.objectStoreHlogToken, CheckpointFileType.OBJ_STORE_HLOG_OBJ, (int)hlogSegmentCount);
                    }

                    // 2. Send object store snapshot files
                    if (obj_hlog_size.snapshotFileEndAddress > 24)
                    {
                        //send snapshot file segments
                        await SendFileSegments(gcs, localEntry.metadata.objectStoreHlogToken, CheckpointFileType.OBJ_STORE_SNAPSHOT, 0, obj_hlog_size.snapshotFileEndAddress);

                        //send snapshot.obj file segments
                        var snapshotSegmentCount = (obj_hlog_size.snapshotFileEndAddress >> clusterProvider.serverOptions.ObjectStoreSegmentSizeBits()) + 1;
                        await SendObjectFiles(gcs, localEntry.metadata.objectStoreHlogToken, CheckpointFileType.OBJ_STORE_SNAPSHOT_OBJ, (int)snapshotSegmentCount);
                    }

                    // 3. Send object store index file segments
                    if (obj_index_size > 0)
                        await SendFileSegments(gcs, localEntry.metadata.objectStoreIndexToken, CheckpointFileType.OBJ_STORE_INDEX, 0, obj_index_size);

                    // 4. Send object store delta file segments
                    var obj_dlog_size = obj_hlog_size.deltaLogTailAddress;
                    if (obj_dlog_size > 0)
                        await SendFileSegments(gcs, localEntry.metadata.objectStoreHlogToken, CheckpointFileType.OBJ_STORE_DLOG, 0, obj_dlog_size);

                    // 5. Send object store index metadata
                    await SendCheckpointMetadata(gcs, objectStoreCkptManager, CheckpointFileType.OBJ_STORE_INDEX, localEntry.metadata.objectStoreIndexToken);

                    // 6. Send object store snapshot metadata
                    await SendCheckpointMetadata(gcs, objectStoreCkptManager, CheckpointFileType.OBJ_STORE_SNAPSHOT, localEntry.metadata.objectStoreHlogToken);
                }
                #endregion

                #region startAofSync
                var recoverFromRemote = !skipLocalMainStoreCheckpoint || !skipLocalObjectStoreCheckpoint;
                var replayAOF = false;
                var checkpointAofBeginAddress = localEntry.GetMinAofCoveredAddress();
                var beginAddress = checkpointAofBeginAddress;
                if (!recoverFromRemote)
                {
                    // If replica is ahead of this primary it will force itself to forget and start syncing from RecoveredReplicationOffset
                    if (replicaAofBeginAddress > ReplicationManager.kFirstValidAofAddress && replicaAofBeginAddress > checkpointAofBeginAddress)
                    {
                        logger?.LogInformation(
                            "ReplicaSyncSession: replicaAofBeginAddress {replicaAofBeginAddress} > PrimaryCheckpointRecoveredReplicationOffset {RecoveredReplicationOffset}, cannot use remote AOF",
                            replicaAofBeginAddress, checkpointAofBeginAddress);
                    }
                    else
                    {
                        // Tail address cannot be behind the recovered address since above we checked replicaAofBeginAddress and it appears after RecoveredReplicationOffset
                        // unless we are performing MainMemoryReplication
                        // TODO: shouldn't we use the remote cEntry's tail address here since replica will recover to that?
                        if (replicaAofTailAddress < checkpointAofBeginAddress && !clusterProvider.serverOptions.FastAofTruncate)
                        {
                            logger?.LogCritical("ReplicaSyncSession replicaAofTail {replicaAofTailAddress} < canServeFromAofAddress {RecoveredReplicationOffset}", replicaAofTailAddress, checkpointAofBeginAddress);
                            throw new Exception($"ReplicaSyncSession replicaAofTail {replicaAofTailAddress} < canServeFromAofAddress {checkpointAofBeginAddress}");
                        }

                        // If we are behind this primary we need to decide until where to replay
                        var replayUntilAddress = replicaAofTailAddress;
                        // Replica tail is further ahead than committed address of primary
                        if (storeWrapper.appendOnlyFile.CommittedUntilAddress < replayUntilAddress)
                        {
                            replayUntilAddress = storeWrapper.appendOnlyFile.CommittedUntilAddress;
                        }

                        // Replay only if records not included in checkpoint
                        if (replayUntilAddress > checkpointAofBeginAddress)
                        {
                            logger?.LogInformation("ReplicaSyncSession: have to replay remote AOF from {beginAddress} until {untilAddress}", beginAddress, replayUntilAddress);
                            replayAOF = true;
                            // Bound replayUntilAddress to ReplicationOffset2 to avoid replaying divergent history only if connecting replica was attached to old primary
                            if (!string.IsNullOrEmpty(clusterProvider.replicationManager.PrimaryReplId2) &&
                                clusterProvider.replicationManager.PrimaryReplId2.Equals(replicaAssignedPrimaryId) &&
                                replayUntilAddress > clusterProvider.replicationManager.ReplicationOffset2)
                                replayUntilAddress = clusterProvider.replicationManager.ReplicationOffset2;
                            checkpointAofBeginAddress = replayUntilAddress;
                        }
                    }
                }

                // Signal replica to recover from local/remote checkpoint
                // Make replica replayAOF if needed and replay from provided beginAddress to RecoveredReplication Address
                var resp = await gcs.ExecuteBeginReplicaRecover(
                    !skipLocalMainStoreCheckpoint,
                    !skipLocalObjectStoreCheckpoint,
                    replayAOF,
                    clusterProvider.replicationManager.PrimaryReplId,
                    localEntry.ToByteArray(),
                    beginAddress,
                    checkpointAofBeginAddress).WaitAsync(replicaSyncTimeout, cts.Token).ConfigureAwait(false);
                var syncFromAofAddress = long.Parse(resp);

                // Assert that AOF address the replica will be requesting can be served, except in case of:
                // Possible AOF data loss: { using null AOF device } OR { main memory replication AND no on-demand checkpoints }
                var possibleAofDataLoss = clusterProvider.serverOptions.UseAofNullDevice ||
                    (clusterProvider.serverOptions.FastAofTruncate && !clusterProvider.serverOptions.OnDemandCheckpoint);

                if (!possibleAofDataLoss)
                {
                    if (syncFromAofAddress < storeWrapper.appendOnlyFile.BeginAddress)
                    {
                        logger?.LogError("syncFromAofAddress: {syncFromAofAddress} < beginAofAddress: {storeWrapper.appendOnlyFile.BeginAddress}", syncFromAofAddress, storeWrapper.appendOnlyFile.BeginAddress);
                        logger?.LogCheckpointEntry(LogLevel.Error, "Requested replay address truncated", localEntry);
                        throw new Exception("Failed syncing because replica requested truncated AOF address");
                    }
                }
                else // possible AOF data loss
                {
                    if (syncFromAofAddress < storeWrapper.appendOnlyFile.BeginAddress)
                    {
                        logger?.LogWarning("AOF truncated, unsafe attach: syncFromAofAddress: {syncFromAofAddress} < beginAofAddress: {storeWrapper.appendOnlyFile.BeginAddress}", syncFromAofAddress, storeWrapper.appendOnlyFile.BeginAddress);
                        logger?.LogCheckpointEntry(LogLevel.Warning, "Unsafe replay due to truncated AOF address", localEntry);
                    }
                }

                // Check what happens if we fail after recovery and start AOF stream
                ExceptionInjectionHelper.TriggerException(ExceptionInjectionType.Replication_Fail_Before_Background_AOF_Stream_Task_Start);

                // We have already added the iterator for the covered address above but replica might request an address
                // that is ahead of the covered address so we should start streaming from that address in order not to
                // introduce duplicate insertions.
                if (!clusterProvider.replicationManager.TryAddReplicationTask(replicaNodeId, syncFromAofAddress, out aofSyncTaskInfo))
                    throw new GarnetException("Failed trying to try update replication task");
                if (!clusterProvider.replicationManager.TryConnectToReplica(replicaNodeId, syncFromAofAddress, aofSyncTaskInfo, out _))
                    throw new GarnetException("Failed connecting to replica for aofSync");
                #endregion
            }
            catch (Exception ex)
            {
                if (localEntry != null)
                    logger?.LogCheckpointEntry(LogLevel.Error, "Error at attaching", localEntry);
                else
                    logger?.LogError("Error at attaching: {ex}", ex.Message);

                if (aofSyncTaskInfo != null) _ = clusterProvider.replicationManager.TryRemoveReplicationTask(aofSyncTaskInfo);
                errorMsg = ex.Message;// this is error sent to remote client
                return false;
            }
            finally
            {
                // At this point the replica has received the most recent checkpoint data
                // and recovered from it so primary can release and delete it safely
                localEntry?.RemoveReader();
                gcs.Dispose();
            }
            return true;
        }

        public async Task<(CheckpointEntry, AofSyncTaskInfo)> AcquireCheckpointEntry()
        {
            AofSyncTaskInfo aofSyncTaskInfo;
            CheckpointEntry cEntry;

            // This loop tries to provide the following two guarantees
            // 1. Retrieve latest checkpoint and lock it to prevent deletion before it is send to the replica
            // 2. Guard against truncation of AOF in between the retrieval of the checkpoint metadata and start of the aofSyncTask
            var iteration = 0;
            var numOdcAttempts = 0;
            const int maxOdcAttempts = 2;
            while (true)
            {
                logger?.LogInformation("AcquireCheckpointEntry iteration {iteration}", iteration);
                iteration++;

                aofSyncTaskInfo = null;
                cEntry = default;

                // Acquire startSaveTime to identify if an external task might have taken the checkpoint for us
                // This is only useful for MainMemoryReplication where we might have multiple replicas attaching
                // We want to share the on-demand checkpoint and ensure that only one replica should succeed when calling TakeOnDemandCheckpoint
                var lastSaveTime = storeWrapper.lastSaveTime;

                var exceptionInjected = ExceptionInjectionHelper.TriggerCondition(ExceptionInjectionType.Replication_Acquire_Checkpoint_Entry_Fail_Condition);

                // Retrieve latest checkpoint and lock it from deletion operations
                var addedReader = !exceptionInjected && clusterProvider.replicationManager.TryGetLatestCheckpointEntryFromMemory(out cEntry);

                if (!addedReader)
                {
                    // Fail to acquire lock, could mean that a writer might be trying to delete
                    logger?.LogWarning("Could not acquire lock for existing checkpoint, retrying.");

                    // Go back to re-acquire the latest checkpoint
                    await Task.Yield();
                    continue;
                }

#if DEBUG
                // Only on Debug mode
                await ExceptionInjectionHelper.WaitOnSet(ExceptionInjectionType.Replication_Wait_After_Checkpoint_Acquisition);
#endif

                // Calculate the minimum start address covered by this checkpoint
                var startAofAddress = cEntry.GetMinAofCoveredAddress();

                // If there is possible AOF data loss and we need to take an on-demand checkpoint,
                // then we should take the checkpoint before we register the sync task, because
                // TryAddReplicationTask is guaranteed to return true in this scenario.
                var validMetadata = ValidateMetadata(cEntry, out _, out _, out _, out _, out _, out _);
                if (clusterProvider.serverOptions.OnDemandCheckpoint &&
                    (startAofAddress < clusterProvider.replicationManager.AofTruncatedUntil || !validMetadata))
                {
                    if (numOdcAttempts >= maxOdcAttempts && clusterProvider.AllowDataLoss)
                    {
                        logger?.LogWarning("Failed to acquire checkpoint after {numOdcAttempts} on-demand checkpoint attempts. Possible data loss, startAofAddress:{startAofAddress} < truncatedUntil:{truncatedUntil}.", numOdcAttempts, startAofAddress, clusterProvider.replicationManager.AofTruncatedUntil);
                    }
                    else
                    {
                        cEntry.RemoveReader();
                        numOdcAttempts++;
                        logger?.LogInformation("Taking on-demand checkpoint, attempt {numOdcAttempts}.", numOdcAttempts);
                        await storeWrapper.TakeOnDemandCheckpoint(lastSaveTime);
                        await Task.Yield();
                        continue;
                    }
                }

                // Enqueue AOF sync task with startAofAddress to prevent future AOF truncations
                // and check if truncation has happened in between retrieving the latest checkpoint and enqueuing the aofSyncTask
                if (clusterProvider.replicationManager.TryAddReplicationTask(replicaNodeId, startAofAddress, out aofSyncTaskInfo))
                    break;

                // Unlock last checkpoint because associated startAofAddress is no longer available
                cEntry.RemoveReader();

                // Go back to re-acquire checkpoint
                await Task.Yield();
            }

            return (cEntry, aofSyncTaskInfo);
        }

        private async Task SendCheckpointMetadata(GarnetClientSession gcs, GarnetClusterCheckpointManager ckptManager, CheckpointFileType fileType, Guid fileToken)
        {
            var retryCount = validateMetadataMaxRetryCount;
            while (true)
            {
                try
                {
                    logger?.LogInformation("<Begin sending checkpoint metadata {fileToken} {fileType}", fileToken, fileType);
                    var checkpointMetadata = Array.Empty<byte>();
                    if (fileToken != default)
                    {
                        switch (fileType)
                        {
                            case CheckpointFileType.STORE_SNAPSHOT:
                            case CheckpointFileType.OBJ_STORE_SNAPSHOT:
                                checkpointMetadata = ckptManager.GetLogCheckpointMetadata(fileToken, null, true, -1);
                                break;
                            case CheckpointFileType.STORE_INDEX:
                            case CheckpointFileType.OBJ_STORE_INDEX:
                                checkpointMetadata = ckptManager.GetIndexCheckpointMetadata(fileToken);
                                break;
                        }
                    }

                    var resp = await gcs.ExecuteSendCkptMetadata(fileToken.ToByteArray(), (int)fileType, checkpointMetadata).WaitAsync(replicaSyncTimeout, cts.Token).ConfigureAwait(false);
                    if (!resp.Equals("OK"))
                    {
                        logger?.LogError("Primary error at SendCheckpointMetadata {resp}", resp);
                        throw new Exception($"Primary error at SendCheckpointMetadata {resp}");
                    }

                    logger?.LogInformation("<Complete sending checkpoint metadata {fileToken} {fileType}", fileToken, fileType);
                    break; // Exit loop if metadata sent successfully
                }
                catch (Exception ex)
                {
                    logger?.LogError("SendCheckpointMetadata Error: {msg}", ex.Message);
                    if (retryCount-- <= 0)
                        throw new Exception("Max retry attempts reached for checkpoint metadata sending.");
                }
                await Task.Yield();
            }
        }

        private async Task SendFileSegments(GarnetClientSession gcs, Guid token, CheckpointFileType type, long startAddress, long endAddress, int batchSize = 1 << 17)
        {
            var fileTokenBytes = token.ToByteArray();
            var device = clusterProvider.replicationManager.GetInitializedSegmentFileDevice(token, type);

            Debug.Assert(device != null);
            batchSize = !ReplicationManager.ShouldInitialize(type) ?
                batchSize : (int)Math.Min(batchSize, 1L << clusterProvider.serverOptions.SegmentSizeBits());
            string resp;

            logger?.LogInformation("<Begin sending checkpoint file segments {guid} {type} {startAddress} {endAddress} {batchSize}", token, type, startAddress, endAddress, batchSize);
            try
            {
                while (startAddress < endAddress)
                {
                    var num_bytes = startAddress + batchSize < endAddress ?
                        batchSize :
                        (int)(endAddress - startAddress);
                    var (pbuffer, readBytes) = await ReadInto(device, (ulong)startAddress, num_bytes).ConfigureAwait(false);

                    resp = await gcs.ExecuteSendFileSegments(fileTokenBytes, (int)type, startAddress, pbuffer.GetSlice(readBytes)).WaitAsync(replicaSyncTimeout, cts.Token).ConfigureAwait(false);
                    if (!resp.Equals("OK"))
                    {
                        logger?.LogError("Primary error at SendFileSegments {type} {resp}", type, resp);
                        throw new Exception($"Primary error at SendFileSegments {type} {resp}");
                    }
                    pbuffer.Return();
                    startAddress += readBytes;
                }

                // Send last empty package to indicate end of transmission and let replica dispose IDevice
                resp = await gcs.ExecuteSendFileSegments(fileTokenBytes, (int)type, startAddress, []).WaitAsync(replicaSyncTimeout, cts.Token).ConfigureAwait(false);
                if (!resp.Equals("OK"))
                {
                    logger?.LogError("Primary error at SendFileSegments {type} {resp}", type, resp);
                    throw new Exception($"Primary error at SendFileSegments {type} {resp}");
                }
            }
            finally
            {
                device.Dispose();
            }
            logger?.LogInformation("<Complete sending checkpoint file segments {guid} {type} {startAddress} {endAddress}", token, type, startAddress, endAddress);
        }

        private async Task SendObjectFiles(GarnetClientSession gcs, Guid token, CheckpointFileType type, int segmentCount, int batchSize = 1 << 17)
        {
            var fileTokenBytes = token.ToByteArray();
            IDevice device = null;
            string resp;
            try
            {
                for (var segment = 0; segment < segmentCount; segment++)
                {
                    device = clusterProvider.replicationManager.GetInitializedSegmentFileDevice(token, type);
                    Debug.Assert(device != null);
                    device.Initialize(-1);
                    var size = device.GetFileSize(segment);
                    var startAddress = 0L;

                    while (startAddress < size)
                    {
                        var num_bytes = startAddress + batchSize < size ? batchSize : (int)(size - startAddress);
                        var (pbuffer, readBytes) = await ReadInto(device, (ulong)startAddress, num_bytes, segment).ConfigureAwait(false);

                        resp = await gcs.ExecuteSendFileSegments(fileTokenBytes, (int)type, startAddress, pbuffer.GetSlice(readBytes), segment).
                            WaitAsync(replicaSyncTimeout, cts.Token).ConfigureAwait(false);
                        if (!resp.Equals("OK"))
                        {
                            logger?.LogError("Primary error at SendFileSegments {type} {resp}", type, resp);
                            throw new Exception($"Primary error at SendFileSegments {type} {resp}");
                        }

                        pbuffer.Return();
                        startAddress += readBytes;
                    }

                    resp = await gcs.ExecuteSendFileSegments(fileTokenBytes, (int)type, 0L, []).WaitAsync(replicaSyncTimeout, cts.Token).ConfigureAwait(false);
                    if (!resp.Equals("OK"))
                    {
                        logger?.LogError("Primary error at SendFileSegments {type} {resp}", type, resp);
                        throw new Exception($"Primary error at SendFileSegments {type} {resp}");
                    }
                    device.Dispose();
                    device = null;
                }
            }
            finally
            {
                device?.Dispose();
            }
        }

        /// <summary>
        /// Note: will read potentially more data (based on sector alignment)
        /// </summary>
        /// <param name="device"></param>
        /// <param name="address"></param>
        /// <param name="size"></param>
        /// <param name="segmentId"></param>
        private async Task<(SectorAlignedMemory, int)> ReadInto(IDevice device, ulong address, int size, int segmentId = -1)
        {
            bufferPool ??= new SectorAlignedBufferPool(1, (int)device.SectorSize);

            long numBytesToRead = size;
            numBytesToRead = ((numBytesToRead + (device.SectorSize - 1)) & ~(device.SectorSize - 1));

            var pbuffer = bufferPool.Get((int)numBytesToRead);
            unsafe
            {
                if (segmentId == -1)
                    device.ReadAsync(address, (IntPtr)pbuffer.aligned_pointer, (uint)numBytesToRead, IOCallback, null);
                else
                    device.ReadAsync(segmentId, address, (IntPtr)pbuffer.aligned_pointer, (uint)numBytesToRead, IOCallback, null);
            }
            await semaphore.WaitAsync(replicaSyncTimeout, cts.Token).ConfigureAwait(false);
            return (pbuffer, (int)numBytesToRead);
        }

        private unsafe void IOCallback(uint errorCode, uint numBytes, object context)
        {
            if (errorCode != 0)
            {
                var errorMessage = Tsavorite.core.Utility.GetCallbackErrorMessage(errorCode, numBytes, context);
                logger?.LogError("[ReplicaSyncSession] OverlappedStream GetQueuedCompletionStatus error: {errorCode} msg: {errorMessage}", errorCode, errorMessage);
            }
            semaphore.Release();
        }
    }

    internal static unsafe class SectorAlignedMemoryExtensions
    {
        public static Span<byte> GetSlice(this SectorAlignedMemory pbuffer, int length)
        {
            return new Span<byte>(pbuffer.aligned_pointer, length);
        }
    }
}