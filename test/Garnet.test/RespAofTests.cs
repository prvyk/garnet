﻿// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using Garnet.server;
using NUnit.Framework;
using NUnit.Framework.Legacy;
using StackExchange.Redis;

namespace Garnet.test
{
    [TestFixture]
    public class RespAofTests
    {
        GarnetServer server;
        private IReadOnlyDictionary<string, RespCommandsInfo> respCustomCommandsInfo;

        static readonly SortedSetEntry[] entries =
        [
            new SortedSetEntry("a", 1),
            new SortedSetEntry("b", 2),
            new SortedSetEntry("c", 3),
            new SortedSetEntry("d", 4),
            new SortedSetEntry("e", 5),
            new SortedSetEntry("f", 6),
            new SortedSetEntry("g", 7),
            new SortedSetEntry("h", 8),
            new SortedSetEntry("i", 9),
            new SortedSetEntry("j", 10)
        ];

        [SetUp]
        public void Setup()
        {
            TestUtils.DeleteDirectory(TestUtils.MethodTestDir, wait: true);
            ClassicAssert.IsTrue(TestUtils.TryGetCustomCommandsInfo(out respCustomCommandsInfo));
            ClassicAssert.IsNotNull(respCustomCommandsInfo);
            server = TestUtils.CreateGarnetServer(TestUtils.MethodTestDir, enableAOF: true, lowMemory: true);
            server.Start();
        }

        [TearDown]
        public void TearDown()
        {
            server.Dispose();
            TestUtils.DeleteDirectory(TestUtils.MethodTestDir);
        }

        [Test]
        public void AofUpsertStoreRecoverTest()
        {
            using (var redis = ConnectionMultiplexer.Connect(TestUtils.GetConfig()))
            {
                var db = redis.GetDatabase(0);
                db.StringSet("SeAofUpsertRecoverTestKey1", "SeAofUpsertRecoverTestValue1");
                db.StringSet("SeAofUpsertRecoverTestKey2", "SeAofUpsertRecoverTestValue2");
            }

            server.Store.CommitAOF(true);
            server.Dispose(false);
            server = TestUtils.CreateGarnetServer(TestUtils.MethodTestDir, tryRecover: true, enableAOF: true);
            server.Start();

            using (var redis = ConnectionMultiplexer.Connect(TestUtils.GetConfig()))
            {
                var db = redis.GetDatabase(0);
                var recoveredValue = db.StringGet("SeAofUpsertRecoverTestKey1");
                ClassicAssert.AreEqual("SeAofUpsertRecoverTestValue1", recoveredValue.ToString());
                recoveredValue = db.StringGet("SeAofUpsertRecoverTestKey2");
                ClassicAssert.AreEqual("SeAofUpsertRecoverTestValue2", recoveredValue.ToString());
            }
        }

        [Test]
        public void AofUpsertStoreAutoCommitRecoverTest()
        {
            using (var redis = ConnectionMultiplexer.Connect(TestUtils.GetConfig()))
            {
                var db = redis.GetDatabase(0);
                db.StringSet("SeAofUpsertRecoverTestKey1", "SeAofUpsertRecoverTestValue1");
                db.StringSet("SeAofUpsertRecoverTestKey2", "SeAofUpsertRecoverTestValue2");
            }

            server.Store.WaitForCommit();
            server.Dispose(false);
            server = TestUtils.CreateGarnetServer(TestUtils.MethodTestDir, tryRecover: true, enableAOF: true);
            server.Start();

            using (var redis = ConnectionMultiplexer.Connect(TestUtils.GetConfig()))
            {
                var db = redis.GetDatabase(0);
                var recoveredValue = db.StringGet("SeAofUpsertRecoverTestKey1");
                ClassicAssert.AreEqual("SeAofUpsertRecoverTestValue1", recoveredValue.ToString());
                recoveredValue = db.StringGet("SeAofUpsertRecoverTestKey2");
                ClassicAssert.AreEqual("SeAofUpsertRecoverTestValue2", recoveredValue.ToString());
            }
        }

        [Test]
        [CancelAfter(10_000)]
        public void AofUpsertStoreCommitTaskRecoverTest()
        {
            server.Dispose(false);
            server = TestUtils.CreateGarnetServer(TestUtils.MethodTestDir, tryRecover: false, enableAOF: true, commitFrequencyMs: 100);
            server.Start();

            using (var redis = ConnectionMultiplexer.Connect(TestUtils.GetConfig()))
            {
                var db = redis.GetDatabase(0);
                db.StringSet("SeAofUpsertRecoverTestKey1", "SeAofUpsertRecoverTestValue1");
                db.StringSet("SeAofUpsertRecoverTestKey2", "SeAofUpsertRecoverTestValue2");
            }

            server.Store.WaitForCommit();
            server.Dispose(false);
            server = TestUtils.CreateGarnetServer(TestUtils.MethodTestDir, tryRecover: true, enableAOF: true);
            server.Start();

            using (var redis = ConnectionMultiplexer.Connect(TestUtils.GetConfig()))
            {
                var db = redis.GetDatabase(0);
                var recoveredValue = db.StringGet("SeAofUpsertRecoverTestKey1");
                ClassicAssert.AreEqual("SeAofUpsertRecoverTestValue1", recoveredValue.ToString());
                recoveredValue = db.StringGet("SeAofUpsertRecoverTestKey2");
                ClassicAssert.AreEqual("SeAofUpsertRecoverTestValue2", recoveredValue.ToString());
            }
        }

        [Test]
        public void AofUpsertStoreAutoCommitCommitWaitRecoverTest()
        {
            server.Dispose(false);
            server = TestUtils.CreateGarnetServer(TestUtils.MethodTestDir, tryRecover: false, enableAOF: true, commitWait: true);
            server.Start();

            using (var redis = ConnectionMultiplexer.Connect(TestUtils.GetConfig()))
            {
                var db = redis.GetDatabase(0);
                db.StringSet("SeAofUpsertRecoverTestKey1", "SeAofUpsertRecoverTestValue1");
                db.StringSet("SeAofUpsertRecoverTestKey2", "SeAofUpsertRecoverTestValue2");
            }
            server.Dispose(false);
            server = TestUtils.CreateGarnetServer(TestUtils.MethodTestDir, tryRecover: true, enableAOF: true);
            server.Start();

            using (var redis = ConnectionMultiplexer.Connect(TestUtils.GetConfig()))
            {
                var db = redis.GetDatabase(0);
                var recoveredValue = db.StringGet("SeAofUpsertRecoverTestKey1");
                ClassicAssert.AreEqual("SeAofUpsertRecoverTestValue1", recoveredValue.ToString());
                recoveredValue = db.StringGet("SeAofUpsertRecoverTestKey2");
                ClassicAssert.AreEqual("SeAofUpsertRecoverTestValue2", recoveredValue.ToString());
            }
        }

        [Test]
        public void AofTransactionStoreAutoCommitCommitWaitRecoverTest()
        {
            server.Dispose(false);
            server = TestUtils.CreateGarnetServer(TestUtils.MethodTestDir, tryRecover: false, enableAOF: true, commitWait: true);
            server.Start();

            using (var redis = ConnectionMultiplexer.Connect(TestUtils.GetConfig()))
            {
                var db = redis.GetDatabase(0);
                var transaction = db.CreateTransaction();
                transaction.StringSetAsync("SeAofUpsertRecoverTestKey1", "SeAofUpsertRecoverTestValue1");
                transaction.StringSetAsync("SeAofUpsertRecoverTestKey2", "SeAofUpsertRecoverTestValue2");

                ClassicAssert.IsTrue(transaction.Execute());
            }
            server.Dispose(false);
            server = TestUtils.CreateGarnetServer(TestUtils.MethodTestDir, tryRecover: true, enableAOF: true);
            server.Start();

            using (var redis = ConnectionMultiplexer.Connect(TestUtils.GetConfig()))
            {
                var db = redis.GetDatabase(0);
                var recoveredValue = db.StringGet("SeAofUpsertRecoverTestKey1");
                ClassicAssert.AreEqual("SeAofUpsertRecoverTestValue1", recoveredValue.ToString());
                recoveredValue = db.StringGet("SeAofUpsertRecoverTestKey2");
                ClassicAssert.AreEqual("SeAofUpsertRecoverTestValue2", recoveredValue.ToString());
            }
        }

        [Test]
        public void AofUpsertStoreCkptRecoverTest()
        {
            using (var redis = ConnectionMultiplexer.Connect(TestUtils.GetConfig(allowAdmin: true)))
            {
                var db = redis.GetDatabase(0);
                db.StringSet("SeAofUpsertRecoverTestKey1", "SeAofUpsertRecoverTestValue1");
                db.StringSet("SeAofUpsertRecoverTestKey2", "SeAofUpsertRecoverTestValue2");

                // Issue and wait for DB save
                var server = redis.GetServer(TestUtils.EndPoint);
                server.Save(SaveType.BackgroundSave);
                while (server.LastSave().Ticks == DateTimeOffset.FromUnixTimeSeconds(0).Ticks) Thread.Sleep(10);

                // Issue additional SET for AOF to process
                db.StringSet("SeAofUpsertRecoverTestKey3", "SeAofUpsertRecoverTestValue3");
            }

            server.Store.CommitAOF(true);
            server.Dispose(false);
            server = TestUtils.CreateGarnetServer(TestUtils.MethodTestDir, tryRecover: true, enableAOF: true);
            server.Start();

            using (var redis = ConnectionMultiplexer.Connect(TestUtils.GetConfig()))
            {
                var db = redis.GetDatabase(0);
                var recoveredValue = db.StringGet("SeAofUpsertRecoverTestKey1");
                ClassicAssert.AreEqual("SeAofUpsertRecoverTestValue1", recoveredValue.ToString());
                recoveredValue = db.StringGet("SeAofUpsertRecoverTestKey2");
                ClassicAssert.AreEqual("SeAofUpsertRecoverTestValue2", recoveredValue.ToString());
                recoveredValue = db.StringGet("SeAofUpsertRecoverTestKey3");
                ClassicAssert.AreEqual("SeAofUpsertRecoverTestValue3", recoveredValue.ToString());
            }
        }

        [Test]
        public void AofRMWStoreRecoverTest()
        {
            using (var redis = ConnectionMultiplexer.Connect(TestUtils.GetConfig()))
            {
                var db = redis.GetDatabase(0);
                db.StringSet("SeAofUpsertRecoverTestKey1", "SeAofUpsertRecoverTestValue1", expiry: TimeSpan.FromDays(1), when: When.NotExists);
                db.StringSet("SeAofUpsertRecoverTestKey2", "SeAofUpsertRecoverTestValue2", expiry: TimeSpan.FromDays(1), when: When.NotExists);
                db.Execute("SET", "SeAofUpsertRecoverTestKey3", "SeAofUpsertRecoverTestValue3", "WITHETAG");
                db.Execute("SETIFMATCH", "SeAofUpsertRecoverTestKey3", "UpdatedSeAofUpsertRecoverTestValue3", "1");
                db.Execute("SET", "SeAofUpsertRecoverTestKey4", "2");
                var res = db.Execute("INCR", "SeAofUpsertRecoverTestKey4");
            }

            server.Store.CommitAOF(true);
            server.Dispose(false);
            server = TestUtils.CreateGarnetServer(TestUtils.MethodTestDir, tryRecover: true, enableAOF: true);
            server.Start();

            using (var redis = ConnectionMultiplexer.Connect(TestUtils.GetConfig()))
            {
                var db = redis.GetDatabase(0);
                var recoveredValue = db.StringGet("SeAofUpsertRecoverTestKey1");
                ClassicAssert.AreEqual("SeAofUpsertRecoverTestValue1", recoveredValue.ToString());
                recoveredValue = db.StringGet("SeAofUpsertRecoverTestKey2");
                ClassicAssert.AreEqual("SeAofUpsertRecoverTestValue2", recoveredValue.ToString());
                ExpectedEtagTest(db, "SeAofUpsertRecoverTestKey3", "UpdatedSeAofUpsertRecoverTestValue3", 2);
                recoveredValue = db.StringGet("SeAofUpsertRecoverTestKey4");
                ClassicAssert.AreEqual("3", recoveredValue.ToString());
            }
        }

        [Test]
        public void AofDeleteStoreRecoverTest()
        {
            using (var redis = ConnectionMultiplexer.Connect(TestUtils.GetConfig()))
            {
                var db = redis.GetDatabase(0);
                db.StringSet("SeAofDeleteRecoverTestKey1", "SeAofDeleteRecoverTestKey1");
                db.StringSet("SeAofDeleteRecoverTestKey2", "SeAofDeleteRecoverTestKey2");

                var val = (string)db.StringGet("SeAofDeleteRecoverTestKey1");
                ClassicAssert.AreEqual("SeAofDeleteRecoverTestKey1", val);

                val = (string)db.StringGet("SeAofDeleteRecoverTestKey2");
                ClassicAssert.AreEqual("SeAofDeleteRecoverTestKey2", val);

                db.KeyDelete("SeAofDeleteRecoverTestKey1");
                val = (string)db.StringGet("SeAofDeleteRecoverTestKey1");
                ClassicAssert.AreEqual(null, val);
            }

            server.Store.CommitAOF(true);
            server.Dispose(false);
            server = TestUtils.CreateGarnetServer(TestUtils.MethodTestDir, tryRecover: true, enableAOF: true);
            server.Start();

            using (var redis = ConnectionMultiplexer.Connect(TestUtils.GetConfig()))
            {
                var db = redis.GetDatabase(0);

                var val = (string)db.StringGet("SeAofDeleteRecoverTestKey1");
                ClassicAssert.AreEqual(null, val);

                val = (string)db.StringGet("SeAofDeleteRecoverTestKey2");
                ClassicAssert.AreEqual("SeAofDeleteRecoverTestKey2", val);
            }
        }

        [Test]
        public void AofExpiryRMWStoreRecoverTest()
        {
            using (var redis = ConnectionMultiplexer.Connect(TestUtils.GetConfig()))
            {
                var db = redis.GetDatabase(0);
                db.StringSet("AofExpiryRMWStoreRecoverTestKey1", "AofExpiryRMWStoreRecoverTestValue1", expiry: TimeSpan.FromDays(1), when: When.NotExists);
                db.StringSet("AofExpiryRMWStoreRecoverTestKey2", "AofExpiryRMWStoreRecoverTestValue2", expiry: TimeSpan.FromSeconds(1), when: When.NotExists);
                Thread.Sleep(2000);
                db.StringSet("AofExpiryRMWStoreRecoverTestKey1", "AofExpiryRMWStoreRecoverTestValue3", expiry: TimeSpan.FromDays(1), when: When.NotExists);
                db.StringSet("AofExpiryRMWStoreRecoverTestKey2", "AofExpiryRMWStoreRecoverTestValue4", expiry: TimeSpan.FromSeconds(10), when: When.NotExists);

                var recoveredValue = db.StringGet("AofExpiryRMWStoreRecoverTestKey1");
                ClassicAssert.AreEqual("AofExpiryRMWStoreRecoverTestValue1", recoveredValue.ToString());
                recoveredValue = db.StringGet("AofExpiryRMWStoreRecoverTestKey2");
                ClassicAssert.AreEqual("AofExpiryRMWStoreRecoverTestValue4", recoveredValue.ToString());
            }

            server.Store.CommitAOF(true);
            server.Dispose(false);
            server = TestUtils.CreateGarnetServer(TestUtils.MethodTestDir, tryRecover: true, enableAOF: true);
            server.Start();

            using (var redis = ConnectionMultiplexer.Connect(TestUtils.GetConfig()))
            {
                var db = redis.GetDatabase(0);
                var recoveredValue = db.StringGet("AofExpiryRMWStoreRecoverTestKey1");
                ClassicAssert.AreEqual("AofExpiryRMWStoreRecoverTestValue1", recoveredValue.ToString());
                recoveredValue = db.StringGet("AofExpiryRMWStoreRecoverTestKey2");
                ClassicAssert.AreEqual("AofExpiryRMWStoreRecoverTestValue4", recoveredValue.ToString());
            }
        }

        [Test]
        public void AofRMWObjectStoreRecoverTest()
        {
            var key = "AofRMWObjectStoreRecoverTestKey";

            using (var redis = ConnectionMultiplexer.Connect(TestUtils.GetConfig()))
            {
                var db = redis.GetDatabase(0);

                var added = db.SortedSetAdd(key, entries);

                var score = db.SortedSetScore(key, "a");
                ClassicAssert.True(score.HasValue);
                ClassicAssert.AreEqual(1, score.Value);

                score = db.SortedSetScore(key, "x");
                ClassicAssert.False(score.HasValue);
            }

            server.Store.CommitAOF(true);
            server.Dispose(false);
            server = TestUtils.CreateGarnetServer(TestUtils.MethodTestDir, tryRecover: true, enableAOF: true);
            server.Start();

            using (var redis = ConnectionMultiplexer.Connect(TestUtils.GetConfig()))
            {
                var db = redis.GetDatabase(0);

                var score = db.SortedSetScore(key, "a");
                ClassicAssert.True(score.HasValue);
                ClassicAssert.AreEqual(1, score.Value);

                score = db.SortedSetScore(key, "x");
                ClassicAssert.False(score.HasValue);
            }
        }

        [Test]
        public void AofDeleteObjectStoreRecoverTest()
        {
            var key1 = "AofDeleteObjectStoreRecoverTestKey1";
            var key2 = "AofDeleteObjectStoreRecoverTestKey2";
            using (var redis = ConnectionMultiplexer.Connect(TestUtils.GetConfig()))
            {
                var db = redis.GetDatabase(0);

                var added = db.SortedSetAdd(key1, entries);
                var score = db.SortedSetScore(key1, "a");
                ClassicAssert.True(score.HasValue);
                ClassicAssert.AreEqual(1, score.Value);

                score = db.SortedSetScore(key1, "x");
                ClassicAssert.False(score.HasValue);

                added = db.SortedSetAdd(key2, entries);
                score = db.SortedSetScore(key2, "a");
                ClassicAssert.True(score.HasValue);
                ClassicAssert.AreEqual(1, score.Value);

                score = db.SortedSetScore(key2, "x");
                ClassicAssert.False(score.HasValue);

                db.KeyDelete(key1);
            }

            server.Store.CommitAOF(true);
            server.Dispose(false);
            server = TestUtils.CreateGarnetServer(TestUtils.MethodTestDir, tryRecover: true, enableAOF: true);
            server.Start();

            using (var redis = ConnectionMultiplexer.Connect(TestUtils.GetConfig()))
            {
                var db = redis.GetDatabase(0);
                var exist1 = db.KeyExists(key1);
                ClassicAssert.IsFalse(exist1);
                var exist2 = db.KeyExists(key2);
                ClassicAssert.IsTrue(exist2);
            }
        }

        [Test]
        public void AofRMWObjectStoreCopyUpdateRecoverTest()
        {
            var key = "AofRMWObjectStoreRecoverTestKey";

            using (var redis = ConnectionMultiplexer.Connect(TestUtils.GetConfig()))
            {
                var db = redis.GetDatabase(0);
                for (int i = 0; i < 100; i++)
                {
                    SortedSetEntry[] entry = [new SortedSetEntry("a", 1), new SortedSetEntry("b", 2)];
                    db.SortedSetAdd(key + i, entry);

                    var score = db.SortedSetScore(key + i, "a");
                    ClassicAssert.True(score.HasValue);
                    ClassicAssert.AreEqual(1, score.Value);

                }
                SortedSetEntry[] newEntries = [new SortedSetEntry("bbbb", 4)];
                db.SortedSetAdd("AofRMWObjectStoreRecoverTestKey" + 1, newEntries);
            }
            server.Store.CommitAOF(true);
            server.Dispose(false);
            server = TestUtils.CreateGarnetServer(TestUtils.MethodTestDir, tryRecover: true, enableAOF: true);
            server.Start();

            using (var redis = ConnectionMultiplexer.Connect(TestUtils.GetConfig()))
            {
                var db = redis.GetDatabase(0);

                var score = db.SortedSetScore(key + 1, "bbbb");
                ClassicAssert.True(score.HasValue);
                ClassicAssert.AreEqual(4, score.Value);

                score = db.SortedSetScore(key + 1, "x");
                ClassicAssert.False(score.HasValue);
            }
        }

        [Test]
        public void AofUpsertObjectStoreRecoverTest()
        {
            var origList = new RedisValue[] { "a", "b", "c", "d" };
            var key1 = "lkey1";
            var key2 = "lkey2";

            using (var redis = ConnectionMultiplexer.Connect(TestUtils.GetConfig()))
            {
                var db = redis.GetDatabase(0);
                var count = db.ListRightPush(key1, origList);
                ClassicAssert.AreEqual(4, count);

                var result = db.ListRange(key1);
                ClassicAssert.AreEqual(origList, result);

                var rb = db.KeyRename(key1, key2);
                ClassicAssert.IsTrue(rb);
                result = db.ListRange(key1);
                ClassicAssert.AreEqual(Array.Empty<RedisValue>(), result);

                result = db.ListRange(key2);
                ClassicAssert.AreEqual(origList, result);
            }

            server.Store.CommitAOF(true);
            server.Dispose(false);
            server = TestUtils.CreateGarnetServer(TestUtils.MethodTestDir, tryRecover: true, enableAOF: true);
            server.Start();

            using (var redis = ConnectionMultiplexer.Connect(TestUtils.GetConfig()))
            {
                var db = redis.GetDatabase(0);

                var result = db.ListRange(key2);
                ClassicAssert.AreEqual(origList, result);
            }
        }

        [Test]
        public void AofUpsertCustomObjectRecoverTest()
        {
            void RegisterCustomCommand(GarnetServer gServer)
            {
                var factory = new MyDictFactory();
                gServer.Register.NewCommand("MYDICTSET", CommandType.ReadModifyWrite, factory, new MyDictSet(), respCustomCommandsInfo["MYDICTSET"]);
                gServer.Register.NewCommand("MYDICTGET", CommandType.Read, factory, new MyDictGet(), respCustomCommandsInfo["MYDICTGET"]);
            }

            server.Dispose(false);
            server = TestUtils.CreateGarnetServer(TestUtils.MethodTestDir, enableAOF: true);
            RegisterCustomCommand(server);
            server.Start();

            var mainKey1 = "key1";
            var subKey = "subKey";
            var subKeyValue = "subKeyValue";
            var mainKey2 = "key2";
            using (var redis = ConnectionMultiplexer.Connect(TestUtils.GetConfig(allowAdmin: true)))
            {
                var db = redis.GetDatabase(0);

                db.Execute("MYDICTSET", mainKey1, subKey, subKeyValue);
                var retValue = db.Execute("MYDICTGET", mainKey1, subKey);
                ClassicAssert.AreEqual(subKeyValue, (string)retValue);

                var rb = db.KeyRename(mainKey1, mainKey2);
                ClassicAssert.IsTrue(rb);
                retValue = db.Execute("MYDICTGET", mainKey1, subKey);
                ClassicAssert.IsTrue(retValue.IsNull);

                retValue = db.Execute("MYDICTGET", mainKey2, subKey);
                ClassicAssert.AreEqual(subKeyValue, (string)retValue);
            }

            server.Store.CommitAOF(true);
            server.Dispose(false);
            server = TestUtils.CreateGarnetServer(TestUtils.MethodTestDir, tryRecover: true, enableAOF: true);
            RegisterCustomCommand(server);
            server.Start();

            using (var redis = ConnectionMultiplexer.Connect(TestUtils.GetConfig()))
            {
                var db = redis.GetDatabase(0);

                var retValue = db.Execute("MYDICTGET", mainKey2, subKey);
                ClassicAssert.AreEqual(subKeyValue, (string)retValue);
            }
        }

        [Test]
        public void AofUpsertCustomScriptRecoverTest()
        {
            static void ValidateServerData(IDatabase db, string strKey, string strValue, string listKey, string listValue)
            {
                var retValue = db.StringGet(strKey);
                ClassicAssert.AreEqual(strValue, (string)retValue);
                var retList = db.ListRange(listKey);
                ClassicAssert.AreEqual(1, retList.Length);
                ClassicAssert.AreEqual(listValue, (string)retList[0]);
            }

            server.Dispose(false);
            server = TestUtils.CreateGarnetServer(TestUtils.MethodTestDir, enableAOF: true);
            server.Register.NewProcedure("SETMAINANDOBJECT", () => new SetStringAndList());
            server.Start();

            var strKey = "StrKey";
            var strValue = "StrValue";
            var listKey = "ListKey";
            var listValue = "ListValue";

            using (var redis = ConnectionMultiplexer.Connect(TestUtils.GetConfig(allowAdmin: true)))
            {
                var db = redis.GetDatabase(0);
                db.Execute("SETMAINANDOBJECT", strKey, strValue, listKey, listValue);
                ValidateServerData(db, strKey, strValue, listKey, listValue);
            }

            server.Store.CommitAOF(true);
            server.Dispose(false);
            server = TestUtils.CreateGarnetServer(TestUtils.MethodTestDir, tryRecover: true, enableAOF: true);
            server.Register.NewProcedure("SETMAINANDOBJECT", () => new SetStringAndList());
            server.Start();

            using (var redis = ConnectionMultiplexer.Connect(TestUtils.GetConfig()))
            {
                ValidateServerData(redis.GetDatabase(0), strKey, strValue, listKey, listValue);
            }
        }

        [Test]
        public void AofMultiRMWStoreCkptRecoverTest()
        {
            long ret = 0;
            using (var redis = ConnectionMultiplexer.Connect(TestUtils.GetConfig(allowAdmin: true)))
            {
                var db = redis.GetDatabase(0);
                var server = redis.GetServer(TestUtils.EndPoint);
                ret = db.StringIncrement("key1", 2);
                ClassicAssert.AreEqual(2, ret);

                server.Save(SaveType.BackgroundSave);
                long lastSave = server.LastSave().Ticks;
                while (lastSave == DateTimeOffset.FromUnixTimeSeconds(0).Ticks)
                {
                    Thread.Yield();
                    lastSave = server.LastSave().Ticks;
                }

                ret = db.StringIncrement("key1", 2);
                ClassicAssert.AreEqual(4, ret);

                // Wait one second to ensure that the last save time is updated
                Thread.Sleep(1000);

                server.Save(SaveType.BackgroundSave);
                long lastSave2 = server.LastSave().Ticks;
                while (lastSave2 == lastSave)
                {
                    Thread.Yield();
                    lastSave2 = server.LastSave().Ticks;
                }

                ret = db.StringIncrement("key1", 2);
                ClassicAssert.AreEqual(6, ret);
            }

            server.Store.CommitAOF(true);
            server.Dispose(false);
            server = TestUtils.CreateGarnetServer(TestUtils.MethodTestDir, tryRecover: true, enableAOF: true);
            server.Start();

            using (var redis = ConnectionMultiplexer.Connect(TestUtils.GetConfig(allowAdmin: true)))
            {
                var db = redis.GetDatabase(0);
                ret = db.StringIncrement("key1", 2);
                ClassicAssert.AreEqual(8, ret);
            }
        }

        [Test]
        public void AofListObjectStoreRecoverTest()
        {
            var key = "AofListObjectStoreRecoverTest";
            var ldata = new RedisValue[] { "a", "b", "c", "d" };
            RedisValue[] returned_data_before_recovery = default;
            using (var redis = ConnectionMultiplexer.Connect(TestUtils.GetConfig()))
            {
                var db = redis.GetDatabase(0);

                var count = db.ListLeftPush(key, ldata);
                ClassicAssert.AreEqual(4, count);

                ldata = [.. ldata.Select(x => x).Reverse()];
                returned_data_before_recovery = db.ListRange(key);
                ClassicAssert.AreEqual(ldata, returned_data_before_recovery);
            }

            server.Store.CommitAOF(true);
            server.Dispose(false);
            server = TestUtils.CreateGarnetServer(TestUtils.MethodTestDir, tryRecover: true, enableAOF: true);
            server.Start();

            using (var redis = ConnectionMultiplexer.Connect(TestUtils.GetConfig()))
            {
                var db = redis.GetDatabase(0);
                var returnedData = db.ListRange(key);
                ClassicAssert.AreEqual(returned_data_before_recovery, returnedData);
                ClassicAssert.AreEqual(ldata, returnedData);
            }
        }

        [Test]
        public void AofCustomTxnRecoverTest()
        {
            server.Register.NewTransactionProc("READWRITETX", () => new ReadWriteTxn(), new RespCommandsInfo { Arity = 4 });
            string readkey = "readme";
            string readVal = "surewhynot";

            string writeKey1 = "writeme";
            string writeKey2 = "writemetoo";

            using (var redis = ConnectionMultiplexer.Connect(TestUtils.GetConfig()))
            {
                var db = redis.GetDatabase(0);
                ClassicAssert.IsTrue(db.StringSet(readkey, readVal));

                RedisResult result = db.Execute("READWRITETX", readkey, writeKey1, writeKey2);

                ClassicAssert.AreEqual("SUCCESS", result.ToString());
            }

            server.Store.CommitAOF(true);
            server.Dispose(false);

            server = TestUtils.CreateGarnetServer(TestUtils.MethodTestDir, tryRecover: true, enableAOF: true);
            server.Register.NewTransactionProc("READWRITETX", () => new ReadWriteTxn(), new RespCommandsInfo { Arity = 4 });
            server.Start();

            using (var redis = ConnectionMultiplexer.Connect(TestUtils.GetConfig()))
            {
                var db = redis.GetDatabase(0);

                string readKeysVal = db.StringGet(readkey);
                ClassicAssert.AreEqual(readVal, readKeysVal);

                string writeKeysVal = db.StringGet(writeKey1);
                ClassicAssert.AreEqual(readVal, writeKeysVal);

                string writeKeysVal2 = db.StringGet(writeKey2);
                ClassicAssert.AreEqual(readVal, writeKeysVal2);
            }
        }

        private static void ExpectedEtagTest(IDatabase db, string key, string expectedValue, long expected)
        {
            RedisResult res = db.Execute("GETWITHETAG", key);
            if (expectedValue == null)
            {
                ClassicAssert.IsTrue(res.IsNull);
                return;
            }

            RedisResult[] etagAndVal = (RedisResult[])res;
            RedisResult etag = etagAndVal[0];
            RedisResult val = etagAndVal[1];

            if (expected == -1)
            {
                ClassicAssert.IsTrue(etag.IsNull);
            }

            ClassicAssert.AreEqual(expectedValue, val.ToString());
        }
    }
}