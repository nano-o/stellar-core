// Copyright 2018 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "main/Config.h"
#include "util/Timer.h"
#include "xdrpp/marshal.h"
#include "xdr/TestCase.h"
#include "test/test.h"
#include "test/TestUtils.h"
#include "ledger/LedgerTxn.h"
#include "test/TxTests.h"
#include "transactions/TransactionFrameBase.h"

#include "main/ApplicationImpl.h"
#include "database/Database.h"
#include "bucket/BucketManager.h"
#include "bucket/BucketManagerImpl.h"
#include "test/ModelBasedTesting.h"
#include "xdrpp/printer.h"
#include "transactions/TransactionUtils.h"

using namespace stellar;
// using xdr::operator<<;

static std::vector<uint8_t>
readFile(const char*);

static Config
getConfig();

template<typename T>
T deserialize(std::string const& binFile) {
  std::vector<uint8_t> inputBytes = readFile(binFile.c_str());
  T t;
  xdr::xdr_get g(&inputBytes.front(), &inputBytes.back() + 1);
  xdr::xdr_argpack_archive(g, t);
  g.done();
  return t;
};

void
ModelBasedTesting::runModelBasedTest(std::string const& inputLedgerFile, std::string const& inputTxFile)
{
  VirtualClock clock;
  auto cfg = getConfig(); // memory mode is set in this cfg
  auto app = std::make_shared<ApplicationImpl>(clock, cfg);

  // Initialize to the genesis ledger:
  app->initialize(false, false);

  // Next we overwrite the genesis ledger.
  // erase the root account entry:
  auto &root = app->getLedgerTxnRoot();
  LedgerTxn ltx(root, false);
  SecretKey rootSKey = SecretKey::fromSeed(app->getNetworkID());
  auto rootKey = accountKey(rootSKey.getPublicKey());
  ltx.erase(rootKey);
  // update the ledger header
  TestLedger testLedger = deserialize<TestLedger>(inputLedgerFile);
  CLOG_DEBUG(Ledger, "Deserialized ledger header:\n {}", xdr::xdr_to_string(testLedger.ledgerHeader));
  auto& currentLH = ltx.loadHeader().current();
  auto& testLH = testLedger.ledgerHeader;
  currentLH.baseFee = testLH.baseFee;
  currentLH.baseReserve = testLH.baseReserve;
  currentLH.ledgerSeq = testLH.ledgerSeq;
  currentLH.totalCoins = testLH.totalCoins;
  // finally, create all ledger entries
  for (auto le : testLedger.ledgerEntries) {
    ltx.create(le);
  };
  ltx.commit();
  CLOG_INFO(Ledger, "Loaded ledger header and ledger entries from {}", inputLedgerFile);

  // Now execute the transaction
  // TODO: ideally we should call closeLedger
  LedgerTxn ltx2(root, false);
  TransactionEnvelope tx = deserialize<TransactionEnvelope>(inputTxFile);
  CLOG_DEBUG(Ledger, "Deserialized transaction:\n {}", xdr::xdr_to_string(tx));

  TransactionFrameBasePtr txfbp =
    TransactionFrameBase::makeTransactionFromWire(app->getNetworkID(),
        tx);
  TransactionMeta tm(2); // is this v2?
  txfbp->apply(*app, ltx2, tm);
  ltx2.commit();

  // TODO: it looks like the meta is not even populated if the transaction fails some basic validity checks.
  CLOG_DEBUG(Ledger, "TransactionMeta:\n {}", xdr::xdr_to_string(tm));

  // There's a comment somewhere saying this should be done:
  cleanupTmpDirs();
}

// copied from https://stackoverflow.com/a/21802936
static std::vector<uint8_t>
readFile(const char* filename)
{
  // open the file:
  std::ifstream file(filename, std::ios::binary);

  // Stop eating new lines in binary mode!!!
  file.unsetf(std::ios::skipws);

  // get its size:
  std::streampos fileSize;

  file.seekg(0, std::ios::end);
  fileSize = file.tellg();
  file.seekg(0, std::ios::beg);

  // reserve capacity
  std::vector<uint8_t> vec;
  vec.reserve(fileSize);

  // read the data:
  vec.insert(vec.begin(),
      std::istream_iterator<uint8_t>(file),
      std::istream_iterator<uint8_t>());

  return vec;
}

static Config
getConfig()
{
    Config cfg = getTestConfig(0);
    cfg.setNoListen();
    cfg.setInMemoryMode();
    cfg.setNoPublish();
    cfg.CATCHUP_COMPLETE = false;
    cfg.CATCHUP_RECENT = 0;
    cfg.ARTIFICIALLY_GENERATE_LOAD_FOR_TESTING = false;
    cfg.ARTIFICIALLY_SET_CLOSE_TIME_FOR_TESTING = UINT32_MAX;
    cfg.WORKER_THREADS = 1;
    cfg.QUORUM_INTERSECTION_CHECKER = false;
    cfg.PREFERRED_PEERS_ONLY = false;
    cfg.LEDGER_PROTOCOL_VERSION = 18;

    return cfg;
}
