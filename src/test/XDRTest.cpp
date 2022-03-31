#include "database/Database.h"
#include "ledger/LedgerManager.h"
#include "ledger/LedgerTxn.h"
#include "ledger/LedgerTxnEntry.h"
#include "ledger/LedgerTxnHeader.h"
#include "lib/catch.hpp"
#include "main/Application.h"
#include "main/Config.h"
#include "test/TestAccount.h"
#include "test/TestExceptions.h"
#include "test/TestMarket.h"
#include "test/TestUtils.h"
#include "test/TxTests.h"
#include "test/test.h"
#include "util/Logging.h"
#include "util/Timer.h"
#include "ledger/LedgerManagerImpl.h"
#include "bucket/BucketManager.h"
#include "transactions/TransactionFrameBase.h"

#include "xdr/TestCase.h"

using namespace stellar;
using namespace stellar::txtest;

// copied from https://stackoverflow.com/a/21802936
std::vector<uint8_t> readFile(const char* filename)
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

bool
isValid(LedgerHeader const& lh)
{
    bool res = (lh.ledgerSeq <= INT32_MAX);

    res = res && (lh.scpValue.closeTime <= INT64_MAX);
    res = res && (lh.feePool >= 0);
    res = res && (lh.idPool <= INT64_MAX);
    return res;
}

TEST_CASE("XDRTest", "TODO: what is this string for?")
{
    Config cfg = getTestConfig();
    cfg.USE_CONFIG_FOR_GENESIS = false; // see how it's used in LedgerManagerImpl::startNewLedger
    cfg.LEDGER_PROTOCOL_VERSION = 18;

    std::ifstream mIn;
    const std::string filename = "/home/user/test-case.bin";

    std::vector<uint8_t> data = readFile(filename.c_str());
    TestCase tc;

    xdr::xdr_get g(&data.front(), &data.back() + 1);
    xdr::xdr_argpack_archive(g, tc);
    g.done();

    if (!isValid(tc.ledgerHeader))
    {
        throw std::runtime_error("invalid ledger header (load)");
    }

    VirtualClock clock;
    auto app = createTestApplication(clock, cfg);

    LedgerTxn ltx(app->getLedgerTxnRoot(), false);
    ltx.loadHeader().current() = tc.ledgerHeader;
    LedgerEntry rootEntry = tc.ledgerEntries.front();
    ltx.create(rootEntry);

    TransactionEnvelope txe = tc.transactionEnvelopes.front();
    TransactionFrameBasePtr tx =
      TransactionFrameBase::makeTransactionFromWire(app->getNetworkID(),
          txe);

    REQUIRE(tx->checkValid(ltx, 0, 0, 0));

    TransactionMeta tm(2); // is this v2?
    tx->apply(*app, ltx, tm);
    ltx.commit();
}
