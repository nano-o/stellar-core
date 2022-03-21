// Copyright 2018 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "main/Application.h"
#include "main/Config.h"
#include "util/Timer.h"
#include "xdrpp/marshal.h"
#include "xdr/TestCase.h"
#include "test/ModelBasedTesting.h"

using namespace stellar;

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

static bool isValid(LedgerHeader const& lh)
{
  bool res = (lh.ledgerSeq <= INT32_MAX);

  res = res && (lh.scpValue.closeTime <= INT64_MAX);
  res = res && (lh.feePool >= 0);
  res = res && (lh.idPool <= INT64_MAX);
  return res;
}

void
ModelBasedTesting::runModelBasedTest(Config cfg, std::string const& xdrFile)
{
  // Config cfg = getTestConfig(); // TODO: what does this do?
  cfg.USE_CONFIG_FOR_GENESIS = false; // see how it's used in LedgerManagerImpl::startNewLedger
  cfg.LEDGER_PROTOCOL_VERSION = 18;

  std::ifstream mIn;

  std::vector<uint8_t> data = readFile(xdrFile.c_str());
  TestCase tc;

  xdr::xdr_get g(&data.front(), &data.back() + 1);
  xdr::xdr_argpack_archive(g, tc);
  g.done();

  if (!isValid(tc.ledgerHeader))
  {
    throw std::runtime_error("invalid ledger header (load)");
  }

  VirtualClock clock;
  cfg.setNoListen();
  Application::pointer app = Application::create(clock, cfg, false);
  app->start();
}
