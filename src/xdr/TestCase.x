%#include "xdr/Stellar-ledger.h"
%#include "xdr/Stellar-ledger-entries.h"
%#include "xdr/Stellar-transaction.h"

namespace stellar
{

struct TestLedger
{
  LedgerHeader ledgerHeader;
  LedgerEntry ledgerEntries<>;
};

struct TestCaseResult
{
  TransactionResult transactionResults<>;
  LedgerEntryChange ledgerChanges<>;
};

}
