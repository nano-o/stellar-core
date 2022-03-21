%#include "xdr/Stellar-ledger.h"
%#include "xdr/Stellar-ledger-entries.h"
%#include "xdr/Stellar-transaction.h"

namespace stellar
{

struct TestCase
{
  LedgerHeader ledgerHeader;
  LedgerEntry ledgerEntries<>;
  TransactionEnvelope transactionEnvelopes<>;
};

struct TestCaseResult
{
  TransactionResult transactionResults<>;
  LedgerEntryChange ledgerChanges<>;
};

}
