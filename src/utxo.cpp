#include "utxo.h"
#include "ed25519.h"
#include "corehash.h"
#include "params.h"
#include <set>
#include <cstring>

uint64_t UTXOSet::balance_of(const std::vector<uint8_t>& pubkey_hash) const {
    uint64_t sum = 0;
    for (const auto& kv : map)
        if (kv.second.pubkey_hash == pubkey_hash) sum += kv.second.amount;
    return sum;
}

bool check_tx(const Transaction& tx, const UTXOSet& view, uint64_t spend_height,
              uint64_t& fee, std::string& err) {
    if (tx.is_coinbase()) { err = "check_tx called on coinbase"; return false; }
    if (tx.vin.empty())   { err = "no inputs";  return false; }
    if (tx.vout.empty())  { err = "no outputs"; return false; }
    { Writer wsz; tx.serialize(wsz); if (wsz.data.size() > consensus::MAX_TX_SIZE) { err = "transaction too large"; return false; } }

    uint256 sh = tx.sighash();
    std::set<OutPoint> seen;
    uint64_t sum_in = 0;
    for (const auto& in : tx.vin) {
        if (!seen.insert(in.prev).second) { err = "duplicate input in tx"; return false; }
        const UTXOEntry* u = view.find(in.prev);
        if (!u) { err = "input not found or already spent"; return false; }
        if (u->is_coinbase && spend_height < u->height + g_params.coinbase_maturity) {
            err = "immature coinbase spend"; return false;
        }
        // Unlocking data = signature(64) || pubkey(32). The pubkey must hash to the
        // output's locking pubkey_hash, and the signature must cover the sighash.
        if (in.sig.size() != 96) { err = "malformed unlocking script"; return false; }
        const uint8_t* sig = in.sig.data();
        const uint8_t* pk  = in.sig.data() + 64;
        uint8_t pkh[32]; ch::blake2b(pkh, 32, pk, 32);
        if (u->pubkey_hash.size() != 32 || memcmp(pkh, u->pubkey_hash.data(), 32) != 0) {
            err = "pubkey does not match output address"; return false;
        }
        if (!ed::verify(sig, pk, sh.b.data(), 32)) { err = "bad signature"; return false; }
        sum_in += u->amount;
        if (sum_in > consensus::MAX_MONEY) { err = "input sum overflow"; return false; }
    }

    uint64_t sum_out = 0;
    for (const auto& o : tx.vout) {
        if (o.amount == 0)                    { err = "zero-value output"; return false; }
        if (o.amount > consensus::MAX_MONEY)  { err = "output over MAX_MONEY"; return false; }
        sum_out += o.amount;
        if (sum_out > consensus::MAX_MONEY)   { err = "output sum overflow"; return false; }
    }

    if (sum_in < sum_out) { err = "inputs less than outputs"; return false; }
    fee = sum_in - sum_out;
    return true;
}

void apply_tx(UTXOSet& view, const Transaction& tx, uint64_t height) {
    if (!tx.is_coinbase())
        for (const auto& in : tx.vin) view.remove(in.prev);
    uint256 id = tx.txid();
    for (uint32_t i = 0; i < tx.vout.size(); i++) {
        OutPoint op{ id, i };
        view.add(op, UTXOEntry{ tx.vout[i].amount, tx.vout[i].pubkey_hash, height, tx.is_coinbase() });
    }
}
