// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/block.h>

#include <chainparams.h>
#include <consensus/params.h>
#include <crypto/ripemd160.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <streams.h>
#include <tinyformat.h>

#include <cassert>

uint256 CBlockHeader::GetHash(const Consensus::Params& consensusParams) const
{
    const HashAlgorithm algo = consensusParams.PowAlgorithmForTime(nTime);
    if (algo == HashAlgorithm::SHA256d) {
        // Historical algorithm and common case.
        return (HashWriter{} << *this).GetHash();
    }

    DataStream ss;
    ss << *this;
    const auto* const pbegin = reinterpret_cast<const unsigned char*>(ss.data());
    const size_t len = ss.size();

    // For the 160-bit algorithms the result is right-padded with zeroes, so
    // start from a zeroed value and only write the low bytes.
    uint256 hash;
    switch (algo) {
    case HashAlgorithm::SHA256:
        CSHA256().Write(pbegin, len).Finalize(hash.begin());
        break;
    case HashAlgorithm::RIPEMD160:
        CRIPEMD160().Write(pbegin, len).Finalize(hash.begin());
        break;
    case HashAlgorithm::HASH160:
        CHash160().Write({pbegin, len}).Finalize({hash.begin(), CHash160::OUTPUT_SIZE});
        break;
    case HashAlgorithm::SHA256d: // handled above
        assert(false);
    }

    return hash;
}

uint256 CBlockHeader::GetHash() const
{
    return GetHash(Params().GetConsensus());
}

std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, ver=0x%08x, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, vtx=%u)\n",
        GetHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nTime, nBits, nNonce,
        vtx.size());
    for (const auto& tx : vtx) {
        s << "  " << tx->ToString() << "\n";
    }
    return s.str();
}
