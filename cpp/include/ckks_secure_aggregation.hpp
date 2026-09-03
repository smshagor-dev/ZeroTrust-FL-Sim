#pragma once

#include <cstddef>
#include <string>
#include <vector>

namespace zerotrust::fl::privacy {

struct CKKSKeyMaterial {
    std::string parameters;
    std::string public_key;
    std::string secret_key;
    std::size_t slot_count;
    int scale_bits;
};

CKKSKeyMaterial generate_ckks_key_material(
    std::size_t poly_modulus_degree,
    const std::vector<int>& coeff_modulus_bits,
    int scale_bits
);

std::vector<std::string> ckks_encrypt(
    const std::vector<double>& values,
    const std::string& parameters,
    const std::string& public_key,
    int scale_bits
);

std::vector<std::string> ckks_add_ciphertext_sets(
    const std::vector<std::vector<std::string>>& encrypted_updates,
    const std::string& parameters
);

std::vector<double> ckks_decrypt(
    const std::vector<std::string>& ciphertexts,
    const std::string& parameters,
    const std::string& secret_key,
    std::size_t original_size
);

}  // namespace zerotrust::fl::privacy
