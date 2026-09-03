#include "ckks_secure_aggregation.hpp"

#include <seal/seal.h>

#include <algorithm>
#include <cmath>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <utility>
#include <vector>

namespace zerotrust::fl::privacy {
namespace {

std::shared_ptr<seal::SEALContext> load_context(const std::string& serialized_parameters) {
    std::stringstream stream(serialized_parameters);
    seal::EncryptionParameters parameters;
    parameters.load(stream);
    auto context = std::make_shared<seal::SEALContext>(parameters);
    if (!context->parameters_set()) {
        throw std::invalid_argument("invalid CKKS encryption parameters");
    }
    return context;
}

template <typename T>
std::string save_object(const T& object) {
    std::stringstream stream;
    object.save(stream);
    return stream.str();
}

seal::PublicKey load_public_key(
    const seal::SEALContext& context,
    const std::string& serialized
) {
    seal::PublicKey key;
    std::stringstream stream(serialized);
    key.load(context, stream);
    return key;
}

seal::SecretKey load_secret_key(
    const seal::SEALContext& context,
    const std::string& serialized
) {
    seal::SecretKey key;
    std::stringstream stream(serialized);
    key.load(context, stream);
    return key;
}

seal::Ciphertext load_ciphertext(
    const seal::SEALContext& context,
    const std::string& serialized
) {
    seal::Ciphertext ciphertext;
    std::stringstream stream(serialized);
    ciphertext.load(context, stream);
    return ciphertext;
}

}  // namespace

CKKSKeyMaterial generate_ckks_key_material(
    std::size_t poly_modulus_degree,
    const std::vector<int>& coeff_modulus_bits,
    int scale_bits
) {
    if (poly_modulus_degree < 2048 || (poly_modulus_degree & (poly_modulus_degree - 1)) != 0) {
        throw std::invalid_argument("poly_modulus_degree must be a power of two >= 2048");
    }
    if (coeff_modulus_bits.size() < 2) {
        throw std::invalid_argument("at least two coefficient-modulus primes are required");
    }
    if (scale_bits <= 0 || scale_bits >= 60) {
        throw std::invalid_argument("scale_bits must be in (0, 60)");
    }

    seal::EncryptionParameters parameters(seal::scheme_type::ckks);
    parameters.set_poly_modulus_degree(poly_modulus_degree);
    parameters.set_coeff_modulus(
        seal::CoeffModulus::Create(poly_modulus_degree, coeff_modulus_bits)
    );

    seal::SEALContext context(parameters);
    if (!context.parameters_set()) {
        throw std::invalid_argument("SEAL rejected the requested CKKS parameter set");
    }

    seal::KeyGenerator key_generator(context);
    seal::SecretKey secret_key = key_generator.secret_key();
    seal::PublicKey public_key;
    key_generator.create_public_key(public_key);
    seal::CKKSEncoder encoder(context);

    return CKKSKeyMaterial{
        save_object(parameters),
        save_object(public_key),
        save_object(secret_key),
        encoder.slot_count(),
        scale_bits,
    };
}

std::vector<std::string> ckks_encrypt(
    const std::vector<double>& values,
    const std::string& parameters,
    const std::string& public_key,
    int scale_bits
) {
    if (values.empty()) {
        throw std::invalid_argument("at least one value is required for CKKS encryption");
    }
    if (scale_bits <= 0 || scale_bits >= 60) {
        throw std::invalid_argument("scale_bits must be in (0, 60)");
    }

    auto context = load_context(parameters);
    seal::PublicKey key = load_public_key(*context, public_key);
    seal::Encryptor encryptor(*context, key);
    seal::CKKSEncoder encoder(*context);
    const std::size_t slots = encoder.slot_count();
    const double scale = std::ldexp(1.0, scale_bits);

    std::vector<std::string> encrypted;
    encrypted.reserve((values.size() + slots - 1) / slots);
    for (std::size_t offset = 0; offset < values.size(); offset += slots) {
        const std::size_t length = std::min(slots, values.size() - offset);
        std::vector<double> chunk(values.begin() + static_cast<std::ptrdiff_t>(offset),
                                  values.begin() + static_cast<std::ptrdiff_t>(offset + length));
        seal::Plaintext plaintext;
        encoder.encode(chunk, scale, plaintext);
        seal::Ciphertext ciphertext;
        encryptor.encrypt(plaintext, ciphertext);
        encrypted.push_back(save_object(ciphertext));
    }
    return encrypted;
}

std::vector<std::string> ckks_add_ciphertext_sets(
    const std::vector<std::vector<std::string>>& encrypted_updates,
    const std::string& parameters
) {
    if (encrypted_updates.empty()) {
        throw std::invalid_argument("at least one encrypted update is required");
    }
    const std::size_t chunk_count = encrypted_updates.front().size();
    if (chunk_count == 0) {
        throw std::invalid_argument("encrypted updates must contain at least one chunk");
    }
    for (const auto& update : encrypted_updates) {
        if (update.size() != chunk_count) {
            throw std::invalid_argument("all encrypted updates must contain the same number of chunks");
        }
    }

    auto context = load_context(parameters);
    seal::Evaluator evaluator(*context);
    std::vector<std::string> result;
    result.reserve(chunk_count);

    for (std::size_t chunk_index = 0; chunk_index < chunk_count; ++chunk_index) {
        seal::Ciphertext aggregate = load_ciphertext(
            *context,
            encrypted_updates.front()[chunk_index]
        );
        for (std::size_t update_index = 1; update_index < encrypted_updates.size(); ++update_index) {
            seal::Ciphertext current = load_ciphertext(
                *context,
                encrypted_updates[update_index][chunk_index]
            );
            evaluator.add_inplace(aggregate, current);
        }
        result.push_back(save_object(aggregate));
    }
    return result;
}

std::vector<double> ckks_decrypt(
    const std::vector<std::string>& ciphertexts,
    const std::string& parameters,
    const std::string& secret_key,
    std::size_t original_size
) {
    if (ciphertexts.empty()) {
        throw std::invalid_argument("at least one ciphertext chunk is required");
    }
    if (original_size == 0) {
        throw std::invalid_argument("original_size must be positive");
    }

    auto context = load_context(parameters);
    seal::SecretKey key = load_secret_key(*context, secret_key);
    seal::Decryptor decryptor(*context, key);
    seal::CKKSEncoder encoder(*context);

    std::vector<double> decoded_values;
    decoded_values.reserve(original_size);
    for (const auto& serialized : ciphertexts) {
        seal::Ciphertext ciphertext = load_ciphertext(*context, serialized);
        seal::Plaintext plaintext;
        decryptor.decrypt(ciphertext, plaintext);
        std::vector<double> chunk;
        encoder.decode(plaintext, chunk);
        const std::size_t remaining = original_size - decoded_values.size();
        const std::size_t take = std::min(remaining, chunk.size());
        decoded_values.insert(decoded_values.end(), chunk.begin(), chunk.begin() + static_cast<std::ptrdiff_t>(take));
        if (decoded_values.size() == original_size) {
            break;
        }
    }
    if (decoded_values.size() != original_size) {
        throw std::runtime_error("decrypted CKKS payload is shorter than the declared original size");
    }
    return decoded_values;
}

}  // namespace zerotrust::fl::privacy
