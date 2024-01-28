import base64
import hashlib
import sys
import bcrypt
import random
from timeit import default_timer as timer

RANDOM_STRING_BIT_LEN = 64

def main():
    if len(sys.argv) != 2:
        print("Usage: ./sha256_collision.py input.txt")
        return
    
    try:
        input_file = open(sys.argv[1], "rb")
    except Exception as e:
        print(f"An error occured: {e}")

    try:
        output_file = open("output.txt", "w")
    except Exception as e:
        print(f"An error occured: {e}")

    # # Hashing two random strings with Hamming Distance of 1 bit and printing result
    # # For Task 1b of assignment 4
    # # Generate random strings
    # sysrandom = random.SystemRandom()
    # random_string_1 = sysrandom.getrandbits(RANDOM_STRING_BIT_LEN)
    # print('string 1: {:016x}'.format(random_string_1))
    # random_string_2 = random_string_1 ^ (1 << sysrandom.randint(0, RANDOM_STRING_BIT_LEN))
    # print('string 2: {:016x}'.format(random_string_2))

    # digest_1 = SHA256_hash(random_string_1.to_bytes(8, 'big'))
    # salt_1 = digest_1[0:29]
    # hash_1 = digest_1[29:]

    # digest_2 = SHA256_hash(random_string_1.to_bytes(8, 'big'))
    # salt_2 = digest_2[0:29]
    # hash_2 = digest_2[29:]

    # print('hash 1: ' + str(hash_1))
    # print('hash 2: ' + str(hash_2))

    # Collision Finding for Task 1c of assignment 4
    num_bits = 10
    digest_dict = {}
    start_time = timer()
    matching_string_1 = ""
    matching_string_2 = ""
    matching_digest = ""
    while True:
        # Generate random strings
        sysrandom = random.SystemRandom()
        random_string_1 = sysrandom.getrandbits(RANDOM_STRING_BIT_LEN)
        random_string_2 = sysrandom.getrandbits(RANDOM_STRING_BIT_LEN)
        # Generate Digests
        digest_1 = SHA256_hash_truncated(random_string_1.to_bytes(8, 'big'), num_bits)
        digest_2 = SHA256_hash_truncated(random_string_2.to_bytes(8, 'big'), num_bits)
        # Check Equality
        if digest_1 == digest_2:
            matching_string_1 = random_string_1
            matching_string_2 = random_string_2
            matching_digest = digest_1
            break
        # Check if resulted key in digest_dict {Key: Value} = {Digest, String}
        if digest_1 in digest_dict:
            matching_string_1 = digest_dict[digest_1]
            matching_string_2 = random_string_1
            matching_digest = digest_1
            break
        if digest_2 in digest_dict:
            matching_string_1 = digest_dict[digest_2]
            matching_string_2 = random_string_2
            matching_digest = digest_2
            break
        # No matches, put keys in digest_dictionary and continue
        digest_dict[digest_1] = random_string_1
        digest_dict[digest_2] = random_string_2

    end_time = timer()
    print(f"Collision Found for {num_bits} bits, time elapsed: {end_time - start_time}")
    print(f"Colliding Digest: {matching_digest}")
    print('String 1: {:016x}'.format(matching_string_1))
    print('String 2: {:016x}'.format(matching_string_2))


    return

# Hashes the input using SHA256 and returns digest (salt and hash)
def SHA256_hash(input):
    salt = bcrypt.gensalt()
    hash = bcrypt.hashpw(
        base64.b64encode(hashlib.sha256(input).digest()),
        salt
    )
    return hash

# Hashes the input using SHA256 and returns string representation of first num_bits of digest
def SHA256_hash_truncated(input, num_bits):
    bit_hash = ""
    total_bits = 0
    salt = bcrypt.gensalt()
    hash = bcrypt.hashpw(
        base64.b64encode(hashlib.sha256(input).digest()),
        salt
    )
    hash = hash[29:]
    for byte in hash:
        # get bytes of hash and remove the 0b 
        binary_byte = bin(byte)[2:]
        # pad the byte to 8 bits
        padded_binary_byte = binary_byte.zfill(8)
        if total_bits >= num_bits:
            break
        else:
            bit_hash += padded_binary_byte
            total_bits += len(padded_binary_byte)
    # Trim bit_hash to represent first n bits
    bit_hash = bit_hash[:num_bits]
    return bit_hash


if __name__ == "__main__":
    main()