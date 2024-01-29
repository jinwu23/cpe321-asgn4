import sys
import bcrypt
from nltk.corpus import words
from timeit import default_timer as timer

def main():
    if len(sys.argv) != 2:
        print("Usage Error: hash_break.py passwords.txt")
        return

    potential_words = [word for word in words.words() if 6 <= len(word) <= 10]

    password_file = open(sys.argv[1], "r")
    password_lines = password_file.readlines()
    
    for line in password_lines:
        user = line.split(':')[0]
        salt = line.split(':')[1][:29]
        hash = line.split(':')[1][29:60]
        salt_and_hash = line.split(':')[1][:60]
        running_total_words = 0
        start_time = timer()
        for word in potential_words:
            running_total_words += 1
            hashed_value = bcrypt.hashpw(word.encode('utf-8'), salt.encode('utf-8')).decode("utf-8")
            if hashed_value == salt_and_hash:
                end_time = timer()
                print(f"Password found for user({user}): {word}, time elapsed: {end_time - start_time}")
                break
            if running_total_words % 1000 == 0:
                print(f"Running Total Words: {running_total_words}")

    return

if __name__ == "__main__":
    main()