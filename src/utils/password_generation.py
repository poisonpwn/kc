from random import randint, randrange, choices
from pathlib import Path
from linecache import getline
from sys import stderr
from string import ascii_letters, ascii_lowercase, digits
from typing import Union, Optional


class PassGen:
    def __init__(self):
        print(PassGen.xkcd())

    # static method can't be used normally
    # here because this function is monkey patched
    def xkcd(
        no_of_words: int = 5,
        delim: str = "-",
        include_size: bool = True,
        service_name: Optional[str] = None,
        should_capitalize_words: bool = False,
        word_len_range: Union[range, int] = range(4, 10),
    ) -> str:
        """
        returns an xkcd style passphrase
        like in https://xkcd.com/936/

        :param no_of_words: no of words to in the password
        :param include_size: whether to append the length of the password
        :param delim: the delimeter to join the words in the password
        :param word_len_range: the length of the word should be within this range
        to be included, or pass an int for word to be exact length
        :param service_name: use the service name as the first word
        """
        word_list = []
        if service_name is not None:
            word_list.append(service_name)

        if isinstance(word_len_range, int):
            word_pass_predicate = word_len_range.__eq__
        elif isinstance(word_len_range, range):
            word_pass_predicate = word_len_range.__contains__
        else:
            raise TypeError(
                "Invalid Type for word_len_range"
                f"expected range or int, got {type(word_len_range)}"
            )

        word_len_sum = 0
        while len(word_list) < no_of_words:
            word = getline(
                str(PassGen.xkcd.WORDLIST_FILE),
                randint(*PassGen.xkcd.LINE_RANGE),
            ).strip()
            if word_pass_predicate(word_len := len(word)):
                word_len_sum += word_len
                word_list.append(word)

        if should_capitalize_words:
            word_list = [word.capitalize() for word in word_list]

        if include_size:
            word_list.append(
                # add `no_of_words - 1` to take delimeters into account
                # when doing len calulation
                str(word_len_sum + no_of_words - 1)
                # * NOTE: the last delimeter before the length number is not counted in length
            )
        return delim.join(word_list)

    xkcd.WORDLIST_DIR = Path(__file__).parents[2]
    xkcd.WORDLIST_FILE = (xkcd.WORDLIST_DIR / "wordlist.txt").absolute()
    xkcd.LINE_RANGE = (4, 7700)
    xkcd = staticmethod(xkcd)

    @staticmethod
    def random_chars(
        size: int = 20,
        digit_count: int = 3,
        include_uppercase: bool = True,
        special_char_count: int = 3,
    ) -> str:
        """
        return a passphrase which consists of random characters

        :param size:               the length of the password
        :param digit_count:        no of digits to include in the password
        :param include_upperase:   whether to include uppercase letters in passwor
        :param special_char_count: no of special characters to include in the password
        """

        if (digit_count + special_char_count) > size:
            stderr.write(
                "no of numbers and special charectars"
                "can't be more than length of password itself!\n"
            )
            exit()

        letter_options = ascii_letters if include_uppercase else ascii_lowercase
        passwd_char_list = choices(
            letter_options, k=size - (digit_count + special_char_count)
        )
        numbers_list = choices(digits, k=digit_count)
        special_char_list = choices(r"&$%#@!*=+-\,.;:/?", k=special_char_count)

        for char in numbers_list + special_char_list:
            index = randrange(len(passwd_char_list))
            passwd_char_list.insert(index, char)

        return "".join(passwd_char_list)


if __name__ == "__main__":
    PassGen()