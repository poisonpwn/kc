from random import randint, choices
from pathlib import Path
from string import ascii_letters, digits
from linecache import getline
from sys import stderr
from typing import Union


class PassGen:
    def __init__(self):
        print(PassGen.xkcd())

    # static method can't be used normally
    # here because this function is monkey patched
    def xkcd(
        *,
        no_of_words: int = 5,
        include_size: bool = True,
        delim: str = "-",
        word_len_range: Union[range, int] = range(4, 10),  # this can also be an int
    ) -> str:
        word_list = []
        word_len_sum = 0

        if isinstance(word_len_range, int):
            word_pass_predicate = lambda word_len: word_len == word_len_range
        elif isinstance(word_len_range, range):
            word_pass_predicate = lambda word_len: word_len in word_len_range
        else:
            stderr.write("invalid word len qualifier!")

        while len(word_list) < no_of_words:
            word = getline(
                str(PassGen.xkcd.WORDLIST_FILE),
                randint(*PassGen.xkcd.LINE_RANGE),
            ).strip()
            if word_pass_predicate(word_len := len(word)):
                word_len_sum += word_len
                word_list.append(word)

        if include_size:
            word_list.append(
                # take into account delimeters when doing len calulation
                str(word_len_sum + no_of_words - 1)
                # * NOTE: the last delimeter before the length number is not counted in length
            )
        return delim.join(word_list)

    xkcd.WORDLIST_DIR = Path(__file__).parents[2]
    xkcd.WORDLIST_FILE = (xkcd.WORDLIST_DIR / "wordlist.txt").absolute()
    xkcd.LINE_RANGE = (4, 7700)
    xkcd = staticmethod(xkcd)

    @staticmethod
    def random(size: int = 20, with_numbers: bool = False) -> str:
        domain = ascii_letters
        if with_numbers:
            domain = domain + digits
        return "".join(choices(domain, k=size))


if __name__ == "__main__":
    PassGen()