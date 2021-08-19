from class_utils import PostInit
from random import randint, choices
from string import ascii_letters, digits
from linecache import getline


class PassGen:
    def __init__(self):
        print(PassGen.xkcd())

    # static method can't be used normally
    # here because this function is monkey patched
    def xkcd(no_of_words: int = 5, include_size: bool = True, delim: str = "-") -> str:
        word_list = []
        word_len_sum = 0
        while len(word_list) < no_of_words:
            word = getline(
                PassGen.xkcd.WORDLIST_FILE, randint(*PassGen.xkcd.LINE_RANGE)
            ).strip()

            if (word_len := len(word)) in PassGen.xkcd.WORD_LEN_RANGE:
                word_len_sum += word_len
                word_list.append(word)
        if include_size:
            word_list.append(
                # take into account delimeters when doing len calulation
                str(word_len_sum + no_of_words - 1)
                # * NOTE: the last delimeter before the length number is not counted in length
            )
        return delim.join(word_list)

    xkcd.WORDLIST_FILE = "wordlist.txt"
    xkcd.LINE_RANGE = (0, 3000)
    xkcd.WORD_LEN_RANGE = range(4, 10)
    xkcd = staticmethod(xkcd)

    @staticmethod
    def random(size: int = 20, with_numbers: bool = False) -> str:
        domain = ascii_letters
        if with_numbers:
            domain = domain + digits
        return "".join(choices(domain, k=size))