class PostInit(type):
    def __call__(cls, *args, **kwargs):
        try:
            return type.__call__(cls, *args, **kwargs).__post_init__()
        except AttributeError:
            print(
                f"class {cls.__name__} needs to have "
                "__post_init__ attribute defined."
            )
            raise
