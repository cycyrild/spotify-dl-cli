from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent


class PATHS:
    GENERATED_DIR = PACKAGE_DIR / "generated"
    RUNTIME_FUNCTIONS_JSON = GENERATED_DIR / "runtimefunction.json"
    THROW_INFOS_JSON = GENERATED_DIR / "throwinfo.json"


class MEM:
    PAGE_SIZE = 0x1000

    STACK_ADDR = 0x1000000
    STACK_SIZE = 0x200000

    HEAP_ADDR = 0x2000000
    HEAP_SIZE = 0x200000

    TEB_ADDR = 0x3000000

    EXIT_ADDR = 0x4000000


class ANALYSIS:
    BASE = 0x0000000180000000


class RT_FUNCTIONS:
    VM_RUNTIME_INIT_VA = 0x00000001802DFFF0
    VM_OBJECT_TRANSFORM_VA = 0x00000001802E1E28
    CXX_THROW_EXCEPTION_VA = 0x0000000181537078


class RT_DATA:
    RUNTIME_CONTEXT_VA = 0x0000000181649FC0


class AES_KEY_HOOK:
    TRIGGER_RAX = 0
    TRIGGER_RBX = 0x00000000011FFF80
    TRIGGER_RIP = 0x0000000181E21BE6


class PLAYPLAY_TOKEN:
    VA = 0x000000018164C240
    SIZE = 16


class RT_HOOKS:
    MTX_LOCK_VA = 0x000000018151B660
    CND_WAIT_VA = 0x000000018151C804
    MTX_UNLOCK_VA = 0x000000018151B68C
    MALLOC_VA = 0x0000000181546CC0


class EMULATOR_SIZES:
    VM_OBJECT = 144
    DERIVED_KEY = 24
    OBFUSCATED_KEY = 16
    CONTENT_ID = 16
    KEY = 16


class AUDIO_AES:
    KEY_SIZE_BITS = 128
    IV = int.from_bytes(
        [
            0x72,
            0xE0,
            0x67,
            0xFB,
            0xDD,
            0xCB,
            0xCF,
            0x77,
            0xEB,
            0xE8,
            0xBC,
            0x64,
            0x3F,
            0x63,
            0x0D,
            0x93,
        ],
        byteorder="big",
    )
