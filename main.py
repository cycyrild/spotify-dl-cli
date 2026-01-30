import argparse
import pefile
from unicorn.unicorn import UcError
from playplay_emulator import PlayPlayCtx
from playplay_emulator.emulator import EXE_PATH, KeyEmu
from unicorn.x86_const import UC_X86_REG_EIP

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-obfuscatedKey", dest="obfuscated_hex", required=True)
    parser.add_argument("-contentId", dest="content_id_hex", required=True)
    parser.add_argument("-traceOutput", dest="trace_output", required=False)
    args = parser.parse_args()

    trace_file = (
        open(args.trace_output, "a", newline="\n") if args.trace_output else None
    )

    derived_key: bytes | None = None
    keystream: bytes | None = None

    pe = pefile.PE(EXE_PATH)

    emu = KeyEmu(pe)
    try:
        derived_key = emu.getDerivedKey(
            bytes.fromhex(args.obfuscated_hex),
            bytes.fromhex(args.content_id_hex),
            trace_file=None,
        )
        state, setup_value = emu.initializeWithKey(
            derived_key,
            trace_file=None,
        )

        state = emu.seek_state_to_block(state, 0, trace_file=None)

        state, keystream = emu.generateKeystream(
            state,
            trace_file=None,
        )
    except UcError as e:
        print(f"CRASH: {e} | EIP: 0x{emu.unicorn.reg_read(UC_X86_REG_EIP):08X}\n")
    finally:
        if trace_file:
            trace_file.close()

    if derived_key:
        print(f"Derived Key: {derived_key.hex()}")
    if keystream is not None:
        print(f"Keystream: {keystream.hex()}")
