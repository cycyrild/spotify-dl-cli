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
    parser.add_argument("-traceOutput", dest="traceOutput", required=False)
    args = parser.parse_args()

    trace_file = open(args.traceOutput, "w") if args.traceOutput else None

    derived_key: bytes | None = None
    playplay_context: PlayPlayCtx | None = None

    pe = pefile.PE(EXE_PATH)

    emu = KeyEmu(
        pe, trace_file=trace_file, enable_callstack_hook=trace_file is not None
    )
    try:
        derived_key = emu.getDerivedKey(
            bytes.fromhex(args.obfuscated_hex), bytes.fromhex(args.content_id_hex)
        )
        playplay_context = emu.playplayInitializeWithKey(derived_key, trace_file)
    except UcError as e:
        print(f"CRASH: {e} | EIP: 0x{emu.unicorn.reg_read(UC_X86_REG_EIP):08X}\n")
        emu.dump_shadow_callstack()
    finally:
        if trace_file:
            trace_file.close()

    if derived_key:
        print(f"Derived Key: {derived_key.hex()}")

    if playplay_context:
        with open("playplay_ctx.bin", "wb") as f:
            f.write(playplay_context.to_bytes())

    
