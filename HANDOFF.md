# HANDOFF.md — what was happening, and the next 3 steps

Read this before continuing. Pair with STATUS.md (what works + proof) and
TODO.md (prioritized backlog).

## Last session (session 17) — what happened

THE WIZARD RUNS. The LuaForWindows (Inno Setup 5) installer under
winnux32 now: outer extracts → engine spawns → full wizard built (incl. the
TNewCheckListBox that raised since session 13) → paints under Xvfb →
settles into a real idle (0.9% CPU, 1-line log, zero stubs, zero
exceptions). Screenshot proof: download/wizard-luaforwindows-session17.png.

Three root causes fixed in sequence (all decode chains in session-17
STATUS.md):

1. **VCL CreateSubClass contract.** The "List item and state item count
   mismatch" raise: VCL's CreateSubClass(Params,'LISTBOX') installs the
   lpfnWndProc returned by GetClassInfo(HInstance,'LISTBOX') as the class
   proc of its superclassed control class — ours returned NULL, so VCL
   registered 'TNewCheckListBox' with its own proc and NO window had
   listbox semantics (LB_ messages died inside VCL, Items.Count stayed 0
   while FStateList grew). Fix: builtin_control_class() now exposes
   proc32 = (uint32_t)ctl_proc on the native i386 build — GetClassInfo,
   GetWindowLong(GWL_WNDPROC) (FDefWndProc) and CallWindowProc all route
   to it (the i386 bridge is a plain stdcall indirect call).
2. **POINT-by-value stdcall ABI.** The WindowFromPoint stub popped 4 bytes
   for an 8-byte by-value POINT → 4-byte frame leak → the wizard's hover
   logic returned to dead stack. Fixed by implementing WindowFromPoint /
   PtInRect / SetRect / SetRectEmpty for real (per-arch signatures; stub
   widths WindowFromPoint 1→2, PtInRect 2→3).
3. **WaitMessage.** Delphi's TApplication.Idle spins on a returning-0
   WaitMessage stub (101k calls/min, 100% CPU). Now blocks on the same
   wake sources as GetMessage without consuming.

Plus: software raises now carry REAL guest registers (naked pusha gate on
kernel32!RaiseException, i386-only), an EBP frame probe (VMT class names
of frame locals — Self identification), the Inno checklistbox field
probes, and an i386 EBP-chain backtrace in crash reports. Proof:
scripts/dev/raise32.c under run32.sh round-trips six distinct register
constants.

Also: the dev environment was rebuilt from scratch after another sandbox
reset — ONE idempotent script now rebuilds the entire 32-bit loop
(scripts/setup_root32.sh: i386 libc + linux-libc-dev + lib32gcc + qemu-user
+ the i386 X11/freetype runtime + "=" ld-script patching; Makefile sysroot
mode gained --sysroot via scripts/fix_m32_sysroot.py; i686 mingw installed
into toolchain/root for 32-bit guest probes). The installer re-download:
GitHub rjpcomputing/luaforwindows release v5.1.5-52 (SourceForge blocks).

Gates: 19/19 tests (new t19_rect_wfp_wait), sigs32 788 exports, both
runtimes green.

## The next 3 steps

1. **Drive the wizard through the install.** Synthetic clicks (the
   scripts/dev xtree click mode from session 6): Welcome → Next → license
   radio → components checks (the checklistbox state model: LB_GETITEMDATA
   / SetChecked → WM_ to the VCL proc → DrawItem ownerdraw) → directory
   page → Install. Each page turn will surface the next contract gap;
   the self-describing crash reports (registers + frame probe) make field
   triage nearly instant now.
2. **Run the /S silent path** — it should now pass the checklistbox
   construction that killed it since session 12; harvest whatever raise
   comes next (expect the file-copy + registry phase: the real test of
   GlobalAlloc/Moveable, file writes, and the uninstall key tree).
3. **Close the loop: lua.exe.** Files in drive_c/Program Files/Lua/5.1,
   registry keys, then `winnux32 run .../lua.exe -e "print(1+2*3,
   ('win'):upper())"` — the original milestone-1-class proof on a REAL
   installed application.
