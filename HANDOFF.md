
# HANDOFF.md — session 20 addendum

## What changed (2026-10-21)
- Close/exit flow: REAL modal MessageBox engine (user32.c, msgbox_*)
  + WM_SYSCOMMAND(SC_CLOSE) chain from X11 WM_DELETE_WINDOW. E2E: the
  Inno "Exit Setup?" box appears, synthetic Yes -> IDYES -> clean exit
  (rc=2). WINNUX_MSGBOX_AUTO answers the default button headlessly
  (t22 pins return values incl. MessageBoxIndirectA/W).
- Text baseline: gen_font.py renders the atlas on ONE baseline row
  (WN_FONT_BASELINE=12; self-checks H==x bottoms, uniform descenders);
  SetTextAlign/GetTextAlign + TA math in TextOut/ExtTextOut (new,
  was a stub); GetPixel real; GetTextMetrics ascent from the same row;
  t21_baseline (.gui, .env WINNUX_NO_FT=1 for the atlas path).
- Scrollbars: per-window sb_* fields + full API set + SBM_ + paint
  (real controls + WS_VSCROLL/HSCROLL adornments) + hit-test input +
  wheel + EM_LINESCROLL/EM_SCROLL/EM_GETFIRSTVISIBLELINE. t23 pins.
  Watch: WM_VSCROLL=0x115, WM_HSCROLL=0x0114 (do not swap again).
  The adornment must paint BEFORE g32_ReleaseDC (it silently no-ops
  with the released handle — cost an hour).
- ctl_priv is now TAGGED (CTL_PRIV_TV/MSGBOX): DestroyWindow dispatches;
  the msgbox ctx is freed by the box's own DestroyWindow. Never add an
  untagged payload.
- Input/state: GetKeyState/GetAsyncKeyState/GetWindowThreadProcessId/
  EnumWindows/EnumThreadWindows/WM_MOUSEWHEEL(ETO...)/GetKeyboardType
  real; WN_BEV_KEYMODS reconciles X11 modifiers; stub logging dedupes
  per (dll,api,caller) with an atexit summary (wn_stub_site_note).
- Build: Makefile M32LDFLAGS embeds the sysroot loader when the host
  lacks /lib/ld-linux.so.2. scripts/bootstrap_root32.sh rebuilds the
  whole i386 sysroot from debs (libc6-i386, libc6-dev-i386,
  lib32gcc-14-dev + i386 libX11/libxcb/libXau/libXdmcp from the trixie
  Packages index) INCLUDING the ld-script rewrite. qemu-user debs go to
  toolchain/qemu. run32.sh contract unchanged.

## Open leads for next session
1. WIZARD DIR PAGE: the click-through freezes at the directory page
   (components advanced after clicking a checklist row first). Debug
   trace recipe:
     sh scripts/e2e_clickthrough_A2.sh   (full run, WINNUX_LOG=debug)
   The dir Next click DISPATCHES (log shows WM_LBUTTONUP at the button)
   but Inno never switches pages; no error box, log quiet afterwards.
   Suspects: ExistsDir/GetFileAttributes on "C:\Program Files (x86)\Lua\5.1",
   or the components-state re-read making Inno loop.
2. wow64 ENGINE crash (session-11 carryover): write to RO at
   luaforwindows tmp+0x1bb7 addr 0x40a998 under WINNUX_WOW64=1. The
   wizard only runs via winnux32 (qemu here) — keep it that way until
   root-caused.
3. Components page: Next only advanced AFTER a synthetic click INSIDE
   the checklist. Check LB_GETITEMDATA/LB_GETSEL answers for VCL's
   TNewCheckListBox state objects.

## How to run the wizard E2E (this sandbox)
    sh /home/z/my-project/scripts/e2e_final.sh       # close-flow: box + Yes + clean rc=2
    sh /home/z/my-project/scripts/e2e_clickthrough_A2.sh  # page-walk + freeze repro
Xvfb :95 + xtree (built at /tmp/xtree; sources scripts/dev/xtree.c) +
qemu-i386 from toolchain/qemu. ALL of it must run in ONE bash call —
the sandbox reaps background processes between invocations.


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
