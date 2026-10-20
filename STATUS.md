
## Date: 2026-10-20 (session 17: THE WIZARD RUNS — VCL superclass contract, POINT-by-value ABI, WaitMessage idle, real raise registers)

### Milestone
`./bin/winnux run LuaForWindows_v5.1.5-52.exe` on the dev box (winnux32 under
qemu+Xvfb, WINNUX_KEEP_TEMP): the outer extractor spawns the Inno engine, the
engine builds the full wizard (TApplication → TWizardForm 579x360 → notebooks,
pages, TEdit, TRichEditViewer, TNewComboBox, **TNewCheckListBox alive with
items**), paints it (353k lit pixels, ~99k text/line pixels, exact Inno 5.x
window geometry), and settles into a proper idle — **0.9% CPU**, zero
stub hits, zero exceptions, 1-line log (the known benign dead-hwnd note).
Screenshot: download/wizard-luaforwindows-session17.png. 19/19 tests.

### The TNewCheckListBox raise, root-caused: VCL's CreateSubClass contract
AddItem2's `Items.Count <> FStateList.Count` sanity check (the decoded
"List item and state item count mismatch") fired because the checklistbox
had NO listbox semantics: zero LB_ messages ever reached our builtin
ctl_proc. Chain (from Inno's own NewCheckListBox.pas + the engine's
disassembly of the check at engine+0x44e058):
1. VCL's `CreateSubClass(Params, 'LISTBOX')` calls
   `GetClassInfo(HInstance, 'LISTBOX')` and installs the returned
   lpfnWndProc as the class proc of the control's superclassed class —
   that proc IS the listbox. Ours reported success but lpfnWndProc = NULL
   (builtin classes only had a host ctl_proc, never a guest-callable one).
2. VCL then registered 'TNewCheckListBox' with its OWN proc; every
   SendMessage routed to the guest VCL proc; FDefWndProc (GetWindowLong
   GWL_WNDPROC) was also unusable, so LB_ADDSTRING/LB_GETCOUNT died inside
   VCL and Items.Count stayed 0 while FStateList grew.
Fix: on the native i386 build ctl_proc IS a stdcall function in-process —
expose it: `builtin_control_class()` now sets `proc32 = (uint32_t)ctl_proc`
(i386 only). GetClassInfoA/W and GetWindowLong already return proc32, and
CallWindowProc/call_guest_wndproc route through wn_wow64_call_wndproc32
which is a plain stdcall indirect call on this build — the whole
superclass-subclass-DefWndProc chain now lands in the builtin. (x64/wow64
keeps 0: a host code pointer is not expressible to a 32-bit guest there.)

### The next crash in the chain: POINT-by-value stdcall ABI
Wizard moved (SetRectEmpty, WindowFromPoint = Inno's flat-button hover
logic — VCL FindControl/GetParent walk) and died returning to a dead stack
address (0x40bdc101, bytes "EXPFTEA") inside tmp+0x414548's frame: the
WindowFromPoint STUB popped 4 bytes for a POINT that arrives BY VALUE
(8 bytes, i386 stdcall) — a 4-byte leak per call that redirected the next
ret. Fixed by making the APIs real (they needed implementing anyway):
- `WindowFromPoint(POINT)`: per-arch signature (two dword args on i386,
  one packed register arg under ms_abi), deepest visible+enabled window
  under the point with proper parent-relative translation (newest-first
  z-order approximation).
- `PtInRect(RECT*, POINT)`: real test, inclusive left/top, exclusive
  right/bottom. Stub table width 2→3.
- `SetRect`/`SetRectEmpty`: real writes (stub-0 left VCL TRects garbage).
- Stub pop table: WindowFromPoint 1→2 (POINT by value).

### WaitMessage: the 100%-CPU idle spin
With the wizard up, Delphi's TApplication.Idle called our returning-0
WaitMessage stub in a hot loop — 101k calls/min, 100% CPU, but ALIVE.
Now a real blocking WaitMessage on the same wake sources as GetMessage
(posted messages, quit flag, timer deadlines, backend input), consuming
nothing. Wizard now idles at 0.9% CPU.

### Software raises finally carry real registers (the all-zero reports)
kernel32's RaiseException is entered directly from the guest IAT; on i386
a naked gate (`pusha`, `ret $16`) snapshots EAX..EDI/EBP/ESP at the call
and passes (args, regs) to the impl — the crash report now prints the
raising method's live context, and seh.c walks it: an EBP frame probe that
classifies frame locals via VMT shortstring class names (AddItem2's
[ebp-4]=Self proves out), the caller chain, the Inno checklistbox's two
divergent lists (Items @ Self+0xfc, FStateList.Count @ [Self+0x168]+8),
and an i386 EBP-chain backtrace in the crash report. Proof:
scripts/dev/raise32.c (i686 mingw, distinct constants in EAX..EDI) — the
report round-trips all six plus RIP = the raise site and an EBP backtrace.
x64 keeps honest zeros (no register state to keep there).

### Environment rebuilt from scratch (sandbox reset again)
Everything needed to rebuild the 32-bit loop is now in ONE idempotent
script: /home/z/my-project/scripts/setup_root32.sh (libc6/libc6-dev:i386,
libgcc-s1:i386, lib32gcc-14-dev, linux-libc-dev:i386 — bits/sched.h wants
linux/types.h under --sysroot — qemu-user 10.0.13, the i386 X11/freetype
runtime chain for winnux32's dlopen, ld scripts rewritten to "="
sysroot-relative paths). Makefile sysroot mode gained
`--sysroot=$(M32_SYSROOT)` (tab-safe patch script:
scripts/fix_m32_sysroot.py) so ld finds the 32-bit interpreter and
NEEDED dirs inside the sysroot. trixie's qemu-user-static is a STUB
package — the dynamic qemu-user has the real binaries. The i686 mingw
toolchain (apt-get download gcc-mingw-w64-i686-posix binutils-
mingw-w64-i686 mingw-w64-i686-dev mingw-w64-common, extract into
toolchain/root) builds 32-bit guest probes end-to-end
(scripts/dev/raise32.c: build → run32.sh → report).

### Gates
19/19 (new t19_rect_wfp_wait: SetRect/SetRectEmpty values, PtInRect edge
semantics, WindowFromPoint off-window/parent/deepest-child via
ClientToScreen, WaitMessage wake on a queued message). sigs32 regen: 788
exports. winnux32 boots under qemu-i386; raise32 probe verified. Installer
wizard run verified twice (alive+idle, 1-line log, 0 stubs).

## Date: 2026-10-20 (session 16: field-log forensics — user IS on the fix; SID 11-word ABI + real EnumFonts + self-describing Delphi reports)

### Forensics: the user's latest log is from a d8c6996 build
The new field log prints `DELPHI_EXCEPTION (0x0EEDFACE) at
luaforwindows_v5.1.5-52.tmp+0x4e09e` — that exc_name and the guest-module
attribution exist ONLY in d8c6996 (git grep at a9f6643: zero hits). So the
RichEdit/Rstrtmgr chain landed and the DLL loads now succeed (no
ERROR_MOD_NOT_FOUND lines). What remains in that log, in order:
`STUB EnumFontsA -> 0, GetLastError=120`, `FreeSid(0x1) refused` TWICE,
then the Delphi raise, still unhandled.

### AllocateAndInitializeSid was a 10-word lie about an 11-word contract
Windows signature: `BOOL AllocateAndInitializeSid(authority, count,
sub0..sub7, PSID *pSid)` — 11 stdcall words, BOOL return. Ours declared
10 params and RETURNED the PSID (which nobody reads). Three separate
breakages from one wrong signature: pSid never written (the RTL kept a
stale 0x1 stack slot and freed it — the two FreeSid WARNs), the guest's
44 pushed bytes met a 40-byte `ret` (4-byte stack skew per call), and the
gen_sigs32-derived thunk words said 10 while the stub table said 11.
Fixed: full 11-param C signature, BOOL return, out-slot written via
wn_wow64_out_handle (caller-width store). obj32 proof:
`ret 0x2c` (44) with the realign prologue intact; sig table regen to 11
words. Same pass fixed OpenThreadToken/OpenProcessToken out-slots
(previously `wn_abiword *token` host-width stores — an 8-byte write into
a 32-bit caller's 4-byte HANDLE slot under wow64, smashing the adjacent
guest dword).

### EnumFonts/EnumFontFamilies: the font world exists now
`STUB EnumFontsA -> 0, GetLastError=120` told every font-walking guest
"this machine has NO fonts" (Inno probes EnumFontsA during wizard
construction; VCL TScreen.Fonts walks EnumFontFamilies). gdi32 now serves
EnumFontsA/W + EnumFontFamiliesA/W from the advertised face table (the
names CreateFont* actually accepts: MS Sans Serif, Arial, Courier New,
Tahoma, System...), one callback per face with LOGFONT/TEXTMETRIC laid
out per mingw's wingdi.h (TEXTMETRICA 56: tmItalic@0x30,
tmPitchAndFamily@0x33, tmCharSet@0x34), metrics sourced from the same path
GetTextMetricsA reports (FreeType on x64, 8x16 atlas otherwise). Guest
callbacks ride the 4-dword bridge for 32-bit guests (low-arena structs)
and direct calls for native-width guests; stop-on-zero and last-callback-
return semantics per Windows. Unknown-but-requested facenames still get
one entry (our renderer aliases any name — reporting it is consistent).

### Unhandled Delphi raises are now self-describing
All Delphi raises funnel through one RTL helper, so "raise site" names
nothing. The crash report now decodes the Exception object:
[obj]=VMT (class-name shortstring scanned from the VMT metadata block,
canonical vmtClassName at -$0C), [obj+4]=FMessage (longstring: length
DWORD at ptr-4), probing info[1] then info[0] (Delphi 2-era RTLs — the
Inno engine — pass the object in info[1]). Everything safe-probed.
Verified end-to-end with a synthetic raise (tests/fuzz/s15_delphi_raise.c,
VirtualAlloc'd below 4GB to model a 32-bit guest's memory):
`delphi exception: ETestError: "list item and state item count mismatch"`.
The NEXT field log will print what the installer actually raises — no
more guessing which check fired.

### Gates
New regression test t18_font_enum_sid (exact face counts, stop protocol,
facename filter, alias, W variants, lparam roundtrip, 11-word SID
contract incl. pSid sentinel + revision bytes + distinct SIDs + FreeSid
NULL returns): **18/18 PASS first run**. gen_sigs32 regen: 783 exports.
winnux32 boots under qemu-i386; `ret 0x2c`/`ret 0x10` proofs above.

## Date: 2026-10-20 (session 15: installer opens — RichEdit/Rstrtmgr/tokens)

### Field report
With the -mincoming-stack-boundary=2 build on their box, the wizard STOPPED
crashing in _XSend and the installer window OPENS. Next failure, decoded
from the user's log: LoadLibrary("RICHED20.DLL"/"RICHED32.DLL"/"Rstrtmgr.dll")
all failed -> Inno's TRichEditViewer raised Delphi 0x0EEDFACE (unhandled).
Bonus findings in the same log: OpenThreadToken resolved to the loud stub
(120) and fed the Delphi RTL garbage (later FreeSid(0x1) WARNs), and the
unhandled-exception report was useless (RIP blamed the host RaiseException
builtin at winnux32+0x10bca, all registers zero).

### Fixes (all verified by new regression test t17_richedit — 17/17 suite)
- riched32/riched20/riched30/msftedit builtins (presence-shim policy: loads
  succeed; the RichEdit window classes are user32 builtin control classes
  "RichEdit"/"RichEdit20A"/"RichEdit20W"/"RichEdit30"/"RichEdit50W" mapped
  to CTL_EDIT memo semantics, exactly what Inno's read-only text viewer
  needs).
- rstrtmgr.dll: graceful Restart Manager — RmStartSession issues a session
  handle + key, RmGetList reports zero affected processes, Shutdown/
  Restart/End/Cancel succeed; installers skip the "files in use" page
  (true under WinNux — nothing else runs the target files).
- advapi32 token honesty: OpenThreadToken FALSE+ERROR_NO_TOKEN (we never
  impersonate), OpenProcessToken FALSE+ERROR_ACCESS_DENIED (no token
  subsystem), GetTokenInformation FALSE+ERROR_INVALID_HANDLE,
  CheckTokenMembership call-ok+not-member (admin checks degrade to plain
  user installs). Ends the stub-120 -> FreeSid(0x1) garbage path.
- seh: wn_seh_raise now takes the GUEST raise site (__builtin_return_address
  from k32_RaiseException = the guest's call site, valid in both native i386
  IAT calls and wow64 tail-jump stubs). Crash reports for Delphi/C++ EH
  raises now name the real module+RVA instead of the host builtin; registers
  stay honestly zero (software raise = no fault context). exc_name knows
  DELPHI_EXCEPTION (0x0EEDFACE) and MSVC_CXX_EXCEPTION (0xE06D7363).
- gen_sigs32 regenerated (779 exports; the 12 new functions).

### Next expected blocker (decoded earlier, unchanged)
TNewCheckListBox 'List item and state item count mismatch' at engine+0x44e058
(Items.Count [Self+0xfc] vs FState.Count [[Self+0x168]+8] diverge) — now
reachable with RichEdit alive.

## Date: 2026-10-20 (session 14: the alignment fix that actually closes the crash)

### Why the user still crashed after session 13 — two stacked failures
User re-ran the installer and hit the SAME `_XSend` movaps SIG11
(bytes `0f 29 64 24 20`, fault in libX11 `_XSend+0x135` via XSetWMProtocols,
backtrace guest `0x40afa3` -> winnux32 `0x8070dcb` -> `0x807055b` ->
`0x804b61f` -> X11). Chain: our wndproc dispatcher called the guest VCL
wndproc; INSIDE it the guest called CreateWindowEx; our builtin passed the
guest's 4-byte-aligned ESP straight down into libX11.
1. bcb34df (session 13 recovery) was NEVER PUSHED — origin/main sat at
   9edf899, so the user's pull+rebuild never contained ANY fix (crash bytes
   were byte-identical to the pre-fix binary).
2. Even if pushed, -mstackrealign alone could NOT fix this crash:
   disassembly of the bcb34df build showed u32_CreateWindowExA,
   u32_ShowWindow, u32_SetWindowPos and x11_win_create ALL had plain
   prologues — -mstackrealign only realigns functions that THEMSELVES have
   16-byte-aligned stack objects (69 of ~1700). The crash chain contains no
   such function, so guest misalignment propagated into libX11 regardless.
Fix (verified this session): M32ALIGN gains
`-mpreferred-stack-boundary=4 -mincoming-stack-boundary=2`. GCC then assumes
only 4-byte incoming alignment for EVERY function, and every function that
makes an outgoing call realigns its frame at entry — so the FIRST builtin
any guest touches realigns, and every host lib below (libX11/libc included)
runs 16-byte aligned. Rebuilt winnux32: 929 realign prologues (was 69);
u32_CreateWindowExA / u32_ShowWindow / u32_SetWindowPos / u32_CreateWindowExW
/ u32_MessageBoxW / k32_GetModuleFileNameA / x11_win_create / all
missing-import stub impls now open with `lea 0x4(%esp),%ecx;
and $0xfffffff0,%esp; push -0x4(%ecx)`. Varargs + 16-aligned struct copies
probed correct under qemu-i386; winnux32 boots under qemu-i386; 16/16
tests green; x86_64 build untouched (flag is i386-only).
Push verification: origin/main == HEAD after this session's push.

## Date: 2026-10-20 (session 13, rebased + pushed)

### The reported GUI installer crash: root cause + fix (VERIFIED at build level)
User report: `./bin/winnux run LuaForWindows...exe` (GUI mode, their Arch box)
died with SIG11 addr=(nil) at winnux32 host code, faulting instruction bytes
`0f 29 44 24 10...` = `movaps %xmm0,0x10(%esp)` with ESP%16==12.
Diagnosis: i386 builtins are stdcall C functions wired DIRECTLY into the guest
IAT; guests only guarantee the Win32 4-byte stack alignment; Arch's -m32
codegen (SSE-emitting) assumes GCC's 16-byte chain and #GP'd at the first
misaligned guest call (Linux reports #GP as SIGSEGV si_addr=NULL — no CR2).
Fix: M32ALIGN = `-msse2 -mstackrealign` for the winnux32 build. Dev-box
verification of the rebuilt binary: 12 functions contain movaps (SSE now
pinned on conservative hosts too, so this class can't silently diverge);
11 of them use stack slots and ALL 11 carry `and $0xfffffff0,%esp`
realignment prologues (69 total); the 12th (u32_SetKeyboardState) writes
only the linker-aligned static g_key_state array — alignment-independent.
Note: this session's sandbox was reset (the earlier session-13 commits were
lost locally and never pushed); all edits below were re-applied from the
session ledger and re-verified as builds. The end-to-end wizard-run
evidence in this ledger comes from that earlier session's runs on the real
installer (same code): the wizard built TMainForm -> TWizardForm -> outer/
inner notebooks + pages -> TNewMemo -> TRichEditViewer -> TNewComboBox ->
TNewCheckListBox, resolved C:\Program Files\Lua\5.1, and MAPPED its window
under Xvfb. SourceForge blocked the exe re-download this session, so the
run-level rerun is left to the user's box.

### The session-12 registry corruption mystery: SOLVED (regression-class)
`reg: CORRUPT child chain` = RegCloseKey -> handle refcount 0 -> the handle
table FREED the wn_reg_key while it stayed linked in the tree; the next
RegOpenKey walked RECYCLED heap, matched garbage, and handed the guest a
handle wrapping someone else's live allocation -> the "runaway write" that
hit host brk and the engine's own heap (0x49d41c buckets), i.e. the whole
session-12 forensics trail. Fix: wn_handle_set_nofree(WN_HTYPE_REGKEY) —
HKEYs are open-instance handles, the tree outlives them (Windows semantics).
Zero tripwire hits since.

### Wizard-chain blockers fixed in sequence (each proven by its disappearance)
1. ExtractIconA/SHGetFileInfoA stubs returned 0 -> VCL raised EOutOfResources
   at the checked icon loads. Both real now (module RT_GROUP_ICON walk +
   shared LoadIconA handle shape; DrawIconEx blits real RT_ICON DIB pixels).
2. CreateCompatibleBitmap stub return made VCL raise EOutOfResources; real
   32bpp bitmap objects now (plus LoadBitmapA walking named RT_BITMAP DIBs —
   Inno's wizard imagery, 4/8bpp palettes included).
3. The whole wizard tree was torn down right after creation with NO
   exception: VCL's menu build (CreateMenu/AppendMenu/SetMenu/GetSystemMenu/
   DeleteMenu all stubs) failed, Inno freed the half-built wizard, a straggler
   page insert under a dead parent raised EOutOfResources('Error creating
   window'). Real menu objects + Set/Get/RemoveProp + scroll state +
   SendNotifyMessageA landed; the teardown vanished.
4. WM_NCDESTROY was never delivered by our DestroyWindow: VCL zeroes FHandle
   in WMNCDestroy, so every destroyed window kept a STALE guest-side handle;
   Inno's recreate flow then re-created children under dead parents. Fixed:
   DestroyWindow dispatches 0x82 after WM_DESTROY.
Also: FreeSid refuses foreign pointers (a garbage SID from token stubs
free()d a stack pointer and aborted mid-install); full ListBox protocol
(LB_INSERTSTRING/ITEMDATA/SETSEL/GETSEL/GETSELCOUNT/GETSELITEMS/FINDSTRING/
GETTOPINDEX + item_data/sel_bits arrays — TCheckListBox state depends on
these); GetTextExtentPointA/W aliases (the stub wrote NOTHING into the
caller's SIZE); CreateWindow failure paths log WARNs with guest call sites;
SendMessage-to-dead-hwnd counter; Delphi exception decoder in the raise log.

### Remaining blocker (decoded, next session)
BOTH /S and the GUI path die at the SAME deterministic point: Inno's
TNewCheckListBox count check at engine+0x44e058 raises
"List item and state item count mismatch" right after the control is
created. The check compares Items.Count (VCL virtual at [Self+0xfc], a
TStrings) against FState.Count ([Self+0x168]+8). Our LB trace showed the
checklistbox receives NO LB_ traffic before the raise — one of the two
lists diverges through a path we haven't seen yet. NEXT: gdb under qemu
(break at 0x44e083) to dump both counts + the [Self+0xfc] object, or
extend the Delphi decoder to walk info[2].

## Date: 2026-10-19 (session 11)

### The reported PeekMessageA infinite pump: root cause + fix (VERIFIED)

User report: `WINNUX_WOW64=1 ... ./bin/winnux run ~/test/LuaForWindows_v5.1.5-52.exe /S`
spammed millions of lines — the same `PeekMessageA / TranslateMessage /
DispatchMessageA` returning `hwnd=101 msg=1 (WM_CREATE) wp=0 lp=0` forever,
then timeout. Reproduced exactly (21.5M log lines in 40s with X11 up).

Root cause 1 (the loop): `u32_PeekMessageA` had the PM constants INVERTED —
`remove & 1 /* PM_NOREMOVE */` gated `queue_peek` (leave it queued) for
PM_REMOVE=1. Inno's silent pump peeked the same message forever.
Root cause 2 (the garbage message): WM_CREATE was POSTED into the queue by
CreateWindowEx (Windows sends NCCREATE/NCCALCSIZE/CREATE synchronously,
inside the call, with a real CREATESTRUCT; the posted lp=0 form is also a
VCL data-init break). Both fixed; CreateWindowEx now delivers the full
create sequence through the new 64->32 callback bridge with a guest-layout
CREATESTRUCT in low memory, honoring the -1 creation-rejected verdict.

### The systemic wow64 width-bug harvest (all found via this installer)

Every layout decision that used compile-time `#if __x86_64__` was WRONG for
the in-process 32-bit guest path; the runtime query `wn_wow64_guest32()`
(already used by some writers) is the correct pattern and is now applied to:
- guest MSG (28-byte i386 layout vs 48-byte x64 — the x64 shape smashed 20
  bytes of guest stack per PeekMessage);
- WNDCLASSA/W reads in RegisterClassA/W (the TApplication class registered
  a GARBAGE name read at x64 offsets from an i386 struct -> "class does not
  exist" -> the Delphi exception that killed the child);
- new GetClassInfoA/W (the missing API: Inno checks-before-registering),
  CharLower/CharUpper(+Buff), OemToChar/CharToOem family, and kernel32's
  GlobalAddAtom/Find/Delete + GetAtomName (all were returning-0 stubs that
  Delphi read as NULL strings / "atom table full");
- RaiseException's ExceptionInformation (DWORD array for i386 callers);
- WaitForMultipleObjects/Ex + MsgWaitForMultipleObjects handle ARRAYS
  (DWORD entries for i386 callers): the parent polled garbage handles and
  never reaped its dead child — the zombie that hung every run (verified:
  the parent now calls GetExitCodeProcess, DeleteFileA, RemoveDirectoryA,
  DestroyWindow and ExitProcess cleanly after a child failure);
- GetWindowLong(GWLP_WNDPROC) on builtin-class windows returned a HOST
  function pointer; the 32-bit outer instance jumped to its low 32 bits
  (0x487a1ce0 = a host heap pointer's low half) via CallWindowProc.

### The 64->32 callback bridge (wow64)

32-bit guests hand us raw i386 code addresses as callbacks; calling them
as host functions executes i386 code in 64-bit mode. New:
- `wn_wow64_call_wndproc32[_base]`: stdcall 4-arg guest-callback invoker
  via wn_wow64_call32, scratch spaced by call-depth below the live guest esp;
- wndprocs (RegisterClass stores proc32, never a callable host pointer),
  dialog procs, timer procs, CallWindowProc and REAL SetWindowLong
  subclassing all route through it — the Inno child's TApplication wndproc
  and VCL MakeObjectInstance subclass (0x419caXXX) now execute correctly
  (verified in-log: the guest proc pushes SEH frames, calls
  DefWindowProcA, returns through the bridge).

### 32-bit frame-based SEH (new, wow64)

Before this session every guest exception fell straight to "unhandled":
Delphi's fs:[0] chain was never walked, so NO guest try/except/finally ever
ran (Delphi raises 0xEEDFACE constantly as flow control). seh.c now has the
full i386 frame-SEH engine:
- search pass over TEB32 fs:[0] frames with guest-layout EXCEPTION_RECORD
  (0x50) + CONTEXT (0x2CC) built in low memory;
- verdicts: 0 continue, -1 continue-execution (context written back to the
  ucontext), 1 unwind-to-me;
- return-1 frames (decoded from the installer's System unit: the Borland
  __finally handler runs the body when flags&6 and returns 1 on both
  passes) run inner finally bodies, pop frames, and the search continues
  OUTWARD — the Delphi "finally bodies run as the exception flies outward"
  model;
- RtlUnwind (kernel32+ntdll) branches to `wn_seh_rtl_unwind_32` for i386
  callers: walks+pops frames, then the continuation lands with
  [esp]=ReturnValue [esp+4]=Record ESP=TargetFrame (decoded from the
  4030cc handler: the Delphi continuation reads the record at [esp+4]);
  a walk-level longjmp chain aborts the unwound handler invocation
  cleanly (depth restored, no C-stack leak);
- verified in-log: the child's setup-data AV walks 3 finally frames,
  runs their bodies (CloseHandle etc. inside the handler), and the outer
  installer instance completes its whole failure lifecycle.

### Session 12: native i386 frame SEH + nested-walk cap (both engines)

User-reported: `make && make winnux32` died at wow64.c's
`wn_wow64_unwind32_take` (-Werror=unused-parameter under -m32). The fix
(void-casts in the #else branch, matching its sibling) exposed what the
user's next build would have hit: `wn_seh_rtl_unwind_32` was defined only
for the x86_64 host, but kernel32/ntdll call it unconditionally — the i386
link died on 2 undefined references. seh.c gained the full NATIVE i386
frame-SEH engine as the #else branch of the wow64 one:
- %fs:0x18 is the REAL TEB on this build, so the walk reads the live
  fs:[0] chain head directly (the guest maintains it); handler addresses
  are plain cdecl code pointers (i386 frame handlers are cdecl, NOT
  WN_API/stdcall — see wn_types.h);
- fault path: real ucontext -> guest-layout CONTEXT (0x2CC),
  ExceptionContinueExecution writes regs back into uc, unwind lands by
  patching uc->EIP/ESP/EAX (sigreturn does the switch);
- RaiseException path: same walk; after an RtlUnwind continuation is
  pending, wn_seh_raise lands via the wn_seh32_land global-asm trampoline
  (mov ecx/edx/eax; mov edx,esp; jmp *ecx) — a real stack switch that
  never returns, mirroring the wow64 thunk's pending-unwind exit path;
- RtlUnwind: walk+pop frames running finally bodies, write the Delphi
  continuation ([esp]=ReturnValue, [esp+4]=Record), longjmp back to a live
  walk or leave the landing pending.
The nested-fault guard (session-11 hang: a finally body raising again
re-entered seh32_dispatch) is now on BOTH engines: a per-thread
g_seh32_walk_active cap refuses re-entrant walks, and a capped raise
during an unwind reuses the pending continuation (x64: the thunk exit
path lands it; i386: the trampoline) instead of hanging or crashing.
Build hygiene: the obj32 rules now use $(CFLAGS) (dep tracking + the
per-file -fno-stack-protector rule extended to obj32 signal-context
files, same rationale as x64); beware: Makefile rules defined BEFORE
OBJ32:= expand $(OBJ32) as empty (the -include line literally picked up
/etc/apparmor.d via the /*/*.d glob — use literal obj32 paths above the
definition, as committed). toolchain/root32 + qemu-i386 were rebuilt
(setup: /home/z/my-project/scripts/setup_root32.sh).
VERIFIED: `make` + `make winnux32` both link clean (sysroot mode here;
the user's native-multilib box needs only the source fixes), smoke32
9/9 checks under qemu (TEB fs:0x18/0x20/0x34, heaps, ticks, last-error),
64-bit suite 16/16.

### Session 12, part 2: Windows-contract heap/resource/registry fixes + crash decoded

Continuing the installer bring-up with the qemu/winnux32 comparison loop
(now working: WINNUX_CHILD_CMD routes guest CreateProcess children through
qemu — /proc/self/exe is the EMULATOR under qemu-user):
- Global/Local heap: faithful Win32 semantics now. GMEM_FIXED handles are
  the pointer (Windows guarantee); GMEM_MOVEABLE is an OPAQUE handle from a
  registry table (0x7A000000-based) whose HANDLE never changes across
  GlobalReAlloc, whose blocks never move while locked (locked reallocs
  fail loudly, Windows-style), with real Lock/Unlock counts and
  GlobalHandle(ptr) lookup. The old identity model realloc'd blocks under
  the old Delphi RTLs (which hold raw pointers into locked blocks).
  GlobalHandle/GlobalReAlloc (+ Local* twins) were missing stubs before —
  the engine ran out of heap and raised 0xEEDFACE during init under qemu.
  Foreign-handle guards: GlobalFree/GlobalReAlloc reject sub-0x08000000
  values with ERROR_INVALID_HANDLE instead of free()ing garbage.
- Resources: FindResourceA returns an opaque WN_HTYPE_RES wn_handle value;
  LoadResource copies the resource into a REAL Global-heap block and returns
  its HGLOBAL (the Windows contract — old RTLs pass it to
  GlobalLock/Size/Free; the old raw wn_res_handle* made those calls
  free/realloc FOREIGN chunks — the winnux32 "Enum"-as-path crash walked
  exactly that chunk recycling). LockResource/SizeofResource accept both
  the HGLOBAL and the HRSRC.
- Registry: RegDeleteKey now ZOMBIES keys (unlink, never free) — the old
  free() left stale HKEYs pointing into recycled chunks (use-after-free);
  stale-handle ops on deleted keys fail cleanly; child_find has an "HK"
  prefix tripwire that logs corrupted chains instead of crashing the host.
- Forensics tooling: WINNUX_KEEP_TEMP=1 (temp-tree guest deletes become
  logged no-ops) captured the is-*.tmp engine; DEBUG logs on GlobalAlloc/
  ReAlloc/Lock, RegOpenKeyExA/RegDeleteKeyA, key_new, LoadResource.
- CRASH DECODED (both paths): engine 0x401bb7 is Inno's small-block heap
  FREELIST PUSH (`mov [edx],eax`) with a VMT address in the bucket head —
  the engine's heap metadata globals (0x49d41c/420/46c/470/478) are
  trashed by an earlier runaway write that ALSO hits host key structs.
  Binary + disassembly notes: /home/z/my-project/engine-forensics/.
VERIFIED: suite 16/16, smoke32 9/9 under qemu, `make`+`make winnux32`
link clean; x64 installer run reproduces the (now-decoded) engine crash
through the SEH walk to a clean failure lifecycle.

### The installer state after all of this

The process TREE now works end-to-end: outer exe extracts -> spawns the
is-*.tmp engine (713KB, reads the compressed payload from the ORIGINAL exe
by path — verified opens + byte-perfect sequential 4KB reads to EOF) ->
engine decompresses -> on any failure the parent notices, cleans up the temp
dir and exits with a code. What still fails: the engine's Inno setup-data
processing crashes writing a Delphi list node whose pointer is garbage
(edx=0x40a998 — an address inside the READ-ONLY CODE section, verified not
writable on Windows either, so it is a corrupted value, not a mapping bug;
reads are proven clean, so the corruption is produced by the engine's own
decompression/consumption path — eax=0x2e ('.') and a "tmp\4000" path string
on the crash stack point at Inno's language/setup-table parsing). The SEH
walk then hangs inside the 4th frame's handler (another nested exception
inside the unwind is the likely cause — nested-fault-in-unwind is not yet
handled). 16/16 tests green throughout.

## Date: 2026-10-18 (session 10)

### The LuaForWindows entry crash: the first guest AV, root-caused to a NULL static-TLS block

User report (native Artix box, one line of log):
`EXCEPTION_ACCESS_VIOLATION at luaforwindows_v5.1.5-52.exe+0x4325, access READ at 0x4`.
The failure point moved again — past PE mapping, past DLL probing, past the
entry call, INTO Delphi's System-unit initialization. Three facts from static
analysis of the exe (downloaded the identical release file):

1. `exe+0x4325` is `mov [eax+4], edx` — a WRITE, not a read (the report was
   lying: see the seh fix below). eax came back 0 from the preceding
   `call 0x403154` — Inno's threadvar fast-path accessor:
   `mov fs:[0x2C] -> TLS array; mov eax,[edx+eax*4]` with the index from
   the PE TLS directory's AddressOfIndex (0x40d3d0). Register residue
   (ESI=entry point, EDI=callbacks array — guest_entry_shim locals preserved
   by the stdcall callee) proves the crash is inside the FIRST entry-chain
   threadvar access of the process.
2. The block in `fs:0x2C[index]` was NULL. qemu-i386 + a hand-rolled GDB
   remote client (scripts/tls_probe.py — new dev tool) breaking at the entry
   point and at the accessor proves the whole chain HEALTHY under emulation:
   index=1 written by the loader, block allocated, accessor returns a real
   pointer at the exact same call site (RA 0x404323) that kills the user's
   box. The failure is native-only; by elimination (both TEBs registered
   and backfilled, LDT entries unique, TlsAlloc far away at 256+, no
   VirtualAlloc MAP_FIXED anywhere) the surviving explanations are
   build/env-specific loss of the index-slot write or the per-thread block.
3. Corrupting the index slot to 0 via the GDB stub reproduces the user's
   crash byte-for-byte (same RIP, same write-to-0x4, same register shape) —
   that is the failure signature on the user's machine.

### Fix: the Windows loader contract, enforced at the last moment

Windows guarantees before the EXE entry runs: the TLS dir's index slot holds
the assigned index AND every thread's TLS array carries an initialized
block. `guest_entry_shim` now re-verifies both immediately before calling
the entry point (main.c): rewrites the index slot if it disagrees (WARN +
log of both values), allocates the current thread's block if missing
(wn_tls_ensure_current in thread.c — which also refuses to write through an
fs:0x18 that does not resolve to a registered TEB, and says so at ERR
level), and logs the full chain (index/TEB/array/block) at DEBUG. Proven by
gdbstub fault injection: clobbering the slot inside guest_entry_shim before
the check → the WARN fires ("held 0, expected 1 — rewriting") and the app
keeps running instead of dying at exe+0x4325. Whatever link is broken on
the user's box, the next run either heals silently or names the broken
link in the log.

Also hardened: wn_tls_register_module's early-returns (dir too small, RVA
unmapped) were SILENT — now WARN with "static TLS NOT installed (expect
guest crashes)". wn_pe_tls_setup gained an out_index_va (cached guest VA of
the index slot, stored on wn_module) so the pre-entry check cannot drift
from the load-time parse.

### seh.c: the crash report was lying about reads

Linux gives SEGV_MAPERR/SEGV_ACCERR — it does NOT say read vs write, and a
store to unmapped memory arrives as SEGV_MAPERR, which the old code mapped
to "read". The user's log said "access READ at 0x4" for a write, sending
the whole hunt in the wrong direction initially. The signal handler now
decodes the faulting instruction's opcode (prefix skip + the common
memory forms: mov pairs 88/89/8A/8B, imm stores C6/C7, moffs A0-A3, string
ops, x87 fst/fstp, SSE loads/stores, ALU/shift/group reg-field split,
inc/dec vs call/push) and only falls back to the si_code guess when the
form is unknown. Bonus fixes in the same report: the "putty-ish rip"
leftover label now prints the real module+RVA; i386 gregs are zero-extended
so RSP no longer prints as 0xfffffffff7b5a130 (greg_t is SIGNED 32-bit;
stack addresses sign-extended into the kernel half).

Verified end-to-end under qemu via fault injection: the report now says
`access write at address 0x4` at `luaforwindows_v5.1.5-52.exe+0x4325`
with clean registers — matching the disassembly exactly.

### New regression test + restored 32-bit dev environment

The sandbox reset wiped toolchain/root32 + qemu + the i686 mingw cross
(again); rebuilt from debs (libc6-i386, libc6-dev-i386, lib32gcc-14-dev,
lib32gcc-s1 — glibc dlopens libgcc_s.so.1 for pthread_exit — qemu-user,
gcc/binutils/runtime for mingw i686, mingw-w64-i686-dev + common; the
libc.so ld script needed absolute-path patching, root32/lib -> usr/lib32
symlink for qemu -L). t16_tls32.c: __thread globals + CreateThread —
locks the static-TLS chain on BOTH arches (index write, per-thread
template copy, main/worker isolation: worker sees the template value, not
main's mutation). 16/16 x64 suite; t01/t06/t09/t16 i386 + 7zr usage under
qemu; LuaForWindows alive CPU-bound with zero repair lines (healthy chain,
as designed); fuzz 3000 iterations clean.


## Date: 2026-10-18 (session 9)

### The i386 stack-smash: one uint64_t extern decl vs the whole ABI

User report: LuaForWindows aborts with `*** stack smashing detected ***`
right after six "DLL not found" warnings (apphelp, propsys, oleacc,
profapi, comres, clbcatq). That glibc message is the HOST canary — a
WinNux frame, not the guest.

The repro gap (why we never saw it): our Debian gcc ships without
default stack protector; the user's Arch gcc enables
-fstack-protector-strong by default. Same overflow, only their build
detects it. The Makefile now passes -fstack-protector-strong explicitly
on every target — distro-independent and matches the field.

The hunt (new dev tools committed): scripts/dev/canary32.c (LD_PRELOAD
interposer for __stack_chk_fail that prints the smashing frame) and
scripts/dev/gdb_canary.py (gdbstub watchpoint driver). Bisects with
env-var early-returns isolated the write to the load_string_lookup ->
k32_FindResourceA call sequence. Root cause: user32.c declared

    extern WN_API uint64_t k32_FindResourceA(uint64_t, ...)

while the definition takes wn_abiword. On i386 WN_API is stdcall, so
the caller pushes 8 bytes for a 4-byte parameter: the callee pops 12
(ret 12), the caller pushed 16, and every skewed push afterwards lands
in the caller's own locals — `rid[16]` and its canary. Exactly the
class wn_types.h warns about; the declarations now use wn_abiword
(6 sites: FindResourceA/LockResource x2 call sites, g32_BeginPaint,
g32_EndPaint). Identity on x64, so nothing 64-bit changed.

Same class of fix: res_dir_base() walked the PE32+ optional-header
layout on PE32 images (data dirs sit 16 bytes earlier in PE32); it now
uses wn_pe_dirs(), which is arch-correct. 32-bit LoadString/resource
walks read real directories now.

### The six missing system DLLs

They are presence probes (Inno Setup feature-detects them at startup;
nothing was GetProcAddress'd from them at TRACE level). New
src/dlls/sysdlls.c adds apphelp/propsys/oleacc/profapi/comres/clbcatq
as builtins with honest failure stubs; wn_dll_sync_placeholders()
creates their files in drive_c/windows/system32 like every other
builtin (the prefix keeps the traditional Wine-style layout — the DLL
search order is builtin -> app dir -> system32 -> windows -> cwd).
Startup log is now clean of "not found" warnings for them.

### PE loader hardening (fuzzer-found, backported honesty)

The fuzzer (re-run after the canary work) found two real bugs:

1. Preferred-ImageBase mapping accepted wild bases: a fuzzed ImageBase
   above 2^47 is legal on LA57 kernels, mmap succeeds, and the mapping
   lands where no address check (or ASan shadow) can see it. Bases are
   now bounded to the arch's user range before MAP_FIXED_NOREPLACE.
2. wn_pe_dirs() re-read e_lfanew from the MAPPED image — but a section
   with VA 0 legally overwrites the mapped DOS header during the
   section copy, handing pointer arithmetic to fuzzed bytes (wild
   dirs pointer -> SEGV in apply_relocations). The validated optional-
   header offset is now cached in wn_pe_image.opt_off at parse time.
   Also: the full header blob must fit in SizeOfHeaders and in the
   file (e_lfanew + PE + file header + optional header + section
   table).

Fuzz: 3000 iterations x 15 seeds, zero crashes, ASan/UBSan clean.
Suite: 15/15. lua prints 7/WIN, sqlite computes, putty stays alive,
7zr prints usage, LuaForWindows runs alive with zero DLL warnings and
zero canary trips (qemu + interposer). Dev-box check32 now compiles
all sources under -m32 again (root32 sysroot restored).


## Date: 2026-10-18 (session 8)

### 32-bit i386: the PE-loading chain that "old" 32-bit apps depend on

The user's LuaForWindows (Inno Setup, Delphi 2-era, /FIXED, no .reloc)
died at "needs relocation but has no .reloc directory" — the loader never
tried the preferred ImageBase. Now wn_pe_map asks the kernel for the
EXACT preferred base with MAP_FIXED_NOREPLACE (4.17+; gracefully degrades
on ancient kernels, verified return address). /FIXED images load at
0x400000 like on Windows; everything else keeps relocating.

That opened a five-layer dig, each a real 32-bit-only bug (the 64-bit
build masked or lucked past every one):

1. **Static TLS** (Delphi threadvars via fs:0x2C): the module TLS
   registry used the x64 data-directory offset on PE32 images (dirs sit
   at optional-header +96, not +112) so 32-bit modules never registered;
   and the MAIN thread's TLS block was never allocated (thread-init only
   ran for future threads). Now: arch-correct dir walk, a live-TEB
   registry, in-place backfill on module load, blocks for new threads.
2. **VirtualAlloc reserve→commit-in-place** (the Delphi MM arena
   pattern): committing a reserved range made a FRESH mmap which the
   kernel displaced past the reservation; the caller kept writing to the
   still-PROT_NONE reserve (crash at arena+0xffc). Now commit-in-place
   mprotects inside the reservation; also correct MEM_COMMIT/MEM_RESERVE
   constants (the old code tested 0x1000 twice), page-readwrite maps to
   R|W (not W alone), and MEMORY_BASIC_INFORMATION is filled with the
   i386 28-byte layout (was: 48-byte x64 overlay stomping 20 bytes of
   guest stack) and VirtualQuery returns 28.
3. **GetSystemInfo**: wrote the 48-byte x64 layout on i386 (36 bytes,
   4-byte fields) — overwrote the caller's adjacent locals and left
   dwNumberOfProcessors/dwAllocationGranularity reading 0; Delphi's
   VirtualQuery region-walk then computed steps from zeroed fields and
   jumped through wild pointers (the "call the GOT" crashes). Arch-split
   layouts now; also fixed x64's dwPageSize offset while there.
4. **sscanf("%lx", (unsigned long*)&uint64)** writes only 4 bytes on
   i386: /proc/self/maps parsing in VirtualQuery/VirtualProtect matched
   nothing (VirtualQuery of the EXE BASE returned failure), so every
   map-walking guest saw garbage. Parse into unsigned long, then widen.
5. **PIC codegen on a -no-pie link** (Debian default -fpic): every host
   function kept EBX = GOT base; that value leaked across guest calls
   and the guest eventually CALLED it (exec fault at _GLOBAL_OFFSET_TABLE_).
   CFLAGS/M32FLAGS now -fno-pic -no-pie; the 64-bit link needed -no-pie
   added for the new objects.

Plus: the i386 stub trampoline now does **stdcall-aware returns**
(curated per-export pop table + `add esp,imm` caller-disassembly
heuristic; before, every stubbed stdcall call leaked its arg frame and
shifted the guest stack), the stub impl takes 4-byte args (the old
uint64_t params read slot pairs as garbage), and the EXE entry is called
with (image base, reason, reserved) like Windows — Delphi's System unit
STORES that hInstance and derives resource addresses from it (we used to
pass the PEB pointer).

### Real 32-bit apps under qemu-i386 (local loop)

- **LuaForWindows_v5.1.5-52.exe** (the user's test case): loads at
  0x400000, TEB/TLS live, Delphi MM arenas work, Inno's startup runs
  (locale tables, string resources via LoadStringA/W — now real), stays
  alive doing payload work (29MB installer overlay; CPU-bound for a long
  time under emulation — fine on native hardware).
- **7zr.exe 26.04 (i386, MSVC, unicode)**: banner, directory scan
  ("2 files, 28 bytes" — needed FindFirstFileW + the LFS fix below),
  archive creation starts. Full completion is blocked on MSVC C++ EH
  (_CxxThrowException is now a clean loud exit, not corruption) — next
  session's item.
- **readdir EOVERFLOW**: 32-bit readdir fails on 64-bit-inode
  filesystems (overlayfs/btrfs; errno 75) — FindFirstFile returned
  nothing at all inside containers. Switched the find + CI-resolve paths
  to readdir64/dirent64.

### New API surface (32-bit world + unicode apps)

FindFirstFileW/FindNextFileW (WIN32_FIND_DATAW), GetFullPathNameA/W
(lexical .. and . cleanup, \?\ stripped by the path layer), LoadStringA/W
(RT_STRING tables — Inno's whole UI), CharNext/CharPrev A+W, the locale
family (GetUserDefaultLangID/LCID, GetThreadLocale, GetLocaleInfoA/W with
the full mingw-verified constant table), FormatMessageA/W (FROM_SYSTEM
table + ALLOCATE_MEMORY + FROM_STRING; NOTE: lpBuffer is arg 5, nSize
arg 6 — the first cut had them swapped and 7-Zip crashed us for it),
GetProcessAffinityMask/IsWow64Process/GetProcessTimes/GetSystemTimes
(affinity 0 → 7-Zip sized a 0-thread pool and called NULL), the msvcrt
wchar family (wcscmp/wcsncmp/wcsicmp/wcschr/wcsrchr/wcscpy/wcsncpy/
wcscat/wcsncat/wcsstr/wcspbrk/wcsspn/wcscspn/wcstok/wmemcpy/wmemset),
_CxxThrowException (honest abort), SetFileApisToOEM/ANSI (no-op).

Also finished the missed tail of session 7's signature sweep: another
9 exports still took uint64_t params where Windows passes pointer-width
(SysStringLen/SysStringByteLen/SysFreeString/SysStringChar,
GetDC/ReleaseDC, BeginPaint/EndPaint, RtlAllocateHeap/RtlFreeHeap/
RtlSizeHeap, FindResourceA/LockResource, CertOpenSystemStoreA) — each
one shifted every 32-bit caller's stack by 4 bytes per bad arg; 7-Zip's
crash-by-NULL-vtable was SysStringByteLen's ret $8 for a 1-arg API.

Dev tooling that made this possible: a minimal Python GDB-remote client
(scripts/gdbstub_watch.py + measure/step/vtrace variants) driving
qemu-i386's gdbstub — breakpoints, watchpoints, register/memory reads,
single-step traces. This is how every crash above was root-caused
without gdb on the box.

64-bit suite 15/15 PASS; hello32/torture32 PASS; FindFirstFile A+W
32-bit test PASS; LuaForWindows zero crash lines.

## Date: 2026-10-18 (session 7)

### 32-bit i386: FIRST REAL RUNS — qemu-i386 unlocked local execution

The user's box aborted at TEB setup ("teb: modify_ldt failed: Success").
That "Success" was the bug: **the kernel returns 0 for modify_ldt(func=1
write), not the byte count** (byte counts are only for func=0 reads) —
the check compared against sizeof(desc)=8, so a WORKING LDT install was
misread as failure. One-line fix; verified against qemu-i386 + kernel
source. His kernel was fine all along.

Bigger unlock: **qemu-user (extracted to toolchain/qemu) can execute the
i386 build here** even though the container seccomp kills native i386
(SIGSYS) — `qemu-i386 -L toolchain/root32 bin/winnux32 run hello32.exe`
is now the local 32-bit test loop (modify_ldt and %fs LDT hosting both
pass through qemu). A local glibc32 sysroot was rebuilt from Debian debs
(apt-get download + dpkg -x, no root) after the sandbox reset wiped
session 6's copy; the mingw i686/x86_64 cross toolchains were re-extracted
the same way.

Then qemu found a bug class the 64-bit build could never show: **every
builtin parameter typed uint64_t where Windows declares a pointer-width
type (SIZE_T, WPARAM, LPARAM, HWND, callbacks...) skews the i386 guest
stack** — on i386 all args are stack-passed, so GCC computed ret-N for
16 bytes where mingw pushed 12, and read garbage upper dwords (HeapAlloc
"size" 0x40D0516000000000 for a 128 ask). Session 6's "hello32 worked"
was luck: the garbage slot happened to be small. Fixed systemically:

- **wn_abiword/wn_abiword_s** (wn_types.h): 8B on x64 = zero change,
  4B on i386. 203 builtin signatures converted across 18 DLL files
  (mechanical pass + manual review; dbghelp's genuine DWORD64 params
  excluded). thread_start_shim stays uint64_t — host-side contract.
- **Guest MSG overlay**: fill_msg now writes the 28-byte i386 MSG (was
  48-byte x64 shape — a frame smash on every GetMessage/PeekMessage);
  DispatchMessage/IsDialogMessage read guest-shaped fields.
- **Window-proc typedefs** (wn_wndclass.proc, dlgproc_fn, mon_enum_cb,
  TIMERPROC) + RegisterClassA/W read the 40-byte i386 WNDCLASS.
- **MSVC FILE stride is 32 bytes on i386** (48 on x64): mingw computes
  stdout as _iob()+N*sizeof(FILE); the wrong stride landed mid-entry,
  failed the magic check, and every fwrite silently no-ops — 32-bit
  printf output vanished. Fixed.
- MonitorFromPoint: POINT by value packs (y<<16|x) on i386, (lo=x,hi=y)
  in one register on x64.

New exports that real 32-bit apps hit immediately (all found by qemu):
**GetVersion** (10.0.19045, bit31 clear like NT), **GetVersionExW**
(OSVERSIONINFOW=276/EXW=284), **wsprintfA/W + wvsprintfA/W** (the shared
printf engine gained a wide-mode: %s follows the A/W direction, %S flips,
%ls/%hs override; the whole wsprintf family is cdecl, NOT stdcall —
varargs can't be stdcall), **_onexit** (returns fn on success per MSVC
contract — mingw CRT registers its cleanup through it), **localtime/
_localtime32/_localtime64/gmtime** (guest-shaped 36-byte MSVC struct tm,
NOT glibc's), **qsort** (in-tree heapsort — the comparator is guest code,
called through a WN_CRTAPI fn-ptr so the convention is right on both
arches; host libc qsort would call it SysV), **_strupr/_strlwr**.

Also: the Makefile had **no rule to create obj32/**, so a fresh clone
failed `make winnux32` with "No rule to make target 'obj32/...'" (the
order-only prereq was unsatisfiable — make rejects the whole pattern);
the user's box worked only because of leftover dirs. Plus the sysroot
mode now re-adds /usr/include/x86_64-linux-gnu to the -m32 chain
(glibc's bits/ headers are bi-arch; wordsize.h dispatches on __x86_64__)
and auto-detects the gcc version dir.

**Verification**: hello32 (CRT startup, WriteFile, GetCommandLineA,
ExitProcess(42) → exit 42), heap32 (HeapAlloc), torture32 (printf
width/precision/floats, malloc family, strdup/strcat/strupr, strtol,
qsort with guest callbacks, fopen/fwrite/fread/fseek/ftell/remove,
argv+env, time/localtime) — all pass under qemu with ZERO stub calls,
and `winnux run 32bit.exe -e args...` forwards guest argv through the
re-exec. The 64-bit suite: **15/15 PASS** (wn_abiword is uint64_t there,
so the width pass is a semantic no-op by construction).

Honest limits: 32-bit GUI beyond the MSG path is still x64-shaped
(TVITEM/DRAWITEMSTRUCT/NMTREEVIEW, WNDCLASSEX other fields); classic
msvcrt time-t-through-pointer (time(&t)) writes 8 bytes on a mingw
i386 guest's 4-byte slot — fine for mingw (64-bit time_t), legacy MSVC
i386 exes would need a 32-bit variant; stub arity metadata for stdcall
i386 still open (see TODO P0.3).

## Date: 2026-10-18 (session 6)

### The PuTTY config box is now the REAL dialog

The category pane root cause was found by downloading putty 0.85's source
(the config box is built around a **SysTreeView32** that putty creates
dynamically — our unknown-class path returned 0 **silently**, so the pane
was empty). Three fixes landed:

1. **SysTreeView32 builtin control class** (user32): TVM_INSERTITEM/
   GETITEM/SETITEM/GETNEXTITEM/SELECTITEM/EXPAND/GETCOUNT/GETITEMRECT,
   TVN_SELCHANGED notifications (synchronous WM_NOTIFY, exactly how
   Windows delivers them inside TreeView_SelectItem), painted tree with
   +/− boxes and selection highlight, click + arrow-key navigation.
2. **The Win64 TVI_* sign-extension trap**: putty passes TVI_ROOT as
   0xFFFFFFFFFFFF0000 (it is `(HTREEITEM)(ULONG_PTR)-0x10000`); our
   zero-extended 0xFFFF0000 constant rejected every ROOT insert, so the
   walk degenerated and Session/Terminal/Window/Connection vanished.
   Found by disassembling the TVI_ROOT immediate in putty.exe. With the
   fix the tree is EXACTLY real putty's: Session->Logging,
   Terminal->Keyboard/Bell/Features, Window->Appearance/Behaviour/
   Translation->Copy/Selection/Colours, Connection->Data/Proxy/SSH->
   Kex/Host keys/Cipher/Auth->Credentials/GSSAPI/TTY/X11/Tunnels/Bugs/
   More bugs/Serial/Telnet/Rlogin/SUPDUP — and the initial selection is
   **Session** (Host Name panel), like Windows.
3. **BS_GROUPBOX is 0x7, not 0x5** (0x5 is BS_3STATE — our comment lied).
   Group boxes now paint their frame+label directly onto the PARENT
   canvas with a transparent interior (Windows composes them last, top
   of the sibling z-order; blitting their opaque child surface covered
   the fields — the "gray overlay boxes"). VLM-verified: Host Name,
   Port, Connection-type radios and the Saved Sessions list are all
   visible in the Session panel.

Also fixed this session (user-reported): the **EMFILE registry failure**
(ensure_gui never set state=1 on success — every CreateWindowEx re-ran
wn_backend_init and LEAKED an eventfd; ~1 per dialog item, putty's fds
were at 72 while idle → now 5), **& accelerator prefixes** (DrawText now
parses '&x'/'&&' unless DT_NOPREFIX; "Cate&gory:" renders correctly),
**ShellExecuteA/W/Ex** (URLs/files via xdg-open, .exe/.bat re-launch
through our own loader; putty's About-box link previously failed with
SE_ERR_NOASSOC), and **resize hardening** (XSetWMNormalHints min==max
for windows without WS_THICKFRAME — X11 WMs resize anything, Windows
dialogs are fixed; plus gdi32 window DCs re-bind their pixel buffer
lazily in gdi_get() so a DC held across a resize cannot draw through
freed memory).

### 32-bit (i386): the loader, the build, and the re-exec — all landed

`winnux run app.exe` on a PE32 (i386) image now re-execs **bin/winnux32**
(a complete i386 build of the runtime). Everything statically verifiable
is verified on this box; RUNTIME verification needs a machine whose
kernel allows 32-bit syscalls (this container's seccomp kills ANY
i386 code — even a static exit(42) — with SIGSYS; the user's Arch box
runs it fine):

- **PE32 parsing is real**: `winnux imports 7zr.exe` walks all 6
  sections and classifies every import (previously rejected at the
  machine check). A mingw-i686-built test exe parses with **50/50
  imports OK, zero stubs**.
- **make winnux32 links**: ELF 32-bit LSB executable. Verified IN THE
  BINARY: stdcall `ret N` sequences in the exports (compile-time
  convention dispatch — Wine's model), the i386 stub trampoline bytes
  (push info/jmp; pop eax; 6 cdecl args; plain ret), `modify_ldt`
  (push 0x7b) + `mov fs,eax` (TEB hosting via LDT — glibc owns %gs).
- **i386 TEB/PEB/LDR/critsect layouts** with per-arch _Static_asserts
  (fs:0x18 self, fs:0x2C TLS, fs:0x30 PEB, fs:0x34 last error).
- **msvcrt is cdecl (WN_CRTAPI) + varargs decode is per-bitness**
  (4-byte slots, 8-aligned doubles on i386); the __p__* mingw startup
  family (__p__iob/__p__fmode/__p__commode/__p___initenv/
  __p___mb_cur_max/__lc_codepage) is implemented — every i686 mingw
  exe calls them at startup.
- **Toolchain discovery in the Makefile**: native -m32 (Arch needs the
  **[multilib] repo enabled in /etc/pacman.conf** first —
  `sudo pacman -Ss gcc-multilib` finds nothing without it — then
  `pacman -S gcc-multilib lib32-gcc-libs`), or a local sysroot
  (WINNUX_M32_SYSROOT; this dev box uses extracted glibc32 debs).

Honest limits: 32-bit GUI structures (MSG/TVITEM/DRAWITEMSTRUCT ...) are
still x64-shaped — the i386 milestone is console-first (7zr.exe is the
acceptance case). The stdcall STUB path (unimplemented imports only)
cannot pop the guest's args without per-export arg-count metadata —
real exports carry their convention at compile time, so only missing
APIs leak a frame per call.

### Regression status

15/15 tests. putty: tree renders with all categories, Session panel
selected, panels switch on click/keys (VLM-verified screenshots),
zero queue overflows, 5 fds. x64 build zero warnings; the whole tree
compiles -m32 with the same flags and links bin/winnux32.

# STATUS.md — the honest ledger

Updated every session. Format: what works (with the test that proves it),
what is broken, what is untested, what is next. Never claim success that was
not observed.

## Date: 2026-10-18 (session 5)

### The user's bug list: fixed and verified

All five issues from the user's run were reproduced locally under Xvfb
(synthetic clicks via the rebuilt `scripts/dev/xtree.c`), root-caused, and
fixed:

1. **`user32: message queue overflow (dropped 0x5/0xf/0x200)` spam —
   GONE.** Root cause: putty's layout code posted WM_SIZE+WM_PAINT per
   MoveWindow (3 queue slots × ~50 controls) and every WM_MOUSEMOVE went
   into a fixed 128-slot ring, so real input got DROPPED. Fixes, matching
   Windows semantics: WM_SIZE/WM_MOVE are now DELIVERED SYNCHRONOUSLY from
   inside MoveWindow/SetWindowPos (never queued); WM_PAINT is only ever
   synthesized from the per-window dirty flag by the pump (direct posts
   removed everywhere); WM_MOUSEMOVE coalesces in place (newest position,
   queue order kept); the ring grows 128→8192 if a burst survives
   coalescing; PeekMessage honors PM_NOREMOVE and pumps input (modal
   loops used to starve the whole input path). Evidence: putty soak now
   logs ZERO overflow lines.
2. **The About-button segfault — FIXED.** Reproduced exactly (same
   backtrace as the user). Chain: dialogs passed an owner as "parent"
   were created as CHILD windows; u32_ShowWindow then called the backend's
   win_show on a child's bwin (priv=NULL) → SIG11 in x11_win_show.
   Dialogs are now top-level OWNED popups (WS_CHILD decides child-vs-
   owned, per Windows), with owner-relative template positioning
   (DS_ABSALIGN honored). The About box opens as its own X11 window
   (540x544), survives interaction, and closes cleanly via the
   WM_DELETE_WINDOW ClientMessage (xtree `close`) — the full modal
   lifecycle (open → interact → close → owner re-enabled) works.
3. **`wship6.dll / hhctrl.ocx / shcore.dll not found` — GONE.** All three
   are builtins now (auto-placeholders in drive_c/windows/system32):
   wship6 = getaddrinfo/freeaddrinfo/getnameinfo over the host resolver
   with the addrinfo list deep-copied and **AF_INET6 translated
   (Linux 10 → Windows 23)**; shcore = SetProcessDpiAwareness/
   GetDpiForMonitor/GetScaleFactorForMonitor; hhctrl = loud honest
   HtmlHelp stubs.
4. **`EnableWindow` / `MessageBeep` STUBs — real.** EnableWindow sets
   WS_DISABLED, moves focus away, returns the previous state, and the
   input path now IGNORES clicks on disabled windows (the hit-test skips
   them; that is why putty's owner must be disabled during modal About).
   MessageBeep rings XBell through a new backend `beep` op.
5. **`registry: cannot save .../system.reg` — hardened.** The save is now
   atomic (tmp + rename, crash-truncation impossible) and reports errno
   with the REASON on failure; a stale/protected destination gets an
   unlink+rename retry. Not reproducible here (saves work locally) —
   if it still fails on the user's box, the log will now say exactly why
   (most likely EACCES from a prefix created by an earlier root run).

### PuTTY's config box now places itself correctly

Monitor/DPI APIs are real: GetSystemMetrics (full metric table),
MonitorFromWindow/Rect/Point (POINT BY VALUE — the 8-byte struct arrives
packed in RCX under the MS x64 ABI; a naive (x,y,flags) signature reads
y from RDX), GetMonitorInfoA/W, EnumDisplayMonitors, SystemParametersInfo
(SPI_GETWORKAREA), GetDpiForWindow/System, SetProcessDPIAware,
ScreenToClient/ClientToScreen, GetParent, GetWindowPlacement/
SetWindowPlacement. Two blockers found on the way: top-level windows
never had cw/ch set (GetWindowRect returned 0-size → putty center
shrank the box to 1x1), and the desktop pseudo-window was hardcoded
1280x800. Both fixed — putty's `centre_dialog(GetDesktopWindow())` now
centers the config box EXACTLY: 600x1008 at (660,36) on 1920x1080.

### Text is now FreeType-rendered (the "readable but not great" fix)

New `src/gfx/font_ft.c`: libfreetype.so.6 is dlopen'd at runtime (zero
compile-time deps, per project rules) and glyph structs are accessed via
hand overlays whose offsets were PROBED against the real headers
(FT_FaceRec.glyph@0x98, size@0xA0; GlyphSlot advance@0x80, format@0x90,
bitmap@0x98, bitmap_left@0xC0). Nothing is trusted blindly: init renders
'A', then locates the glyph-slot/size pointers by structural signature,
with every candidate pointer validated against a /proc/self/maps
snapshot (refreshed per scan — a stale snapshot made verification flaky).
On any mismatch we fall back to the embedded bitmap atlas and log it.
Rendering: alpha-blended glyphs, per-glyph advances, surrogate pairs,
family matching (Courier New/Consolas→mono, Times→serif, everything else
sans; DejaVu/Liberation/Free/Noto probed on Arch and Debian layouts),
bold/oblique variants with double-strike synthesis when only regular
exists. GetTextMetrics/GetTextExtentPoint use REAL metrics (ascent/
descent from the face; tmAveCharWidth = the 'x' advance — a face's
max_advance is a lie, DejaVu Bold reports 4129 units = 2× the em).
Also fixed on the way: XGetWindowAttributes wrote a ~136-byte struct
into a 24-byte overlay (stack smash in x11_init — the wild-pointer
crashes of the "1x1 config box" hunt).

### Interaction API batch (user32)

InvalidateRect/ValidateRect (dirty-flag semantics), GetSysColor/
GetSysColorBrush (classic palette), GetCursorPos/GetKeyboardState/
SetKeyboardState/GetKeyboardLayout/GetQueueStatus/GetMessageTime/
GetDoubleClickTime/GetCaretBlinkTime/IsIconic/IsZoomed/FlashWindow/
SetForegroundWindow, caret family (CreateCaret/SetCaretPos/ShowCaret/
HideCaret/DestroyCaret), FindWindowA, LoadImageA(icons), DestroyIcon,
DrawEdge (gdi32: real 3D borders), MsgBoxIndirectW, W-variants for
message/dispatch/text APIs, SendDlgItemMessageA/W, Get/SetDlgItemText,
MsgWaitForMultipleObjects (queue-aware wait with 0-timeout handle
probes through the sync engine). Push buttons now draw 3D frames +
dotted focus rects; disabled controls paint gray text (COLOR_GRAYTEXT).

### Dialog-engine fixes found by the About-box screenshots

DS_SETFONT dialog templates carry a font section after the title
(pointsize + fontname, plus weight/italic/charset in EX form) that the
item parser did not skip — every item after the first misaligned, which
is why putty's About box created only 2 controls and rendered no text.
With the skip: the About box renders its full text (595 dark + 1532
antialiased pixels measured in the region). Top-level windows also
honor their requested creation position now (X windows were born at
(0,0); the About box lands at (280,160), fully on-screen).

### 32-bit (WoW64) groundwork — source-level

`make check32` compiles the whole tree with -m32 (i386) when a multilib
toolchain exists (this container lacks 32-bit libc headers; the target
prints install hints and skips — it will run on the user's Arch box
with gcc-multilib). WN_API maps to cdecl on i386 for now; the x64-only
asm blocks (stub trampoline, RtlCaptureContext, _setjmp/_longjmp,
gs-TEB access) are guarded with i386 variants or compile-stubs, so the
tree stays buildable on both. What 32-bit STILL needs before a single
32-bit exe runs (documented in TODO P2): per-export stdcall/cdecl
dispatch metadata (Win32 i386 APIs clean the stack; varargs are cdecl),
i386 TEB/PEB layouts + a set_thread_area TLS scheme (gs:0x30 → fs:0x18),
i386 CONTEXT/EXCEPTION layouts for SEH, and a separate 32-bit build of
the runtime (Wine's model: 32-bit process, 32-bit X11 via dlopen).

### Regression status

15/15 tests (t14/t15 updated: wship6 is now a real DLL so the
missing-DLL test uses a permanently-missing name; text-extent checks
accept proportional metrics). lua.exe and sqlite3.exe re-verified.
Putty: 40s ASan soak clean (x2); interactions verified via xtree
(clicks, key typing, About modal cycle, WM_DELETE close). ASan exit-time
notes: memory CORRUPTION is zero everywhere; LeakSanitizer still flags
the per-thread TEB allocation (24B, freed-never at process death —
freeing it inside wn_process_exit is riskier than the leak) — the
exe_path strdup leak from cmd_run was fixed. Known gaps: putty's
Open button fires WM_COMMAND(BN_CLICKED) into its dlgproc but no
session launch follows (next session's target: trace the wndproc path
from WM_COMMAND to launch — likely needs the config→registry save and
the launch-thread flow); SysLink control class unknown (About box link
falls back); X11 clipboard/menus remain stubs.

## Date: 2026-10-18 (session 4)

### PuTTY STAYS ALIVE (the headline)

`winnux run putty.exe` under Xvfb now **runs until killed** (exit 124 after
a 30-40s timeout = a live GUI app in its message loop), with the
"PuTTY Configuration" dialog and "hidden timing window" mapped in the X
window tree, a QUIET log (only the three known optional-DLL notes:
wship6/hhctrl/shcore), and **40 minutes-equivalent soak: zero
AddressSanitizer/UBSan reports**. This session found and fixed the chain
that used to kill putty ~50ms after startup:

1. **gdi32 GetTextMetricsA wrote 32 bytes past TEXTMETRICA** (memset 0x58 +
   a write at offset 0x54 into a 56-byte struct). Putty's stack canary sat
   exactly after the 56-byte caller buffer → MSVC /GS failure →
   `__report_gsfailure` → `TerminateProcess(GetCurrentProcess(),
   0xC0000409 STATUS_STACK_BUFFER_OVERRUN)`. Fixed with the exact x64
   layout (tmItalic@0x30, tmPitchAndFamily@0x33, tmCharSet@0x34; total
   0x38). Found by disassembling putty's report path + stack archaeology
   (the failing function's RA and corrupted canary were recovered from the
   report_gsfailure frame).
2. **user32 LoadCursor/LoadIcon(A/W) dereferenced MAKEINTRESOURCE
   values** (IDC_ARROW = 32512 = 0x7f00 passed as a "string"). Fixed:
   `IS_INTRESOURCE` check (< 0x10000) in res_name_to_id + the W variants.
3. **IsDialogMessage had a one-arg signature** — it takes (hDlg, lpMsg);
   RCX is the dialog handle, RDX the MSG. The old code faulted reading the
   handle as the MSG pointer.
4. **loader DLL probe loop read cands[2] OUT OF BOUNDS**: when a
   LoadLibrary path had no ".dll" suffix (hhctrl.ocx), the `.dll`-append
   branch filled the last NULL slot and the loop walked one past the array
   into stack garbage (the "unreadable win-path pointer 0x6" spam).
   Fixed: cands[3] with a mandatory NULL terminator + Windows semantics
   (.dll is appended ONLY to extension-less names — "hhctrl.ocx" is probed
   as-is).
5. **MoveWindow + SetWindowPos are real now** (was a stub putty's dialog
   layout hits): child coordinates + parent recompose; top-level resize
   through a new backend op `win_move_resize` (X11: XMoveResizeWindow via
   dlsym + pixel-buffer realloc). WM_SIZE/WM_MOVE posted.
6. kernel32: **Rtl* unwinding exports** (RtlCaptureContext raw asm,
   RtlLookupFunctionEntry .pdata binary search, RtlVirtualUnwind full
   unwind-code interpreter incl. XMM saves/CHAINED opcodes, RtlPcToFileHeader,
   RtlUnwind v1 walk), **RaiseException** (real, routes through the VEH /
   crash-report path), **UnhandledExceptionFilter** (routes to the app's
   SetUnhandledExceptionFilter function). Putty's abort/SEH path calls
   exactly these.

Putty's config dialog: window + OK/Cancel buttons + controls are created
and the modal loop runs; the dialog is NOT yet visually complete (controls
draw as flat boxes; no per-control painting fidelity; keyboard nav exists
via IsDialogMessage but no end-to-end session creation yet — see TODO P0).

### Regression status this session

15/15 tests (t01-t15); lua.exe (`print(1+2*3, ("win"):upper())` → `7 WIN`)
and sqlite3.exe (`SELECT id, upper(name)` → `1|ALPHA 2|BETA 3|GAMMA`)
re-verified; putty 40s ASan/UBSan soak clean.

### The X11 input path was dead — now it is alive (same session, part 2)

Synthetic clicks (scripts/dev/xtree.c "click" mode, XSendEvent) proved the
whole X11 event path had never worked: events reached handle_event, then
vanished. Three bugs fixed:

1. **win_for compared X window IDs against stored priv POINTERS** — could
   never match, so Expose/Key/Button/Motion dispatch was all dead (painting
   worked only because generate_paints drives present() from timers).
   Fixed with a backend-local xwin→bwin map (x11_backend.c winmap_*).
2. **xkey overlay had `uint32_t time`** where LP64 X11 `Time` is 8 bytes
   (unsigned long) — every field after it shifted by 4: coordinates wrong,
   button read from `state`. Fixed: time is uint64_t, x@64/y@68,
   state@80, keycode/button@84.
3. **Dialog windows were message black holes**: class #32770 used ctl_proc
   which never forwarded to the guest dlgproc. Now every dialog message
   (WM_COMMAND from controls, WM_CLOSE, ...) is routed to putty's dlgproc;
   a synthetic click on the OK button makes putty's own handlers run
   (proven: putty called RegisterWindowMessageA + ReleaseCapture in
   direct response).

Also: WS_VISIBLE children now set their visible flag at creation
(previously only ShowWindow set it — dialog controls were invisible to
hit-testing); SetCapture/ReleaseCapture/GetCapture (mouse capture routing)
and RegisterWindowMessageA/W (ids ≥ 0xC000) are real.

**Proof of the full chain**: XSendEvent click at (80,500) → x11 trace →
user32 mouse handler (correct button + coords) → hit-test to the Button
child → WM_LBUTTONDOWN → ctl_proc → WM_COMMAND → dialog proc → guest
dlgproc → putty's handler code executes. Zero ASan/UBSan reports with
clicks; 15/15 suite.

### Part 3 (same session): dialog paints again + keyboard events arrive

- Dialog WM_PAINT is handled by the layer (face-color fill + child compose
  + present) BEFORE forwarding to the dlgproc — routing every message to
  the guest dlgproc had left nobody painting the background (putty's
  dlgproc ignores WM_PAINT like most do; DefDlgProc owns erasing).
  Screenshot now shows gray dialog + dark text pixels in the dialog
  region (xtree root capture; the PPM reader in xtree was also fixed to
  real 32bpp reads).
- Keyboard events reach the guest too (synthetic 'a' key via
  `xtree key <win> 0x61`: KeyPress/KeyRelease logged, routed to the focus
  window). Putty moved its own config dialog with our real MoveWindow —
  partially off-screen (600x1008 at 340,-104) because the monitor/DPI
  APIs are stubs; that placement (GetMonitorInfo/MonitorFromWindow/
  GetSystemMetricsForDpi) is the next visual-fidelity item.
- xtree (dev tool) gained: window geometry in the tree dump, PPM capture
  with correct 32bpp reads, synthetic click + key injection.

## Date: 2026-10-17 (session 3)

### Real applications (the headline)

| App | Result | Proof |
|-----|--------|-------|
| **lua.exe 5.4.7** (mingw build, loads lua54.dll) | **RUNS**: real language, strings, tables | `winnux run lua.exe -e 'print(1+2*3, ("win"):upper())'` → `7 WIN`; `table.concat` loops; ASan-clean |
| **sqlite3.exe 3.50.4** (mingw build) | **RUNS**: real SQL engine | `sqlite3.exe :memory: "CREATE TABLE t(...); INSERT...; SELECT id, upper(name) ..."` → `2\|BETA 3\|GAMMA`, `count/sum` aggregate — **zero stub hits**; ASan-clean; stdin script mode prints `42` |
| **putty.exe** (official x64, MSVC) | **STARTS: all 348 imports resolve; creates a window** | Xvfb window tree shows `PuTTY: hidden timing window` (scripts/xprobe); fatal box "Unable to load any WinSock library" ELIMINATED by path-aware LoadLibrary + wsock32 |
| 7zr.exe (32-bit) | analyzed only | `winnux imports` parses its PE32 import table; runtime = WoW64 TODO (P2) |

**UPDATE (same session): PuTTY's CONFIGURATION DIALOG EXISTS.** The dialog
engine landed: .rsrc resource walking (FindResourceA/LoadResource/
LockResource/SizeofResource), DLGTEMPLATE/DLGTEMPLATEEX parsing (incl. the
EX item layout and MAKEINTRESOURCE id resolution), child windows with
offscreen surfaces composed onto the parent, builtin control classes
(Button/Edit/Static/ListBox/ComboBox), DialogBoxParam modal loop. Proof:
`xprobe :95` shows `PuTTY Configuration` + the log shows its real control
tree (STATIC/EDIT/BUTTON ids 1041..1050 from the embedded template), zero
crashes; screenshot saved via scripts/xprobe. Remaining for putty: visual
fidelity (window sizing/painting), dialog message navigation, GDI fonts —
see TODO.md P0. Its abort/SEH path calls RtlLookupFunctionEntry/RtlUnwind —
confirming the SEH milestone priority.

### New: `winnux imports <exe> [-v]`

Static import analyzer for PE32+ and PE32, regular + delay-load imports;
classifies every function as ok / stub / native / native-missing / MISSING
DLL; builtin ordinal exports (`#N`) recognized. Exit 1 on missing DLL or
32-bit image. This is now the tool that drives priorities: run it on any
new app before touching code.

### New builtin DLLs (25+, proactive batch)

imm32, comctl32, comdlg32, shell32, shlwapi, ole32, oleaut32 (incl. ordinal
exports 7-Zip uses), rpcrt4 + uuid alias, version, psapi, dbghelp, setupapi,
winspool.drv/.dll, wininet, winhttp, mswsock, iphlpapi, dnsapi, crypt32,
bcrypt + cryptbase, secur32 + sspicli, userenv, uxtheme, dwmapi, winmm,
msvcp140 family (presence), wsock32 → ws2_32, api-set routing
(api-ms-win-crt-* → ucrtbase, other api-ms-/ext-ms- → kernelbase).

REAL inside them: CommandLineToArgvW (full quoting rules), SHGetFolderPath,
BSTRs/Sys*, GUID parse/format, UuidCreate (urandom), DnsQuery A/AAAA/PTR
via getaddrinfo, BCryptGenRandom/SystemFunction036 (urandom), base64
(CryptStringToBinary), psapi module enumeration, userenv environment
blocks, winmm timeGetTime. Everything else: documented honest failures
with WARN logs — never silent fake success.

### Loader + kernel32/msvcrt fixes found by real apps

- **LoadLibrary("C:\windows\system32\kernel32.dll") now works**: builtins
  match by basename; explicit paths resolve through the prefix. (This
  single bug blocked putty's winsock.)
- FLS (FlsAlloc/GetValue/SetValue/Free + thread-exit callbacks) over the
  Tls index space.
- LoadLibraryExW, GetModuleHandleExW/A (FROM_ADDRESS), GetSystemDirectory,
  GetWindowsDirectory, GetEnvironmentStringsW, Get/SetCurrentDirectoryW,
  MulDiv, InitializeSListHead, IsValidCodePage, SetConsoleCtrlHandler.
- msvcrt: ctype batch, **real `_setjmp`/`_longjmp` (raw asm, MS x64
  jmp_buf)**, fgets, _wfopen, _fileno, _isatty, _access/_waccess, _setmode,
  _time64.
- IsProcessorFeaturePresent: PF_FASTFAIL_AVAILABLE(23)=0 — returning 1 made
  MSVC's abort() fire `int 0x29` immediately.
- user32 MessageBoxA/W prints the text to the log and returns IDOK
  (diagnostic aid; the window is not fake-drawn).
- Crash report: RBP frame-chain backtrace (MSVC builds keep frame pointers).
- Out-of-bounds utf16 reads fixed (LoadLibraryW/GetModuleHandleW used the
  length parameter wrongly).

### Quality gates this session

13/13 tests; ASan/UBSan clean on the whole suite AND on real lua/sqlite
runs; fuzzing clean (600 iterations × 11 seeds after clean obj-dbg);
zero-warning build under GCC 14.2 (user's GCC 15 covered by the
discarded-qualifiers fix from session 2).

## Date: 2026-10-17 (session 2)

### Portability fix (user-reported: first build on GCC 15 failed)

* Building on a user machine with GCC 15 tripped
  `-Werror=discarded-qualifiers` in msvcrt.c: GCC 15 const-propagates the
  first argument's qualifier into `strchr`/`strrchr`/`strstr` builtin return
  types, so returning them as `char *` (the MSVC CRT contract:
  const-in/mutable-out) became an implicit const-discard. Fixed with
  explicit casts + a comment explaining the intent.
* Audited the whole tree for the same class: every other strchr-family
  use stores into `const char *` or a boolean context — safe on any GCC.
  `calloc` argument orders audited too (no transposed-args sites).
* Verified after fix: clean full rebuild, 13/13 tests on GCC 14.2 (Debian).

## Date: 2026-10-17 (session 1, part 3)

### Working — proven by `make test` (13/13 pass)

| Area | Proof |
|------|-------|
| PE32+ loading (map, relocs, imports, TLS, protections) + recursive PE DLL loading | all tests; t08 loads real `libwinpthread-1.dll` |
| ms_abi ABI bridge, TEB/PEB/GS-base, LDR lists | all tests |
| Console I/O + in-tree printf engine (MS-ABI varargs) | t01, t02 |
| args/env/CWD, GetCommandLine | t03 |
| Files (CI-reopen, delete, size, seek) | t04 |
| Directories + FindFirstFile (Windows dot semantics) | t05 |
| Threads + critical sections | t06 |
| Events/semaphores/WFMO/recursive mutex | t07 |
| Static `__thread` TLS + Tls API | t08 |
| Module APIs | t09 |
| VirtualAlloc/Protect/Query/Free + heap | t10 |
| **GUI vertical slice: X11 via dlopen, window, message loop, WM_PAINT, GDI FillRect/TextOut (server-rendered fonts via glyph cache), timers, destroy** | **t11 under Xvfb** |
| Winsock (TCP roundtrip, select, nonblocking) | t12 |
| Guest crash handling: SIGSEGV → EXCEPTION_ACCESS_VIOLATION report (module+rva, registers) + exception-code exit | t13 |

### Sockets (new this session)

* ws2_32 builtin over host BSD sockets: socket/bind/listen/accept/connect/
  send/recv/shutdown/closesocket, ioctlsocket FIONBIO, select with the
  **Windows fd_set layout** (count + SOCKET array, translated to host
  fd_set and back), __WSAFDIsSet, inet_addr/ntoa, gethostbyname,
  WSAStartup. SO_REUSEADDR on stream sockets matches Windows rebind
  behavior. **Proof: t12 — in-guest TCP server+client roundtrip with
  select() and nonblocking accept: 12/12 suite pass.**

### GUI architecture (as of this session)

* `src/backends/`: backend abstraction; X11 implemented with **zero X11
  headers** (dlopen + dlsym + wire-ABI overlay structs). Text rendering
  draws glyphs server-side into a scratch pixmap and reads them back with
  XGetImage — real fonts, no font library linked.
* user32: classes, windows, message queue (eventfd wake), timers,
  keysym->VK translation, DefWindowProc.
* gdi32: DCs over software BGRA buffers; window DIB layout == X11 32bpp
  ZPixmap, so present() is zero-conversion.
* Wayland: hand-marshalled wire protocol; display connect + registry +
  sync roundtrip verified; surface path (xdg_shell/shm) in progress —
  init() currently fails honestly and the selector falls back to X11.

### Broken / partial (unchanged from part 2 unless noted)

- SEH table-based unwinding (x64 .pdata/.xdata) still not implemented;
  guest `__try`/`__except` will not find scope handlers. Crash capture,
  VEH and the Windows-style report ARE proven (t13). POSIX truncates
  guest exit codes to 8 bits (0xC0000005 shows as 5) — same as Wine.
- MessageBox, dialogs, child windows, scrollbars: not implemented (stubs).
- Graphics: only software rendering; Vulkan loader present but no
  D3D/GL translation yet (`make bench` reports what exists).
- musl build not attempted.

### Environment notes

* Xvfb started automatically by the test runner for GUI cases.
* ASan found and we fixed: missing msvcrt export terminator, stub-info
  realloc use-after-free, XImage ABI offsets (my overlay struct had
  wrong member alignment), GetMessage timer starvation (pure pump(-1)),
  double-free in DestroyWindow.

### Fuzzing + bench (this session)

* `make fuzz`: fork-based mutation fuzzer over the PE loader core
  (map + relocations + export resolution + unmap), built against the
  ASan/UBSan objects. Campaign: 11 seeds x 1000 mutations = **22,000
  inputs, zero crashes**; malformed inputs are rejected loudly and
  cleanly (see the log spam in the runner for examples).
* `winnux bench` now measures real things: pe-map+reloc 34-36 us/image
  (3.4-3.6 GB/s), futex no-op wake ~0.15 us, checksummed memset ~7 GB/s.
* Vulkan: dlopen + two-stage entry resolution (global then instance
  level) implemented and exercised — vkCreateInstance returns
  VK_ERROR_INCOMPATIBLE_DRIVER on this box (no ICD), which is the honest
  result; the code path is proven by the raw-loader probe test. Surface
  + swapchain follow.

### Next

1. Wayland surface path (xdg_shell + shm present + seat input).
2. SEH x64 table-based unwinding (.pdata/.xdata) so guest `__try`/`__except`
   scope handlers actually run (crash capture already works).
3. Vulkan surface (Xlib) + swapchain once a GPU/ICD is available; D3D9
   translation start (shader decode can be developed headless).
4. Real-world app testing (Notepad-class tools, installers).
