// tonhack.m — offline IL2CPP cheat for BLEACH (com.klab.bleach) 18.1.1
//
// Build (on a Mac, arm64):
//   clang -dynamiclib -arch arm64 -miphoneos-version-min=12.0 \
//         -framework Foundation -framework UIKit -framework MachO \
//         -o tonhack.dylib tonhack.m -lobjc
//
// Install: drop into Payload/Bleach.app/Frameworks/ and add to UnityFramework:
//   LC_LOAD_DYLIB @executable_path/Frameworks/tonhack.dylib
//   LC_RPATH    @executable_path/Frameworks
//
// RVAs from Il2CppDumper v6.7.46 on
//   Payload/Bleach.app/Frameworks/UnityFramework.framework/UnityFramework
//   Payload/Bleach.app/Data/Managed/Metadata/global-metadata.dat
// class CharacterStatus : AdventEnemyLogicAi.IStatus   (TypeDefIndex 2750)
//
// No server. No encrypted config. No memory scanning. Named IL2CPP methods.
// ------------------------------------------------------------------ config

#define GOD_MODE              1
#define ONE_HIT_KILL          1
#define INVULNERABLE_DEFENCE  1
#define MAX_ATTACK            1
#define NO_REVIVAL            1
#define NO_HEAVY_ATTACK_LOCK  1

// Roster index of the player. 0 is normally the leader. If the wrong character
// turns unkillable, keep TH_LOG at 1 and read the log line for each status:
// it prints index / hp / hpMax so you can pick the right slot.
#define PLAYER_INDEX          0
#define TH_LOG                1
#define TH_RETRY              1   // retry install a few times if UF is late

// ----------------------------------------------------------------- RVAs

#define RVA_get_Index                 0x0291CBB0
#define RVA_get_HP                    0x02A48AF4
#define RVA_set_HP                    0x02A4A690
#define RVA_get_HPMax                 0x02A4C1C0
#define RVA_set_HPMax                 0x02A4DCF0
#define RVA_get_Attack                0x0291CDB0
#define RVA_set_Attack                0x0291D5F8
#define RVA_get_Defence               0x02A67208
#define RVA_set_Defence               0x02A67B98
#define RVA_get_CanRevival            0x02A09A64
#define RVA_get_IsForbiddenHeavy      0x02A04898
#define RVA_UpdateHp                  0x02A284DC

// ---------------------------------------------------------------- includes

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <objc/runtime.h>
#include <dispatch/dispatch.h>

static void TH_log(const char *fmt, ...) {
    if (!TH_LOG) return;
    va_list ap; va_start(ap, fmt);
    fprintf(stderr, "[tonhack] "); vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}

// ------------------------------------------------------------ base address

static uintptr_t th_base(void) {
    static uintptr_t b = 0;
    if (!b) {
        const struct mach_header *h = _dyld_get_image_header("UnityFramework");
        if (!h) return 0;
        b = (uintptr_t)h + _dyld_get_image_vmaddr_slide(h);
        TH_log("UnityFramework base = %p", (void *)b);
    }
    return b;
}

#define VA(rva) (th_base() + (uintptr_t)(rva))

// ------------------------------------------- minimal AArch64 inline hook
//
// prologue (16 B) :  ldr x16, #8 ; br x16 ; .quad replacement
// trampoline(32 B) :  adr x17, #8 ; <4 saved words> ; b <orig+16> ; .quad orig+16

static void th_make_stub(void *replacement, uint8_t *m) {
    uint32_t hdr[2] = { 0x58000050u, 0xD61F0200u };
    memcpy(m, hdr, 8);
    memcpy(m + 8, &replacement, 8);
    __builtin___clear_cache((char *)m, (char *)m + 16);
}

static void th_make_tramp(void *target, uint8_t *out) {
    uintptr_t a  = (uintptr_t)target;
    uintptr_t bk = a + 16;
    uint32_t adr = 0x10000051u;              /* adr x17, #8 */
    uint32_t saved[4];
    memcpy(saved, (void *)a, 16);
    int64_t  off = (int64_t)(bk - ((uintptr_t)out + 20));
    uint32_t br  = 0x14000000u | (uint32_t)((off >> 2) & 0x03FFFFFF);
    memcpy(out + 0,  &adr,       4);
    memcpy(out + 4,  &saved[0],  4);
    memcpy(out + 8,  &saved[1],  4);
    memcpy(out + 12, &saved[2],  4);
    memcpy(out + 16, &saved[3],  4);
    memcpy(out + 20, &br,        4);
    memcpy(out + 24, &bk,        8);
    __builtin___clear_cache((char *)out, (char *)out + 32);
}

// Returns 0 on success, -2 if the target doesn't look like a function.
// A wrong RVA degrades to a logged refusal instead of a crash.
static int th_hook(void *target, void *replacement, void **out_tramp) {
    if (!target) return -1;
    uint32_t p0, p1;
    memcpy(&p0, (uint8_t *)target + 0, 4);
    memcpy(&p1, (uint8_t *)target + 4, 4);
    (void)p1;
    int frame = ((p0 & 0xFFC003E0) == 0xA98003E0) ||
                ((p0 & 0xFF0003FF) == 0xD10003FF);
    if (!frame) {
        TH_log("REFUSING %p: prologue %08x is not a frame setup", target, p0);
        return -2;
    }
    uint8_t *tr = (uint8_t *)malloc(32);
    if (!tr) return -3;
    th_make_tramp(target, tr);
    uint8_t stub[16];
    th_make_stub(replacement, stub);
    memcpy((void *)target, stub, 16);
    __builtin___clear_cache((char *)target, (char *)target + 16);
    if (out_tramp) *out_tramp = tr;
    return 0;
}

// ------------------------------------------------------------ IL2CPP types

typedef int32_t (*fn_getIndex)(void *);
typedef int32_t (*fn_getInt)(void *);
typedef void    (*fn_setInt)(void *, int32_t);
typedef void    (*fn_void)(void *);
typedef uint8_t (*fn_getBool)(void *);

// true entry points (before patching)
static fn_getIndex real_getIndex;
static fn_getInt    real_getHP, real_getHPMax, real_getAttack, real_getDefence;
static fn_getBool   real_getCanRevival, real_getForbiddenHeavy;
static fn_void      real_UpdateHp;
static fn_setInt    real_setHP, real_setHPMax, real_setDefence, real_setAttack;

// call a hook chain if it exists, otherwise the real function
#define CHAIN_SET(fn)   ((fn) ? (fn)   : real_set##fn)
#define CHAIN_GET(fn)   ((fn) ? (fn)   : real_get##fn)
#define CHAIN_GETB(fn)  ((fn) ? (fn)   : real_get##fn)
#define CHAIN_VOID(fn)  ((fn) ? (fn)   : real_##fn)

// trampolines (after patching) -- may be NULL if a hook was refused
static fn_getIndex orig_getIndex;
static fn_getInt    orig_getHP, orig_getHPMax, orig_getAttack, orig_getDefence;
static fn_setInt    orig_setHP, orig_setHPMax, orig_setAttack, orig_setDefence;
static fn_getBool   orig_getCanRevival, orig_getForbiddenHeavy;
static fn_void      orig_UpdateHp;

static inline int is_player(void *self) {
    fn_getIndex f = orig_getIndex ? orig_getIndex : real_getIndex;
    return f && f(self) == PLAYER_INDEX;
}

// ------------------------------------------------------------------ hooks

static void h_setHP(void *self, int32_t v) {
    CHAIN_SET(setHP)(self, v);
#if GOD_MODE
    if (is_player(self)) {
        int32_t mx = CHAIN_GET(getHPMax)(self);
        if (mx > 0 && CHAIN_GET(getHP)(self) < mx) orig_setHP(self, mx);
    }
#endif
}

static void h_setHPMax(void *self, int32_t v) {
    if (ONE_HIT_KILL && !is_player(self)) v = 1;
    CHAIN_SET(setHPMax)(self, v);
    if (INVULNERABLE_DEFENCE && is_player(self) && orig_setDefence) {
        orig_setDefence(self, INT32_MAX);
    }
}

static void h_setDefence(void *self, int32_t v) {
    if (INVULNERABLE_DEFENCE && is_player(self)) v = INT32_MAX;
    CHAIN_SET(setDefence)(self, v);
}

static void h_setAttack(void *self, int32_t v) {
    if (MAX_ATTACK && !is_player(self)) v = INT32_MAX;
    CHAIN_SET(setAttack)(self, v);
}

static void h_UpdateHp(void *self) {
    CHAIN_VOID(UpdateHp)(self);

    if (TH_LOG) {
        fn_getIndex gi = CHAIN_GET(getIndex);
        fn_getInt    gh = CHAIN_GET(getHP);
        fn_getInt    gm = CHAIN_GET(getHPMax);
        fn_getInt    ga = CHAIN_GET(getAttack);
        fn_getInt    gd = CHAIN_GET(getDefence);
        TH_log("status idx=%d hp=%d hpMax=%d atk=%d def=%d",
               gi ? gi(self) : -1, gh ? gh(self) : -1, gm ? gm(self) : -1,
               ga ? ga(self) : -1, gd ? gd(self) : -1);
    }

    if (GOD_MODE && is_player(self)) {
        int32_t mx = CHAIN_GET(getHPMax)(self);
        if (mx > 0 && CHAIN_GET(getHP)(self) < mx && orig_setHP) orig_setHP(self, mx);
    }
}

static uint8_t h_getCanRevival(void *self) {
    if (NO_REVIVAL) return 0;
    return CHAIN_GETB(getCanRevival)(self);
}

static uint8_t h_getForbiddenHeavy(void *self) {
    if (NO_HEAVY_ATTACK_LOCK) return 0;
    return CHAIN_GETB(getForbiddenHeavy)(self);
}

// ---------------------------------------------------- UserDefaults seeding
//
// Confirmed from an iMazing container dump of com.klab.bleach 18.1.1
// (Library/Preferences/com.klab.bleach.<suffix>.plist):
//
//  * "keyGodMode-switch" ... 9 named booleans, all False
//  * "N-switch" for N in {1..14, 20..27, 32,33,35,36,37} -- 27 booleans,
//    of which EXACTLY 3 were True (2, 3 and 4) and 24 False.
//
// Three enabled out of 27 is the "max active cheats" cap, persisted as plain
// booleans in the app's own NSUserDefaults. Nothing on the write path consults
// the server, so writing them to YES from inside the process enables
// everything without ever going through the toggle handler.
//
// Verified empirically -- sideload, run, pull the container again and confirm
// more than 3 come back True.

#include <objc/message.h>

#define SEED_SWITCHES 1
#define SEED_RANGE_FROM 1
#define SEED_RANGE_TO   37      // covers the gaps (15-19, 28-31, 34) harmlessly

static void th_seed_switches(int round) {
    Class dfltCls = objc_getClass("NSUserDefaults");
    if (!dfltCls) return;
    SEL selStd  = sel_registerName("standardUserDefaults");
    SEL selSet  = sel_registerName("setBool:forKey:");
    SEL selSync = sel_registerName("synchronize");

    id  (*std)(id, SEL)             = (id  (*)(id, SEL))objc_msgSend;
    void (*setB)(id, SEL, BOOL, id) = (void (*)(id, SEL, BOOL, id))objc_msgSend;
    BOOL (*sync)(id, SEL)           = (BOOL (*)(id, SEL))objc_msgSend;

    id d = std((id)dfltCls, selStd);
    if (!d) return;

    // the 9 named cheat switches
    const char *named[9] = {
        "keyOneHitKill-switch",  "keyGodMode-switch",     "keyKillAll-switch",
        "keyFreezeEnemy-switch", "keyCoopMoveSpeed-switch",
        "keyCoopNoHeavyCooldown-switch", "keyCoopNoExtraCooldown-switch",
        "keyCoopComboDamage-switch", "keyCoopHealMultiplier-switch",
    };
    int n = 0;
    for (int i = 0; i < 9; i++) { setB(d, selSet, YES, (id)named[i]); n++; }

    // the numeric feature switches -- this is where the cap actually lives
    char buf[32];
    for (int i = SEED_RANGE_FROM; i <= SEED_RANGE_TO; i++) {
        snprintf(buf, sizeof(buf), "%d-switch", i);
        setB(d, selSet, YES, (id)buf);
        n++;
    }
    sync(d, selSync);
    TH_log("seeded %d switches to YES (round %d)", n, round);
}

// ---------------------------------------------------------------- install

static int g_installed = 0;

static void th_install(void) {
    if (g_installed) return;
    if (!th_base()) { TH_log("UnityFramework not mapped yet"); return; }

    real_getIndex         = (fn_getIndex)VA(RVA_get_Index);
    real_getHP            = (fn_getInt)   VA(RVA_get_HP);
    real_getHPMax         = (fn_getInt)   VA(RVA_get_HPMax);
    real_getAttack        = (fn_getInt)   VA(RVA_get_Attack);
    real_getDefence       = (fn_getInt)   VA(RVA_get_Defence);
    real_getCanRevival    = (fn_getBool)  VA(RVA_get_CanRevival);
    real_getForbiddenHeavy= (fn_getBool)  VA(RVA_get_IsForbiddenHeavy);
    real_UpdateHp         = (fn_void)     VA(RVA_UpdateHp);
    real_setHP            = (fn_setInt)   VA(RVA_set_HP);
    real_setHPMax         = (fn_setInt)   VA(RVA_set_HPMax);
    real_setDefence       = (fn_setInt)   VA(RVA_set_Defence);
    real_setAttack        = (fn_setInt)   VA(RVA_set_Attack);

    void *t = NULL;

    if (th_hook((void *)real_UpdateHp, (void *)h_UpdateHp, &t) == 0)
        orig_UpdateHp = (fn_void)t;
    else { TH_log("UpdateHp hook failed -- aborting"); return; }

    if (th_hook((void *)VA(RVA_set_HP), (void *)h_setHP, &t) == 0)
        orig_setHP = (fn_setInt)t; else TH_log("set_HP hook failed");
    if (th_hook((void *)VA(RVA_set_HPMax), (void *)h_setHPMax, &t) == 0)
        orig_setHPMax = (fn_setInt)t; else TH_log("set_HPMax hook failed");
    if (th_hook((void *)VA(RVA_set_Defence), (void *)h_setDefence, &t) == 0)
        orig_setDefence = (fn_setInt)t; else TH_log("set_Defence hook failed");
    if (th_hook((void *)VA(RVA_set_Attack), (void *)h_setAttack, &t) == 0)
        orig_setAttack = (fn_setInt)t; else TH_log("set_Attack hook failed");
    if (th_hook((void *)VA(RVA_get_CanRevival), (void *)h_getCanRevival, &t) == 0)
        orig_getCanRevival = (fn_getBool)t;
    if (th_hook((void *)VA(RVA_get_IsForbiddenHeavy), (void *)h_getForbiddenHeavy, &t) == 0)
        orig_getForbiddenHeavy = (fn_getBool)t;

    g_installed = 1;
    TH_log("installed. player index = %d", PLAYER_INDEX);
}

__attribute__((constructor))
static void th_ctor(void) {
#if SEED_SWITCHES
    th_seed_switches(0);
#endif
    th_install();
#if TH_RETRY
    for (int i = 1; i <= 12 && !g_installed; i++) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(250 * i) * NSEC_PER_MSEC),
                       dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            th_install();
        });
    }
    // re-seed on the main queue: NSUserDefaults may be reset once the app
    // finishes its own setup, so write again shortly after launch.
    for (int i = 1; i <= 6; i++) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1200 * i) * NSEC_PER_MSEC),
                       dispatch_get_main_queue(), ^{
#if SEED_SWITCHES
            th_seed_switches(i);
#endif
        });
    }
#endif
}