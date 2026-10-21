// tonhack.m — offline IL2CPP cheat + VIP unlock for BLEACH (com.klab.bleach) 18.1.1
//
// Build (on a Mac, arm64):
//   clang -dynamiclib -arch arm64 -miphoneos-version-min=12.0 \
//         -framework Foundation -framework UIKit -framework MachO \
//         -o tonhack.dylib tonhack.m -lobjc
//
// Install: drop into Payload/Bleach.app/Frameworks/ and load it from
// UnityFramework with:
//   LC_LOAD_DYLIB @executable_path/Frameworks/tonhack.dylib
//
// RVAs from Il2CppDumper v6.7.46 on
//   Payload/Bleach.app/Frameworks/UnityFramework.framework/UnityFramework
//   Payload/Bleach.app/Data/Managed/Metadata/global-metadata.dat
// class CharacterStatus : AdventEnemyLogicAi.IStatus   (TypeDefIndex 2750)
//
// No server. No encrypted config. No memory scanning. Named IL2CPP methods.
// ------------------------------------------------------------------ config

#define GOD_MODE              0
#define ONE_HIT_KILL          0
#define INVULNERABLE_DEFENCE  0
#define MAX_ATTACK            0
#define NO_REVIVAL            0
#define NO_HEAVY_ATTACK_LOCK  0

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

#import <Foundation/Foundation.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <objc/runtime.h>
#include <dispatch/dispatch.h>

// libSystem export; declared here because <libkern/OSCacheControl.h> is not
// guaranteed to be present in every SDK slice.
extern void sys_icache_invalidate(void *address, unsigned long size);

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
        uint32_t n = _dyld_image_count();
        for (uint32_t i = 0; i < n; i++) {
            const char *name = _dyld_get_image_name(i);
            if (name && strstr(name, "UnityFramework")) {
                const struct mach_header *h = _dyld_get_image_header(i);
                if (h) {
                    b = (uintptr_t)h + _dyld_get_image_vmaddr_slide(i);
                    TH_log("UnityFramework base = %p (%s)", (void *)b, name);
                    return b;
                }
            }
        }
        TH_log("UnityFramework not found among %u images", n);
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
    sys_icache_invalidate((void *)m, 16);
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
    sys_icache_invalidate((void *)out, 32);
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
    sys_icache_invalidate((void *)target, 16);
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
#define CHAIN_SET(fn)   ((orig_##fn) ? (orig_##fn) : real_##fn)
#define CHAIN_GET(fn)   ((orig_##fn) ? (orig_##fn) : real_##fn)
#define CHAIN_GETB(fn)  ((orig_##fn) ? (orig_##fn) : real_##fn)
#define CHAIN_VOID(fn)  ((orig_##fn) ? (orig_##fn) : real_##fn)

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

// ===================================================================
//                    VIP unlock  --  NSUserDefaults layer
// ===================================================================
//
// The iOSGods tweak (libbleachbravesoul.dylib) stores its cheat flags as
// plain booleans in the host app's own NSUserDefaults domain
// (Library/Preferences/com.klab.bleach.<suffix>.plist):
//
//   * "keyGodMode-switch" ... 9 named booleans, all False
//   * "N-switch" for N in {1..14, 20..27, 32,33,35,36,37} -- 27 booleans,
//     of which EXACTLY 3 were True (2, 3 and 4) and 24 False.
//
// Three enabled out of 27 is the "max active cheats" cap. The key names are
// built by the tweak with the format string "%@-switch", so every switch key
// ends in "-switch".
//
// Two layers are used, because either one alone can be bypassed:
//
//  1. PERSISTENCE. Every "-switch" key is written YES. The write path of the
//     toggle handler is what enforces the cap, so writing directly from
//     inside the process never goes through it. The plist therefore ends up
//     with every feature enabled.
//
//  2. RUNTIME. -[NSUserDefaults boolForKey:] / objectForKey: / setBool:forKey:
//     / setObject:forKey: are swizzled so that a "-switch" key can never be
//     read as NO and can never be written as NO. This holds even if the tweak
//     re-reads the flags later, resets them at launch, or re-applies its own
//     "max 3" rule from inside its handler.
//
// The swizzle is installed from this dylib's constructor, which runs before
// the tweak's own constructor when this dylib is loaded from UnityFramework
// ahead of libbleachbravesoul.dylib.
//
// Verified empirically -- sideload, run, pull the container again and confirm
// more than 3 come back True.

#include <objc/message.h>
#include <objc/runtime.h>

#define SEED_SWITCHES 1

static void TH_seed_switches(int round);

// The 9 named cheat switches (from the tweak's binary string table).
static const char *TH_NAMED_SWITCHES[9] = {
    "keyOneHitKill-switch",  "keyGodMode-switch",     "keyKillAll-switch",
    "keyFreezeEnemy-switch", "keyCoopMoveSpeed-switch",
    "keyCoopNoHeavyCooldown-switch", "keyCoopNoExtraCooldown-switch",
    "keyCoopComboDamage-switch", "keyCoopHealMultiplier-switch",
};

// Notification the tweak posts when a switch is toggled (from its binary
// string table). Re-posting it after a write makes the tweak re-apply the
// flags even if it only listens for its own event.
#define TH_TOGGLE_NOTIFICATION "kItemSwitchToggled"

static BOOL TH_is_switch_key(id key) {
    if (!key) return NO;
    if (![key isKindOfClass:[NSString class]]) return NO;
    return [(NSString *)key hasSuffix:@"-switch"];
}

// Original implementations, captured before the swizzle is installed.
static IMP g_origBoolForKey   = NULL;
static IMP g_origObjectForKey = NULL;
static IMP g_origSetBool      = NULL;
static IMP g_origSetObject    = NULL;

static BOOL TH_sw_boolForKey(id self, SEL _cmd, NSString *key) {
    if (TH_is_switch_key(key)) return YES;
    return ((BOOL (*)(id, SEL, NSString *))g_origBoolForKey)(self, _cmd, key);
}

static id TH_sw_objectForKey(id self, SEL _cmd, NSString *key) {
    id v = ((id (*)(id, SEL, NSString *))g_origObjectForKey)(self, _cmd, key);
    if (TH_is_switch_key(key) && [v isKindOfClass:[NSNumber class]] && ![v boolValue])
        return [NSNumber numberWithBool:YES];
    return v;
}

static void TH_sw_setBool(id self, SEL _cmd, BOOL value, NSString *key) {
    if (TH_is_switch_key(key)) value = YES;
    ((void (*)(id, SEL, BOOL, NSString *))g_origSetBool)(self, _cmd, value, key);
}

static void TH_sw_setObject(id self, SEL _cmd, id value, NSString *key) {
    if (TH_is_switch_key(key) && [value isKindOfClass:[NSNumber class]] && ![value boolValue])
        value = [NSNumber numberWithBool:YES];
    ((void (*)(id, SEL, id, NSString *))g_origSetObject)(self, _cmd, value, key);
}

static int g_swizzled = 0;

static void TH_install_swizzle(void) {
    if (g_swizzled) return;
    Class cls = objc_getClass("NSUserDefaults");
    if (!cls) { TH_log("NSUserDefaults class not found"); return; }

    struct { const char *name; IMP *slot; } targets[4] = {
        { "boolForKey:",    &g_origBoolForKey   },
        { "objectForKey:",  &g_origObjectForKey },
        { "setBool:forKey:", &g_origSetBool     },
        { "setObject:forKey:", &g_origSetObject },
    };

    for (int i = 0; i < 4; i++) {
        SEL sel = sel_registerName(targets[i].name);
        Method m = class_getInstanceMethod(cls, sel);
        if (!m) { TH_log("NSUserDefaults has no %s", targets[i].name); continue; }
        IMP custom = (IMP)(i == 0 ? (IMP)TH_sw_boolForKey
                           : i == 1 ? (IMP)TH_sw_objectForKey
                           : i == 2 ? (IMP)TH_sw_setBool
                                    : (IMP)TH_sw_setObject);
        *(targets[i].slot) = method_getImplementation(m);
        method_setImplementation(m, custom);
    }
    g_swizzled = 1;
    TH_log("NSUserDefaults swizzled (boolForKey/objectForKey/setBool/setObject)");
}

// The tweak rewrites its own flags from time to time (launch sync, menu
// interaction, its own "max 3" rule). Every write to the defaults is a
// signal to re-assert the YES state, so the flip is undone as soon as it
// happens instead of waiting for the next heartbeat.
static void TH_defaults_changed(NSNotification *note) {
    (void)note;
    TH_seed_switches(-1);
}

static void TH_watch_defaults(void) {
    [[NSNotificationCenter defaultCenter]
        addObserverForName:NSUserDefaultsDidChangeNotification
                    object:nil
                     queue:[NSOperationQueue mainQueue]
                usingBlock:^(NSNotification *n) { TH_defaults_changed(n); }];
}

// Read the *stored* value, bypassing the swizzle.
static id TH_raw_value(NSUserDefaults *d, NSString *key) {
    if (g_origObjectForKey)
        return ((id (*)(id, SEL, NSString *))g_origObjectForKey)(d, sel_registerName("objectForKey:"), key);
    return [d objectForKey:key];
}

static BOOL TH_raw_is_yes(NSUserDefaults *d, NSString *key) {
    id v = TH_raw_value(d, key);
    if (!v) return NO;
    if (![v isKindOfClass:[NSNumber class]]) return NO;
    return [v boolValue];
}

// Force one key to YES. Returns YES when the stored value actually changed.
static BOOL TH_force_yes(NSUserDefaults *d, NSString *key, BOOL createIfMissing) {
    id v = TH_raw_value(d, key);
    if (!v) {
        if (!createIfMissing) return NO;
        [d setBool:YES forKey:key];
        return YES;
    }
    if ([v isKindOfClass:[NSNumber class]] && [v boolValue]) return NO;
    [d setBool:YES forKey:key];
    return YES;
}

// ------------------------------------------------------------ seeding

static int g_seeding = 0;

static void TH_seed_switches(int round) {
    if (g_seeding) return;               // re-entrancy guard
    g_seeding = 1;

    @try {
    @autoreleasepool {
        NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
        if (!d) { g_seeding = 0; return; }

        NSMutableArray *changed = [NSMutableArray array];

        // (a) every "-switch" key that already exists in the app's domain.
        //     Only existing keys are touched here, so features that do not
        //     exist in this build are never invented -- inventing them could
        //     inflate the tweak's "how many switches are on" counter.
        NSDictionary *rep = [d dictionaryRepresentation];
        NSMutableArray *existing = [NSMutableArray array];
        for (NSString *k in rep) {
            if (TH_is_switch_key(k)) [existing addObject:k];
        }
        for (NSString *k in existing) {
            if (TH_force_yes(d, k, NO)) [changed addObject:k];
        }

        // (b) the 9 named switches: always materialised, even if the tweak
        //     has not created them yet.
        for (int i = 0; i < 9; i++) {
            NSString *k = [NSString stringWithUTF8String:TH_NAMED_SWITCHES[i]];
            if (TH_force_yes(d, k, YES)) [changed addObject:k];
        }

        [d synchronize];

        // The tweak applies its flags when it receives its own toggle event.
        // Re-post it so a write that happened outside the tweak's menu is
        // picked up as well.  Only on the first rounds, and never from the
        // change-notification path (that would feed the tweak's handler).
        if (round >= 0 && round <= 2 && changed.count) {
            for (NSString *k in changed) {
                [[NSNotificationCenter defaultCenter]
                    postNotificationName:TH_TOGGLE_NOTIFICATION
                                  object:k
                                userInfo:[NSDictionary dictionaryWithObject:k forKey:@"key"]];
            }
        }

        TH_log("seed round %d: %lu existing switch key(s), %lu changed to YES",
               round, (unsigned long)[existing count], (unsigned long)[changed count]);
    }
    } @catch (NSException *e) {
        TH_log("seed aborted: %s", e.reason ? [e.reason UTF8String] : "?");
    }

    g_seeding = 0;
}

// Print the current switch state -- the fastest way to confirm on device
// that the layer is live.
static void TH_dump_switches(void) {
    @try {
    @autoreleasepool {
        NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
        NSDictionary *rep = [d dictionaryRepresentation];
        NSMutableArray *keys = [NSMutableArray array];
        for (NSString *k in rep) {
            if (TH_is_switch_key(k)) [keys addObject:k];
        }
        [keys sortUsingSelector:@selector(compare:)];
        for (NSString *k in keys) {
            id raw = TH_raw_value(d, k);
            id live = [d objectForKey:k];
            TH_log("switch %-34s stored=%-5s live=%-5s",
                   [k UTF8String],
                   [raw isKindOfClass:[NSNumber class]] ? ([raw boolValue] ? "YES" : "NO") : "-",
                   [live isKindOfClass:[NSNumber class]] ? ([live boolValue] ? "YES" : "NO") : "-");
        }
        TH_log("switch dump done: %lu key(s)", (unsigned long)[keys count]);
    }
    } @catch (NSException *e) {
        TH_log("dump aborted: %s", e.reason ? [e.reason UTF8String] : "?");
    }
}

// ---------------------------------------------------------------- install

static int g_installed = 0;

static void th_install(void) {
    if (g_installed) return;
    if (!th_base()) { TH_log("UnityFramework not mapped yet"); return; }
#if !(GOD_MODE || ONE_HIT_KILL || INVULNERABLE_DEFENCE || MAX_ATTACK || NO_REVIVAL || NO_HEAVY_ATTACK_LOCK)
    // No IL2CPP hooks requested: only the NSUserDefaults layer.
    g_installed = 1;
    TH_log("installed (NSUserDefaults layer only)");
    return;
#endif
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
    // The swizzle goes in first so that every later read of a switch key --
    // including the tweak's own constructor and its change handler -- already
    // sees YES.
    TH_install_swizzle();

#if SEED_SWITCHES
    TH_watch_defaults();
    TH_seed_switches(0);
    TH_dump_switches();
#endif

    th_install();

#if TH_RETRY
    for (int i = 1; i <= 12 && !g_installed; i++) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(250 * i) * NSEC_PER_MSEC),
                       dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            th_install();
        });
    }

    // The tweak rewrites its own flags during launch (it syncs its config
    // with its server and restores the persisted "max 3" state). Re-seed for
    // a while after launch to win that race, then keep a slow heartbeat.
    for (int i = 1; i <= 60; i++) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(500 * i) * NSEC_PER_MSEC),
                       dispatch_get_main_queue(), ^{
#if SEED_SWITCHES
            TH_seed_switches(i);
#endif
        });
    }
    for (int i = 1; i <= 24; i++) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5000 * i) * NSEC_PER_MSEC + 30000000000LL),
                       dispatch_get_main_queue(), ^{
#if SEED_SWITCHES
            TH_seed_switches(60 + i);
#endif
        });
    }
#endif
}
