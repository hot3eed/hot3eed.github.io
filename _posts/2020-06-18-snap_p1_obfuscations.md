---
title: "Reverse Engineering Snapchat (Part I): Obfuscation Techniques"
layout: post
---

# Reverse Engineering Snapchat (Part I): Obfuscation Techniques
2020-06-18 
<br />

When you have 200+ million daily users, you'll definitely want to keep your API private from spammers and co., so you'll have to keep a secret in the binary that authorizes it to make API calls to your server. 
Snapchat (as of version 10.81.6.81) does this by including an `X-Snapchat-Client-Auth-Token` header in each request, a typical one would look like:
<br />
```
v8:7841EAFE02CD9DE06AE8E41C6478D504:2B8115D1C5873C8BD5A3A9DDA7F976B21A672A643D8AB2AC91CE223C84BA5F9EB112B65B7C85AFD9CEA86A9DC36D5F6405B8D23B369A94A5657894207F09E432CBD21953F8E4F50E44373B59FB39270360DE5113FA983D1F06FF71A0D540488403A848D1C52A2421AF4341E6BBCD702F4921E5DC134ECCF99EDBD599EAA1AAA8556C6122334A63C86711740E58E453A7049FE94634DEC8FFE2E26C28780FFA46994818F7D0915E6DB3061188784D46D381CE2BF4D15E83BEC1ABFFE29207D2A58906CAC598AD314F368CF41E1892CA032859485DC99882F97D5064D4C7C5C2A4A4975C59530F4D0289EF4BC4E7CFC89FC8279038FB6E623C88A8AB38678F1D2757F7C0914C1A162E4F5B173E694109CD67E73762D8C090D8780714861DB883977D3B85D6F503D8D8CD5167B43A2DB18B79804841FE8064AD1A8078EAEF472698AD482AA77BC5D7EB012F0946DAFB923CFD10BA06675730EF338A96D1D0081B174BE5989B77FD07DCEDCDC635DEF1EE986F65798D87A358742F152AA929800FD5BA2CC29E
```

## Control flow obufscations:
Forget about doing static analysis on this binary. Here's what they do on a high level: the CFG (control flow graph) is destroyed (not flattened), dead code, library calls are mostly dynamic, and all symbols for the token generation function (let's call it `gen_token`) and its callees are stripped. They're implemented in C and not Objective-C for this reason, because you can always use the ObjC runtime against itself<sup>[1]</sup> (Trivia: they only started using Swift recently, but for other tasks.)

### Indirect branches and opaque predicates
Let's take a look at the very first block in `gen_token`. The block loads some values from different sections of the binary and then:
{% highlight asm %}
orr       w8,wzr,#0x3
cmp       x8,#0xb
orr       w9,wzr,#0x6
csel      x8,x9,x8,hi
adrp      x28,0x106941000
add       x28,x28,#0xe40 ; jump table
ldr       x8,[x28, x8, LSL #0x3]
br        x8
{% endhighlight %}

See the first two instructions. Why would they compare `x8` with `0xb` right after storing `0x3` in it? Opaque predicates<sup>[1]</sup>. The `csel` condition will always be false, but that doesn't matter, because as far as the disassembler is concerned, this is a condition, and conditions need to be evaluated at runtime. Replace every single jump (including legit conditions) with a similar block, and you've completely destroyed the CFG for any modern disassembler. Now Ghidra/IDA would be happy to display what it thinks is a small function with a tail call, which is in fact a huge function. I'll give Ghidra that it's able to calculate the address in `br x8` but only for the first block (because that's where it thinks the function ends). Now that's a plugin idea: use emulation to calculate all the addresses in indirect branches with opaque predicates, which would require an emulation. I actually worked for a bit on implementing this but then that's not even half the battle for this binary.

### Bogus instructions AKA dead code
Every few blocks you'll find a block that loads a global constant, does some complex-looking operations on it, then just discards it and branches to somewhere else. Those are just there to confuse you and are easily detectible once you see them for a couple of times, so it's not much of a hindrance.

### Dynamic library calls
To make the code as bland as possible, and to prevent you from making educated guesses when you see a call to `SecItemCopyMatching` for example, most library calls are dynamic.
So for example instead of a simple `bl SecItemCopyMatching`, they would do:

{% highlight asm %}
adrp x23 <address of SecItemCopyMatching>
{% endhighlight %}

Then, in another block they would:
{% highlight asm %}
blr x23
{% endhighlight %}

The disassembler doesn't know the value of `x23` here because, as stated above, it treats the block as if it doesn't block to the current function.

### Loop unrolling
When you have a loop that comes with a pre-determined/fixed counter, you can get rid of the counter, and hardcode the loop iterations. This comes at a cost of the binary size, and it's slightly faster than using a counter. Snap uses this technique in an encryption function. This block moves a huge array of bytes to another, notice how the offsets increment, replacing the counter:
{% highlight asm %}
ldr        w8,[sp, #0x278]
str        w8,[sp, #0x226c]
ldr        w8,[sp, #0x27c]
str        w8,[sp, #0x2268]
ldr        w8,[sp, #0x280]
str        w8,[sp, #0x2264]
ldr        w8,[sp, #0x284]
str        w8,[sp, #0x2260]
ldr        w8,[sp, #0x288]
str        w8,[sp, #0x225c]
ldr        w8,[sp, #0x28c]
str        w8,[sp, #0x2258]
ldr        w8,[sp, #0x290]
str        w8,[sp, #0x2254]
; and so on
{% endhighlight %}

### Joint functions
Suppose you have a function that fills some structure with the right data and another that converts bytes to ASCII:
{% highlight c %}
void set_struct_fields(some_struct *p);
void bin2ascii(char *in, char *out, size_t nbytes);
{% endhighlight %}

With a little effort you could intercept calls to both and understand what they do just by watching their behavior. Snapchat has quite a clever way of thwarting this. Instead of the two above, there would be:

{% highlight c %}
void joint_function(uint64_t function_id, void *retval, void *argv[]) {
    switch (function_id) {
        case SET_STRUCT_FIELDS_FI:
            // Get argument from argv
            set_struct_fields(p);
            break;
        case BINS2ASCII_FI:
            bin2sacii(in, out, nbytes);
            break;
        // etc
    }
}
{% endhighlight %}

`argv` would include all the arguments needed. Now strip all symbols, add the above obfuscations and you've got an unintelligble mammoth of a function. You would think that you could still trace all calls to the joint function and treat the `path_key` as an identifier to the function you're interested in. But breakpoints won't act as you'd expect them to. See next.

## The solution: not breakpoints (AKA anti-debugging measures)
Now most control flow obfuscation is against static analysis, using a debugger to get past the above would do it. Not so fast. Most functions call an anti-debugging function, which I named appropriately and whose signature is:

{% highlight c%}
uint64_t fuckup_debugging(/* some args */, void *func);
{% endhighlight %}

There's at least 9 such functions, all the same behavior. I haven't taken the time to reverse them but their behavior is clear. \
Software breakpoints work by patching the instruction at the designated address in memory. The patch is an instruction that triggers an interrupt that's handled by the parent process, the debugger<sup>[3]</sup>. That makes them easily detectable; if you have a checksum of what a certain area in memory looks like, a breakpoint in that area will invalidate the checksum. Or, you could look for the interrupt instruction's `brk` bytes in the binary. 

After doing its check, `fuckup_debugging` will return a `uint64_t`, its value which depends on whether there was a breakpoint detected. So actually there's only two possible values. Isn't that called a `bool`? Yes. But a boolean would be trivial to patch. But with an int you can't guess the "right" value. The `fuckup_debugging` caller uses the return value (I'll call it the `path_key`) to load an address from a jump table, if there was a breakpoint, the fetched address would lead to an infinite loop, leading the app to just keep loading with no feedback, which is the right way to do it.

## Data flow obufscations
Data obfuscation is one of the harder things to work with in this binary.
Here we have _lots_ of MBA (mixed-boolean arithmetic) and scratch arguments passed to functions just to distract you.

### Mixed-boolean arithmetic
One of the less resarched areas in obfuscation techniques is MBA (shoutout to the awesome [Quarkslab](https://quarkslab.com/) for their research on this and many other things). Those are typically used in cryptography but can be utilized for obufscation. Basically they're expressions that mix logical operations with pure arithmetic. For example, `x = (a ^ b) + (a & b)`.

The interesting thing about those here is identities, for example `x + y` can be re-written as `(x ^ y) + 2 * (x & y)`<sup>[5]</sup>. Now imagine how huge the simple `x + y` expression could get if you substituted each term recursively with its MBA equivalent, crazy stuff.

An example in assembly. All what that block does is `timestamp * 1000`:

{% highlight asm %}
add        x0,sp,#0x1b8             ; struct timeval *tval
mov        x1,#0x0                  ; struct timezonze *tzone
adrp       x8,0x109499000
ldr        x8,[x8, #0x1d0]
blr        x8                       ; gettimeofday(tval, tone)
ldr        x8,[sp, #0x1b8]          ; tval->tv_sec
mov        w9,#0x3e8
mul        x8,x8,x9
ldrsw      x9,[sp, #0x1c0]
lsr        x9,x9,#0x3
mov        x10,#0xf7cf
movk       x10,#0xe353, LSL #16
movk       x10,#0x9ba5, LSL #32
movk       x10,#0x20c4, LSL #48
umulh      x9,x9,x10
mov        x10,#0xe6b3
movk       x10,#0x7dba, LSL #16
movk       x10,#0xecfa, LSL #32
movk       x10,#0xd0e1, LSL #48
add        x9,x10,x9, LSR #0x4
orr        x11,x9,x8
lsl        x11,x11,#0x1
eor        x8,x9,x8
sub        x8,x11,x8
eor        x9,x8,x10
mov        x10,#0xe6b3
movk       x10,#0x7dba, LSL #16
movk       x10,#0xecfa, LSL #32
movk       x10,#0x50e1, LSL #48
bic        x8,x10,x8
sub        x8,x9,x8, LSL #0x1     ; effectively tv_sec *= 1000
{% endhighlight %}

### Scratch arguments
This one isn't very prevalent in the binary but it's still interesting to mention. I've seen it used in a function that reads the first 8 bytes at a pointer. It has the signature: 
{% highlight c  %}
uint64_t get_first_qword(uint64_t scratch1, void *src, uint64_t scratch2);
{% endhighlight %}
`scratch1` and `2` are overwritten without being used at all, again, there to slow you down a bit.

## Clever shit/time buyers
### In-house `memmove`?
To make your life even more miserable, Snap ocassionally deprives you of recognizing some basic standard lib functions, namely `memmove`, by implementing their own, or maybe just copying the source. You won't be very happy after spending a day or two reversing a function to find it's `memmove` in the end.
### Loading by overflowing
Another honorary mention. This one has a base address and an index and it loads bytes from an array using a loop. Instead of simply adding the base address to the counter to get the byte, they do a calculation that yields two big 64-bit integers that will overflow but whose sum will be equivalent to the simple calculation. So instead of:

{% highlight asm %}
add        x10, sp, #0x338             ;base
ldr        x9, [sp, #0x270]            ;counter
ldrb       w9, [x10, x9]              
{% endhighlight %}

They do:

{% highlight asm %}
add        x10, sp, #0x338              ;base
ldr        x9,[sp, #0x270]              ;counter
mov        x11,#0x5bdd
movk       x11,#0x7d38, LSL #16
movk       x11,#0x1e74, LSL #32
movk       x11,#0x6d7c, LSL #48
add        x9,x9,x11
mov        x12,#0x3f94
movk       x12,#0x7886, LSL #16
movk       x12,#0xf6b2, LSL #32
movk       x12,#0xb119, LSL #48
add        x9,x9,x12
sub        x9,x9,x11
add        x9,x9,#0x10
mov        x11,#0xd943
movk       x11,#0xb8b5, LSL #16
movk       x11,#0x5fd9, LSL #32
movk       x11,#0x6bd2, LSL #48       ; x11 = 0x6bd25fd9b8b5d943
sub        x9,x9,x11
sub        x9,x9,x12
add        x9,x10,x9                  ; x9 = 0x942da027b272bb75
ldrb       w9,[x9, x11]               ; overflowing sum but right stack offset
{% endhighlight %}

### __mod_init_func
In Mach-O binaries, functions whose pointers are in the `__mod_init_func` section run before `main`. Using `otool` to see how many of those are in Snap, we find a staggering _816_ functions:

{% highlight shell %}
$ otool -s __DATA __mod_init_func Snapchat
Snapchat:
Contents of (__DATA,__mod_init_func) section
0000000106819610	0042de58 00000001 0042de58 00000001
0000000106819620	0042de58 00000001 0042de58 00000001
0000000106819630	0042de58 00000001 0042de58 00000001
0000000106819640	0042de58 00000001 0042de58 00000001
0000000106819650	0042de58 00000001 0042de58 00000001
0000000106819660	0042de58 00000001 0042de58 00000001
0000000106819670	0042de58 00000001 0042de58 00000001
0000000106819680	0042de58 00000001 0042de58 00000001
0000000106819690	0042de58 00000001 0042de58 00000001
00000001068196a0	0042de58 00000001 0042de58 00000001
...and a lot more
{% endhighlight %}

Hmm, seems too much to count manually. Let's `wc` it:

{% highlight shell %}
$ otool -s __DATA __mod_init_func Snapchat | wc -l
     410
{% endhighlight %}

And since it's two function pointers per line, their actualy number is 816 (after discarding the first two lines). But wait, all of those point to the same function? They're probably using duplicates as a distraction and to make your job harder, let's see how many are there. After doing some regex to get the functions pointers, I found there's 769 _unique_ functions, still a huge number.

{% highlight shell %}
$ cat mod_init_func | sort -u | wc -l
     769
{% endhighlight %}

Some of those are dummy functions that do nothing useful. For example the very first one loads a constant, stores it on the stack, then discards it and returns:

{% highlight asm %}
sub        sp,sp,#0x10
adrp       x8,0x10641a000
add        x8,x8,#0x340
str        x8,[sp, #0x8]
add        sp,sp,#0x10
ret
{% endhighlight %}

Among those 769 functions some will definitely be doing some real initializations, and some could be there as another stealthy jailbreak/debugger detection. Filtering out the dummies should be easy, but we're still talking about 700+ function, so to find the ones you're interested in you'll have to have some idea about how Snap is doing it, so you can get there without having to sift throught all those functions.

## What's next
I'll probably do a part II on how to bypass all of this. 

[1]: https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/ObjCRuntimeGuide/Articles/ocrtHowMessagingWorks.html#//apple_ref/doc/uid/TP40008048-CH104-SW1
[2]: https://en.wikipedia.org/wiki/Opaque_predicate
[3]: https://eli.thegreenplace.net/2011/01/23/how-debuggers-work-part-1#id11
[4]: https://wiki.tcl-lang.org/page/Cryptographically+secure+random+numbers+using+%2Fdev%2Furandom
[5]: https://blog.quarkslab.com/what-theoretical-tools-are-needed-to-simplify-mba-expressions.html

