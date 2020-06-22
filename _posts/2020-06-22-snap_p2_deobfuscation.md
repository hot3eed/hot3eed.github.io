---
title: "Reverse Engineering Snapchat (Part II): Deobfuscating the Undeobfuscatable"
layout: post
---

# Reverse Engineering Snapchat (Part II): Deobfuscating the Undeobfuscatable
2020-06-22

# Black box
Many Hackernews users suggested using emulation to generate the token, treating the whole thing as a black box. The problem with this solution as I mentioned in a comment is that there's way too many real device dependencies. `X-Snapchat-Client-Auth-Token` isn't random gibberish. It contains _lots_ of info about the device, encrypted. Even if you use Corellium, I'll just leave it at saying that the chances of it working are slim. I don't see an alternative to reversing it.

# Deoptimizing optimizations
First of all how is all this monstrosity achieved? When you compile `hello.c` using `clang`, `clang` is just the front end, `llvm` is the real deal; meaning `clang` takes the C source and converts it to an intermediate representation (IR)<sup>[1]</sup>, `llvm` then interprets this IR, optimizes and compiles it to machine code. The advantage of this system is that the backend remains language-agonstic, you just write an LLVM-IR-compatible-front end for each language and leave the rest to `llvm`. Now what we're interested in is optimizations AKA optimization passes. `llvm` operates on the IR to generate more efficient code, which might look a bit different in assembly than what you expect.
That's where obfuscation comes; instead of actually optimizing the code, we can change it however we want as long as we keep the semantics. That's how `O-LLVM`<sup>[2]</sup> works; at the compiler level, because no one can maintain source code like that. (The team behind O-LLVM is now acquired by Snap <sup>[3]</sup>) 
If we understand the obfuscations can't we just do the reverse and generate something that resembles the original assembly? As well articulated by one Hackernews user<sup>[4]</sup>, obfuscation is mostly lossy; deobfuscate all you want (many cool libraries<sup>[5]</sup> allow you to do this), but you're way better off getting your hands dirty with the binary directly.

# "Evan Spiegel Hates This Trick!": or, How to Bypass the Breakpoint Check
This might end my Snapchat reversing career (or the whole post really). One of the biggest hurdles with this binary is `fuckup_debugging`. You won't be able to do any kind of dynamic analysis (which is the only way to go in this binary in my opinion) because of it. And you can't patch `fuckup_debugging` to return the right `path_key` so that it takes the right execution and not the infinite loop because there are anti-tamepring checks to stop you from communicating with the server in a modified binary. But first how do you even get the right `path_key`, by defnition you'll have to set a breakpoint so that you can get to `fuckup_debugging` in the first place? Is it a dead lock? Let's see it in action:
Here we're in the function that returns the token, this is the block that calls `fuckup_debugging`, I know that because when I debug it, the block right after that is an infinite loop.

{% highlight asm %}
mov        x8,#0x4458
movk       x8,#0x1e6, LSL #16
movk       x8,#0x1, LSL #32
movk       x8,#0x0, LSL #48
mov        x9,#0x4714
movk       x9,#0x1e6, LSL #16
movk       x9,#0x1, LSL #32
movk       x9,#0x0, LSL #48
add        x1,x8,x27                    ; arg1 = func pointer
add        x2,x9,x27                    ; arg2 = another func pointer
mov        w0,#0xad51 
movk       w0,#0xeb37, LSL #16          ; arg3 = don't care
blr        x24                          ; fuckup_debugging called
adrp       x8,0x109e5b000
ldr        w8,[x8, #0x6a8]
eor        w8,w8,w0                     ; returned path_key
cmp        x8,#0xb
orr        w9,wzr,#0x6
csel       x8,x9,x8,hi
ldr        x8,[x28, x8, LSL #0x3]
br         x8
{% endhighlight %}

So how do you "hide" breakpoints from `fuckup_debugging`? 
1. Set a breakpoint right before it's called. 
2. Disable this breakpoint (I disable all of them just in case):
    ```
    (lldb) br dis
    ```
3. _Single_ step inside `fuckup_debugging`.
    ```
    (lldb) si
    ```
4. Now as far as `fuckup_debugging` is concerned, no breakpoints exist. 
5. Set a breakpoint before it returns and stop at it:
    ```
    (lldb) b <you know where>
    (lldb) c
    ```

6. Now you have the correct `path_key` in `x0`.
7. Profit.

A couple of gotchas here: 
1. If you got smart like I did and after disabling all breakpoints, stepped over `fuckup_debugging` using `(lldb) ni` instead of single stepping, you'll get an infinite loop, because you've just set another breakpoint. That's because stepping over is essentially a breakpoint at the address of the next instruction. While single stepping has a sweet little `ptrace` command of its own (`PTRACE_SINGLESTEP`)<sup>[6]</sup>, or in other words it executes at the CPU level, no code patching.
2. The weakness of `fuckup_debugging` is that it doesn't check breakpoints for itself. That's why you'd be able to set a breakpoints inside it harmlessly. There, a new challenge for future Snap reverse engineers after they patch this.

Now we've bypassed one breakpoint check for one function. Not every function in token generation is breakpoint-checked. But now for every check that you bypass using the above method, you can add a comment with the correct path key. So in the future it will be a matter of: 

{% highlight shell %}
(lldb) ni
(lldb) po $x0 = <path_key>
{% endhighlight %}

We stepped over `fuckup_debugging` and patched the return value on the fly. We're a bit slowed down because we'll have to do this with every patched function, but now we can at least do some real debugging.

# Getting what you want
Here's what happens on a very high level with the token. We have the joint function `gen_token`, which calls `set_token_params`, which is a mammoth joint function that calls _many_ other functions. Then the token is encrypted and returned from `gen_token`. To get info like this, you have to spend some time on the binary and make educated guesses until you have a rough big picture, then you can go for something specific, or a bottom-up approach to be concise. Let's go over an example of how you would reverse a specific token parameter.

## Anchor addresses
Having bookmarks in critical areas of the binary will save you lots of time and headache. For example I had bookmarks where the token params are being written, right before the token is encrypted, etc. That way I can start working on a certain parameter just by knowing its offset in the token structure, since that's the closest trace I know to where it's generated. But how do you find these anchor addresses in the first place?

## Watchpoints are underrated
If you asked me to give you _only_ one word that will solve more than half of your problems with the Snap binary, I would tell you: watchpoints. For example you have no idea where to start with anything, but you know that `gen_token` returns the token's pointer, so that's your lead. You then trace `gen_token` before it returns, and you find that this pointer is actually written to by another function before being returned by `gen_token`, say the equivalent C code:

{% highlight c %}
char *gen_token() {
    // Do stuff

    char token_out[TOKEN_LEN];
    real_deal(token_out);

    return token_out;
}
{% endhighlight %}

Now before `real_deal` is called, you set a watchpoint on `token_out`, disable all breakpoints so that `fuckup_debugging` is happy, continue execution, then the watchpoint will stop the process as it's being written to/read from, getting you to a possibly critical point of the code that you can use as an anchor. There's my second ace with the Snap binary.

{% highlight shell %}
(lldb) w s e -w write -- $x0
(lldb) c
... Now it will stop as soon as the address at $x0 is accessed and you have your anchor address.
{% endhighlight %}


## No trick is too dirty
Watchpoints are nice and all, but what about registers? You can't set a watchpoints on those, or in theory you could, but that's for another time. So what if the value you're interested in is in a register? The answer is an execution trace and a text editor that supports regex.

Suppose we're in `set_token_params` and we know that the value we're interested in is in `x2`:

{% highlight asm %}
ldr        x9,[sp, #0x80]	; token parameter offset
str        x2,[x9]		; token parameter	
; other instructions..
{% endhighlight %}

Since that's the start of the block and there's no CFG, we have no idea where `x2` came from. 

What I did is I generated an execution trace using Frida's Stalker<sup>[7]</sup> from a point near `set_token_params` enough and one that I know isn't policed by `fuckup_debugging`; because Frida patches instructions to hook to functions, which will trigger the breakpoints check. Now I had a sequential execution trace. Then I used a good old text editor to find the above block, and searched for points before it where `x2` is written to, where the source of the data is. 

## Dreams of Assembly
Once you find that a certain paramter is generated by the function `gen_param1`, I see no other way but to reverse it to its high level source code equivalent. I see C (haha) as the best fit for this as you can accurately translate data structures/types from assembly to C. And as close as C is to the CPU, you still have to know how struct alignment works, make educated guesses about certain values and their types, and keep track of all stack offsets. I had dreams of assembly instructions while working on this binary, no shit.

## MBA, again
MBA expressions are the trickiest thing in this binary. The latest research<sup>[8]</sup> on MBA says that there are effectively two ways to simplify MBA expressions. Let's explain them then give an example from the binary.

### Synthesis
In this method<sup>[9]</sup> you treat the whole expression as a black box "oracle", you give it input, observe the output, and try to generate a function simulating that behavior. 
The biggest problem with this is that it's impractical for complex expressions<sup>[8]</sup>.

### Re-write rules
In this method<sup>[8]</sup> all the rules for simplification is hardcoded, so for example you have a rule that says:
`(x | y) - y + (~x & y) == x ^ y`.
Then you try to match the rules with the expression recursively, after which you use an SMT solver to prove that the original expressions is identical to the simplified tone.
The problem with this is that the rules aren't universal like boolean/algebraic simplification, so it won't be able to handle expressions outside the hardcoded ones.

### Standing on the shoulders of giants
The first step to this is extracting the expressions from the binary, we can do it using symbolic execution<sup>[10]</sup>. Which is basically a way of executing the binary where we don't assign concrete values to variables, only symbols. A good fit for this is the awesome Triton<sup>[11]</sup> framework. After extracting the expressions, for synthesis you could still use Triton<sup>[12]</sup>, and for re-write rules there exists SSPAM<sup>[13]</sup> by Quarkslab, which is Python 2 only.

### MBA simplification example
This example involves a 120+ instruction block, whose input is two values from the stack, and whose output is in 4 registers. The trickiest output is in x27, so we'll do that one. First we need to extract the expressions. We symbolize the block's input using `Triton.symbolizeMemory`, then after emulating the block, we get the full expression in the register using `Triton.getSymbolicRegister(x27).regAst().unroll()`, which, brace yourselves, prints to:

{% highlight python %}
((((((((0x431e33362537db49 | (~((~(0xbac03a4c7e26a10c ^ ((0xbac03a4c7e26a10c & (~(bss_val1) & 0xffffffffffffffff)) | (bss_val1 & (~(0xbac03a4c7e26a10c) & 0xffffffffffffffff)))) & 0xffffffffffffffff)) & 0xffffffffffffffff)) & 0xc92460b4173d8ad1) | ((~((0x431e33362537db49 | (~((~(0xbac03a4c7e26a10c ^ ((0xbac03a4c7e26a10c & (~(bss_val1) & 0xffffffffffffffff)) | (bss_val1 & (~(0xbac03a4c7e26a10c) & 0xffffffffffffffff)))) & 0xffffffffffffffff)) & 0xffffffffffffffff))) & 0xffffffffffffffff) & (~(0xc92460b4173d8ad1) & 0xffffffffffffffff))) ^ ((0xc92460b4173d8ad1 & (~((((0x431e33362537db4a | (~(bss_val1) & 0xffffffffffffffff)) - (~(bss_val1) & 0xffffffffffffffff)) & 0xffffffffffffffff)) & 0xffffffffffffffff)) | ((((0x431e33362537db4a | (~(bss_val1) & 0xffffffffffffffff)) - (~(bss_val1) & 0xffffffffffffffff)) & 0xffffffffffffffff) & (~(0xc92460b4173d8ad1) & 0xffffffffffffffff)))) | (~(((0x431e33362537db49 | (~((~(0xbac03a4c7e26a10c ^ ((0xbac03a4c7e26a10c & (~(bss_val1) & 0xffffffffffffffff)) | (bss_val1 & (~(0xbac03a4c7e26a10c) & 0xffffffffffffffff)))) & 0xffffffffffffffff)) & 0xffffffffffffffff)) | (~((((0x431e33362537db4a | (~(bss_val1) & 0xffffffffffffffff)) - (~(bss_val1) & 0xffffffffffffffff)) & 0xffffffffffffffff)) & 0xffffffffffffffff))) & 0xffffffffffffffff)) | 0x253a41858a5c76d6) - ((((((0x431e33362537db49 | (~((~(0xbac03a4c7e26a10c ^ ((0xbac03a4c7e26a10c & (~(bss_val1) & 0xffffffffffffffff)) | (bss_val1 & (~(0xbac03a4c7e26a10c) & 0xffffffffffffffff)))) & 0xffffffffffffffff)) & 0xffffffffffffffff)) & 0xc92460b4173d8ad1) | ((~((0x431e33362537db49 | (~((~(0xbac03a4c7e26a10c ^ ((0xbac03a4c7e26a10c & (~(bss_val1) & 0xffffffffffffffff)) | (bss_val1 & (~(0xbac03a4c7e26a10c) & 0xffffffffffffffff)))) & 0xffffffffffffffff)) & 0xffffffffffffffff))) & 0xffffffffffffffff) & (~(0xc92460b4173d8ad1) & 0xffffffffffffffff))) ^ ((0xc92460b4173d8ad1 & (~((((0x431e33362537db4a | (~(bss_val1) & 0xffffffffffffffff)) - (~(bss_val1) & 0xffffffffffffffff)) & 0xffffffffffffffff)) & 0xffffffffffffffff)) | ((((0x431e33362537db4a | (~(bss_val1) & 0xffffffffffffffff)) - (~(bss_val1) & 0xffffffffffffffff)) & 0xffffffffffffffff) & (~(0xc92460b4173d8ad1) & 0xffffffffffffffff)))) | (~(((0x431e33362537db49 | (~((~(0xbac03a4c7e26a10c ^ ((0xbac03a4c7e26a10c & (~(bss_val1) & 0xffffffffffffffff)) | (bss_val1 & (~(0xbac03a4c7e26a10c) & 0xffffffffffffffff)))) & 0xffffffffffffffff)) & 0xffffffffffffffff)) | (~((((0x431e33362537db4a | (~(bss_val1) & 0xffffffffffffffff)) - (~(bss_val1) & 0xffffffffffffffff)) & 0xffffffffffffffff)) & 0xffffffffffffffff))) & 0xffffffffffffffff)) & 0x253a41858a5c76d6)) & 0xffffffffffffffff)
{% endhighlight %}

The real expression is less scary than that because Triton adds bit masks. Let's see what SSPAM has to say:

{% highlight shell %}
$ sspam "`cat x27_exprs`"
((((((4836359357488159561L | (~ (~ (13456819786791428364L ^ ((13456819786791428364L & (~ bss_val1)) | (bss_val1 & 4989924286918123251L)))))) & 14493815827385387729L) | ((~ (4836359357488159561L | (~ (~ (13456819786791428364L ^ ((13456819786791428364L & (~ bss_val1)) | (bss_val1 & 4989924286918123251L))))))) & 3952928246324163886L)) ^ ((14493815827385387729L & (~ ((- (~ bss_val1)) + (4836359357488159562L | (~ bss_val1))))) | (((- (~ bss_val1)) + (4836359357488159562L | (~ bss_val1))) & 3952928246324163886L))) | (~ ((4836359357488159561L | (~ (~ (13456819786791428364L ^ ((13456819786791428364L & (~ bss_val1)) | (bss_val1 & 4989924286918123251L)))))) | (~ ((- (~ bss_val1)) + (4836359357488159562L | (~ bss_val1))))))) ^ 2682528569860323030L)
{% endhighlight %}

That's not too good. So SSPAM, the only tool that I know to exist for MBA re-write rules, didn't give a meaningful simplification. So I thought let's try some synthesis, I used Python's `eval` to plug in different inputs to this expression and see how the bits in the output react (try it yourself, it's fun). In the end my synthesized expression was:

{% highlight shell %}
0x99DB8D4C50945260 ^ bss_val1 & ~0x3
{% endhighlight %}

Can't see it getting simpler than this, but is it identical to the obfuscated expression? Let's ask Z3:
{% highlight python %}
>>> z3.prove(obfsc_expr == simp_expr)
proved
{% endhighlight %}

Bingo!

_EDIT_: [@adriengnt](https://twitter.com/adriengnt) brought to my attention Arybo which he worked on at Quarkslab (they seem to have a monopoly on MBA). It was able to simplify the expression above in one go<sup>[14]</sup>. I'd say this is state of the art as far as MBA obfuscation goes. Its concepts<sup>[15]</sup> are interesting if you wanna get technical.

# We cool, Snap?
There's much more to token generation than obfuscations. Being able to work with the binary at this level is only half the battle. I won't disclose how to communicate with the API, because if Godfather has taught us anything, it's that the perfect number of sequels is one.

[1]: https://releases.llvm.org/2.6/docs/tutorial/JITTutorial1.html
[2]: https://github.com/obfuscator-llvm/obfuscator/wiki/Bogus-Control-Flow
[3]: https://www.bloomberg.com/news/articles/2017-07-21/snap-hires-swiss-team-behind-software-protection-startup
[4]: https://news.ycombinator.com/item?id=23562878
[5]: https://github.com/ksluckow/awesome-symbolic-execution
[6]: https://www.man7.org/linux/man-pages/man2/ptrace.2.html
[7]: https://frida.re/docs/stalker/
[8]: https://dl.acm.org/doi/pdf/10.1145/2995306.2995308?download=true
[9]: https://hal.inria.fr/hal-01241356v2/document
[10]: https://en.wikipedia.org/wiki/Symbolic_execution
[11]: https://github.com/JonathanSalwan/Triton
[12]: https://github.com/JonathanSalwan/Triton/blob/master/src/examples/python/synthetizing_obfuscated_expressions.py
[13]: https://github.com/quarkslab/sspam
[14]: https://twitter.com/hot3eed 
[15]: https://pythonhosted.org/arybo/concepts.html#sec-theory-esf
