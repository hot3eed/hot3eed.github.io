---
title: "Reverse Engineering Starling Bank (Part I): Obfuscation Techniques" 
layout: post
---

# Reverse Engineering Starling Bank (Part I): Obfuscation Techniques 
2020-07-30
<br/>

UK banks seem to have an earned reputation of tight securtiy<sup>[1]</sup>. Starling is one good example.
<br/>

If you launch the Starling binary (version 1.47.0, on iOS) on a jailbroken device, or with a debugger, it'll crash. And you could tell from the crashlog that this is gonna be an interesting binary. 

{% highlight shell %}
Exception type: EXC_BAD_ACCESS (SIGBUS)
Exception subtype: KERN_PROTECTION_FAILURE: 0x201d5fa94
Exception codes: 0x0000000000000002, 0x0000000201d5fa94
Culprit: Unknown
VM Protection: rw-

Triggered by thread: 0
Thread name: Dispatch queue: com.apple.main-thread
Call stack:
0   ???                           	0x0000000201d5fa94 0 + 8620735124
1   libdyld.dylib                 	0x00000001b58348f0 0x1b5833000 + 6384       	// start
{% endhighlight %}

This is strange, why does a callee for `dyld` `start` crash? Shouldn't that be the binary's `main`<sup>[2]</sup>? And why does it look like a heap address? Besides this quirk, this backtrace is also a bit misleading, we'll see later why. But first how can we decrypt the binary if we can't launch it? Luckily there's `flexdecrypt`<sup>[3]</sup>. Now let's try to see what happens to `main`. We'll need to spawn the binary from the debugger first.

{% highlight shell %}
(lldb) debugserver localhost:6666 -x backboard Starling
(lldb) b <main_addr>
(lldb) c
{% endhighlight %}

The binary stops at `main`, which is good. And after continuing, as expected, it crashes:

{% highlight shell %}
Process 4586 stopped
* thread #1, queue = 'com.apple.main-thread', stop reason = EXC_BAD_ACCESS (code=2, address=0x2010da73c)
    frame #0: 0x00000002010da73c
->  0x2010da73c: udf    #0x0
    0x2010da740: udf    #0x0
    0x2010da744: udf    #0x0
...
{% endhighlight %}

So it crashes at the strange heap pointer. Let's see the backtrace.

{% highlight shell %}
(lldb) bt
* thread #1, queue = 'com.apple.main-thread', stop reason = EXC_BAD_ACCESS (code=2, address=0x2010da73c)
  * frame #0: 0x00000002010da73c
    frame #1: 0x00000001004a97ec Starling` ___lldb_unnamed_symbol14799$$Starling  + 77528
    frame #2: 0x00000001b58348f0 libdyld.dylib` start  + 4
{% endhighlight %}

That's why the crashlog was misleading, you can see the point in the binary before which the crash happens. Good, now we're somewhere at least. But the 77528 instructions tell you that this is gonna be considerably obfuscated. Let's see the block leading up to the crash:

{% highlight asm %}
ldr        w8,[x22, #0x57c]
adrp       x9,0x1037e2000
add        x9,x9,#0x7d0
add        x8,x9,x8
str        x8,[x19, #0x5b58]
blr        x8
{% endhighlight  %}

We can safely assume this happens after something in our environment, i.e. debugger or jailbreak, triggers something in the function's logic. But what's the trigger? Before you get to know that, you'll be met with a strong arsenal of obfuscation techniques.

## Control flow obfuscation techniques

### Opaque predicates done right
Opaque predicates are a staple obfuscation in all of the high-profile apps I've reversed, but they're rarely done right. They're usually inserted as identical, self-contained blocks in between blocks of the original code. They become very easy to recognize once you play with the binary for a short while. But in this binary they're a different beast; they're not identical nor self-contained and they make extensive use of stack variables, so it's not always clear anymore whether a branch is taken due to an opaque predicate or a legit constraint from the binary. Snapchat's opaque predicates<sup>[4]</sup> were a joke compared to this. Let's see a real example.

{% highlight asm %}
mov    w8, #0x3
stur   w8, [x24, #0xfa]
b      0x10041e218
{% endhighlight %}

Then a couple of blocks later:

{% highlight asm %}
ldur   w8, [x24, #0xfa] 			
str    w8, [x21, #0x4] 			
sub    w8, w8, #0x1               
subs   w8, w8, #0x3               
cset   w8, lt
strb   w8, [x21, #0xe]        
mov    w8, #0x4             	; all above is practically dead code
str    w8, [x21, #0x8] 		; this is where the opaque predicate starts
b      <somewhere>

{% endhighlight %}

And finally a decision is made:

{% highlight asm %}
ldr    w8, [x21, #0x8] 		
str    w8, [x21, #0x10] 	
sub    w8, w8, #0x1             
subs   w8, w8, #0x3      
b.lt   <somewhere>          ; will never be taken
b      <somewhere>          ; will always be taken
{% endhighlight %}

Add enough of those and it becomes considerably hard to distinguish what's original code behavior/data and what's not. My solution? An execution trace, but we'll see later why that's not as easy as it usually is. 


### Instruction aliases
If you lookup the `CMP`'s page in the ARMv8 manual<sup>[5]</sup>, you'll find that it's an alias for `SUBS` (subtract and set flag), and so is `TST` for `ANDS`. Instead of giving you the conveneince of understandable aliases, they give you the original ones, so `SUBS` and `ANDS` and who knows what else, but it's no big deal anyway.


### Instructions substitution
This is another popular technique. Substitute a simple instruction with a few others that have the same semantics. Example:

{% highlight asm %}
str        xzr,[x19, #0x2138]
ldr        x12,[x19, #0x2138]
and        x9,x8,x12                    
{% endhighlight %}

If you haven't noticed, this is equivalent to:

{% highlight asm %}
movz x9, #0x0
{% endhighlight %}

### Function inlining

Function inlining is another popular technique, but does a very good job in this function and it works both as a control & data flow obfuscation. It basically blurs the lines between functions, so instead of having the convenient:

{% highlight c %}
func0(arg00, arg01, arg02);
func1(arg10, arg11, arg12);
...
{% endhighlight %}

You'd have:

{% highlight c %}
func0_logic
.
.
.

func1_logic
.
.
.
// both are in one container
{% endhighlight %}

If you've reverse engineered for a while, you'll know that "normal" functions are a great help, because arguments and return values give you hints on what the function could be doing, plus when you reverse a function in one context, you normally won't have to reverse it again in another context. So this is a technique that definitely made this function way harder to work with.


## Data flow obfuscation techniques
The team at Starling seems to have been very focused on hiding stack variables, which is the right thing to do in a function like this.

### Multiple stack pointer registers
Stack offsets are very useful in identifying the variables you're interested in and seeing them in action. Usually the `SP` register is used to access stack variables, with this binary though, a couple more registers are used to "hide" the offset. This happens because if you have multiple "bases" that aren't actually the same pointer, the offset that's used to access the same value would change

{% highlight asm %}
add x19, sp, #0x0	        
add x22, sp, #0x40

; those two instructions are usually in separate blocks, far away from this one, they're only here for convenience

add x0, x19, #0x60 	        ; arg0, x19+0x60
bl <some_func>

; now let's access what's at arg0 via x22
ldr x0, [x22, #0x20] 	    ; arg0, x20+0x20 (x19 + 0x40 + 0x20)
{% endhighlight %}

The solution to this is watchpoints (because the address remains the same), although using a binary analysis framework/emulator to "resolve" non-`SP` stack pointers would be both cool and easy.


### Literal "tunneling"
I don't know if this technique already has a name but if not let me coin it. I call it tunneling because it's similar to how tunneling protocols work<sup>[6]</sup> You have an important return value, from a syscall for example, you're obviously gonna do a check on it. But you don't want that check to be trivial to bypass. So you store it at some stack offset, then a couple of blocks later you load then store it at another stack offset, then more blocks later you do the same, and so on. And since blocks aren't sequential in memory, it'll be very hard to tell when the check is being made on the original value unless you're using a debugger or looking at an execution trace. Example:

{% highlight asm %}
svc    #0x80
mov    w8, w0
stur   w8, [x19, #0x12]			; retval
; redacted block logic
{% endhighlight %}

Then:

{% highlight asm %}
ldur   w8, [x19, #0x12] 		; retval
stur   w8, [x19, #0xea] 		; retval
b      <somwhere>
{% endhighlight %}

And a couple of blocks later:

{% highlight asm %}
ldur   w8, [x19, #0xea] 		; retval
stur   w8, [x19, #0xfe] 		; retval
; redacted block logic
{% endhighlight %}

And so on until a decision is finally made:

{% highlight asm %}
ldur   w8, [x24, #0xfe] 		; retval
; redacted logic
cbz    w8, <somewhere> 			; retval == 0
{% endhighlight %}

I've redacted the blocks' logic for simplicity, but in the binary these blocks don't come so clear-cut.


## How to deal with all of this

### The manual approach
When I'm working on a binary like this, as a I begin to understand what's being done here, I usually have some ideas on how to de-obfuscate this using symbolic execution, tainting, slicing, or other fancy techniques<sup>[7]</sup>. But reverse engineering is time management, so I usually delay investing the time until I find the "manual" approach too time intensive. And almost always the manual approach wins. Or, I make progress with it before resorting to other approaches, this binary was no exception. And by manual I mean a debugger, disassembler and possibly an execution trace. 


### You can't single-step your way through it 
With all these obfuscations in mind, the two things that contribute the most to making this function quite tricky to reverse are opaque predicates and function inlining. Because strings are obfuscated, opaque predicates are used heavily (maybe half-ish of the instructions are bogus), and there are loops that check for a considerable amount of files, you'll find yourself swimming in a sea of assembly, most of which is opaque predicates. So my usual way of single-stepping and reversing to C wasn't practical, and Frida Stalker would be naturally the way to go here.


### The poor man's Frida Stalker
When I tried to spawn Starling using Frida, with a script that stalks `main`, it crashed as expected, but it didn't give an execution trace up to the crash, which was all I wanted. 

{% highlight shell %}
$ frida -U -f uk.co.starlingbank.Starling -l main_stalk.js
[iPhone::uk.co.starlingbank.Starling]-> %resume 
{% endhighlight %}

Only a crashlog:

{% highlight shell %}
[iPhone::uk.co.starlingbank.Starling]-> [*] Started stalking main
Process crashed: Bus error
...
{% endhighlight %}

Then I thought why not write an atrocious single-stepper Python plugin for LLDB that logs all instructions? It was terribly slow, and the execution trace was huge (too huge in fact that it was impractical to log the whole thing in one go.) But it gave me what I wanted. I wonder how much faster this plugin in C++<sup>[8]</sup> would be. Might not be a bad idea, you could even call it `creep`.


## What's next?
Jailbreak and debugger detection techniques, weaknesses and mitigations.


[1]: https://www.reddit.com/r/jailbreak/comments/gcod9m/release_kernbypass_bypass_jailbreak_detection_for/fpcixkc?utm_source=share&utm_medium=web2x
[2]: https://embeddedartistry.com/blog/2019/04/08/a-general-overview-of-what-happens-before-main/
[3]: https://github.com/JohnCoates/flexdecrypt
[4]: https://hot3eed.github.io/2020/06/18/snap_p1_obfuscations.html
[5]: https://developer.arm.com/documentation/ddi0487/latest
[6]: https://en.wikipedia.org/wiki/Tunneling_protocol
[7]: https://github.com/JonathanSalwan/Triton/tree/master/src/examples/python
[8]: https://lldb.llvm.org/python_reference/lldb-module.html
