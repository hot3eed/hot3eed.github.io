---
title: "Reverse Engineering Starling Bank (Part II): Jailbreak & Debugger Detection, Weaknesses & Mitigations"
layout: post
---


# Reverse Engineering Starling Bank (Part II): Jailbreak & Debugger Detection, Weaknesses & Mitigations
2020-08-02

## Three layers
There are three layers of protection applied before main starts doing its intended work. Frida detection, jailbreak detection, and debugger detection.

##  Frida listens
When Frida runs in injected mode<sup>[1]</sup>, there's a daemon, `frida-server`, that listens for connections on port `27042` and exposes `frida-core`. And as mentioned in the OWASP guide<sup>[2]</sup>, you could detect Frida in this mode of operation using this port. Starling uses this method.
First it gets all TCP interfaces using `getifaddrs`<sup>[3]</sup> and checks for interfaces with the address family `AF_INET`<sup>[4]</sup>, which is for Internet connections. 

{% highlight c %}
ifa->ifa_addr->sa_family == AF_INET
{% endhighlight %}

After getting Internet interfaces, which in my experiments have been the `lo0` (loopback/localhost) and `en2` (USB ethernet), a [socket](http://beej.us/guide/bgipc/html/multi/unixsock.html) is created, and `bind()` is called to try and bind that socket to the interface's address at port `27024`. All that does is basically check if that port is already open, in all Internet interfaces iteratively.

{% highlight c %}
int status = bind(sfd, addr, sizeof(addr));
{% endhighlight %}

If Frida is listening there, `bind()` will return an error `EADDRINUSE`<sup>[5]</sup>. But what if it's another legit process that has nothing to do with Frida but for some reason chose to listen on that port? Frida uses the D-Bus protocol<sup>[6]</sup>, so Starling double checks that this is Frida by sending an `AUTH` command<sup>[7]</sup>, if it receives a `REJECTED`<sup>[8]</sup> response, then this is D-Bus and this is most likely is Frida.

{% highlight c %}
char *cmd = "\0AUTH"; 				// null-beginning for some reason
write(sfd, cmd, sizeof(cmd));			// communicate with Frida

char reply[REPLYMAX];
recvfrom(sfd, reply, sizeof(reply));		// Frida replies
if (strncmp(reply, "REJECTED", 8) == 0) { 	// strncmp or something along those lines
	// This is defintely Frida, crash
}
{% endhighlight %}

## Jailbreak detection 
`access()`, and sometimes `stat64()`, is a canonical method for checking for the existence of jailbreak artifacts (Cydia, SafeMode, themes, etc.). Starling takes it three steps further: 

First, before checking for those files using their absolute paths, .e.g `"/Applications/Cydia.app"`, it creates a symlink from the root directory `"/"` to a file in `tmp` inside the binary's sandbox, and uses that symlink to check for the existence of said artifacts, so it would check for the existence for `"<sandbox>/tmp/<somefile>/Applications/Cydia.app"` instead. Why? Porbably because most jailbreak detection bypass tweaks are expecting absolute addresses, so this bypasses the bypasses. 

Second, it checks for non-JB files/directories, e.g. `/dev/null`, `/etc/hosts`, and expects `access()` to return `0`, or success. Otherwise, it'll crash. This is probably to prevent you from trivially hooking `access()` to always return `ENOENT` (file doesn't exist); because you expect it to only check for jailbreak artifacts.

Third, it checks for a quite sizable amount of files. Most jailbreak detectors will check for maybe 10 files and that's it. So all in all it'll look something like this:


{% highlight c %}
char slnk = "<sandbox>/tmp/<somefile>";	// replace <sandbox> with that of the app
symlink("/", slnk);
int status_lookup[];	// hardcoded, expected status for each file (JB or non-JB)
char artifacts[];	// hardcoded, but strings are obfuscated

for (int i = 0; i < LEN_ARTIFACTS; i++) {
	char artifactp[400];
	sprintf(artifactp, "%s%s", slnk, artifacts[i]);
	int status = access(artifactp, F_OK); 	// just check for its existence
	if (status != status_lookup[i]) {
		// File access isn't what's expected, crash 
	} 
}
{% endhighlight %}

## kill -0?
There's a call to `kill(getpid(), 0)`. Regarding the second argument, the `man` page for `kill` states:
> A value of 0, however, will cause error checking to be performed (with no signal being sent).  This can be used to check the validity of pid.

Hmm, so it checks if the process actually exists. My guess then is that this is for anti-emulation purposes; because a process wouldn't normally exist in an emulated enviornment. If anyone has a better explanation, feel free to hit me up.

## Debugger detection
After confirming that the device isn't jailbroken using the methods above, the binary will check if a debugger is attached to it via the standard way, `sysctl`, even Apple has a page<sup>[9]</sup> on it. It's trivial to bypass it by just flipping the `P_TRACED` flag if it's on in `info.kp_proc.p_flag`<sup>[10]</sup>. The twist here is that it does this very same check not once, not twice, but thrice. You would think that is just redundant, but it's not. Remember, with this binary, you can't single-step your way out of it<sup>[11]</sup>. The original code should look something like this:


{% highlight c %}
bool is_debugged = amIBeingDebugged();
is_debugged |= amIBeingDebugged();
is_debugged |= amIBeingDebugged();
{% endhighlight %}


## Weaknesses & mitigations
The Starling team did a great job, kudos to them. But like everything else humans make, there's room for improvement.

### Code signature
I was quite surprised when I was able to re-sign the binary myself, run it on a non-jailbroken device, and see what the execution trace for a normal device (save for the debugger) should look like, it saved me a lot of time actually because I was able to do confirm things quickly, e.g. `bind()`<sup>[11]</sup> should return success. For an app that cares about its security, it's not a good idea to let the binary run its critical parts when it's been re-signed by a third-party. 
Mitigation: verify that the binary isn't signed by a third-party.


### Better debugger detection
Although three `sysctl`s are better than one, a non-standard debugger detection would be a good advantage to a binary like this. Although these are kind of trade secrets.


### Code injection
Currently nothing stops someone from injecting a dylib that hooks<sup>[12]</sup> ObjC/Swift methods in this binary and changes its behavior. That's true even on a jailed device due to the lack of the signature check above. 
Mitigation: verify that no suspicious dylibs (dynamic libraries) are loaded. This could be done using `dyld` (dynamic linker) such as `dlsym()`<sup>[13]</sup> and `_dyld_get_image_count()`<sup>[14]</sup>.


### Anti-tampering
After having reverse engineered the detections, which requires a good amount of skill, nothing stops someone from trivially patching all the checks, and re-packaging the binary, then use it even on a jailed device. 
Possible mitigation: an obfuscated checksum function that verifies the integrity of the checks.


## More obfuscation?
As long as it doesn't come at a huge performance cost, more obfuscation techniques would help make breaking jailbreak/debugger detection an even harder task than it already is, and give Starling more advantage in the cat-and-mouse that is reverse engineering.
<br/>

PS: I'm available for [hire](https://hot3eed.github.io/contact.html)

[1]: https://frida.re/docs/modes/#injected
[2]: https://mobile-security.gitbook.io/mobile-security-testing-guide/ios-testing-guide/0x06j-testing-resiliency-against-reverse-engineering
[3]: https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/getifaddrs.3.html
[4]: https://opensource.apple.com/source/xnu/xnu-6153.81.5/bsd/sys/socket.h.auto.html
[5]: https://opensource.apple.com/source/xnu/xnu-201/bsd/sys/errno.h.auto.html
[6]: https://en.wikipedia.org/wiki/D-Bus 
[7]: https://dbus.freedesktop.org/doc/dbus-specification.html#auth-command-auth
[8]: https://dbus.freedesktop.org/doc/dbus-specification.html#auth-command-rejected
[9]: https://developer.apple.com/library/archive/qa/qa1361/_index.html
[10]: https://opensource.apple.com/source/xnu/xnu-6153.81.5/bsd/sys/proc.h.auto.html
[11]: https://hot3eed.github.io/2020/07/30/starling_p1_obfuscations.html 
[12]: https://developer.apple.com/documentation/objectivec/1418769-method_exchangeimplementations?language=objc
[13]: https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/dlsym.3.html
[14]: https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/dyld.3.html
