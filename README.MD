Hacky way of protecting a value in memory in C++ using a very basic VM, various x86 assembler hacks und anti-debugger techniques. The "goal" to break this protection is (without checking the code when compiling it obviously) to make the console display the changed value without crashing. The default value is 0x1337 of course. Hooking the OEP and implementing your own console display loop is not allowed, but the console must still use the original variable. The code has comments for a lot of stuff, but it's recommended that you have some C++ and assembler knowledge. Functions like GetProcAddr are re-implemented in assembler to obfuscate them.

Why?
========

Back in 2013 a friend and I were challenging each other by writing protections for a single variable in memory as a training exercise. This code contains my final way of protecting the value, which he (and others I gave it to) were not able to defeat. Though old and x86 only, maybe you can learn a thing or two. If you have any questions, feel free to shoot me an e-mail at lms@lms-dev.com.

License
========

The code is free to use for non-commerical applications, a link to this git repo or including this repo would be appreciated. I've used various snippets myself from the internet in this code, but I'm only uploading this now (Feb 2017) so the credits are mostly missing. 